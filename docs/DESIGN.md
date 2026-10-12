# Lamport Vault: design

Lamport Vault is a post-quantum custody layer for Solana. Funds sit in a program-owned account that moves
only on a **hash-based signature** (LMS, RFC 8554, NIST SP 800-208). The only cryptographic assumption is
SHA-256. No elliptic curve stands between an attacker with a quantum computer and the funds.

Three pieces share one signature library:

| piece | what it is |
|---|---|
| `programs/lamport-vault` | the vault program: create, deposit (plain transfer), execute a signed action, rotate keys, close |
| `programs/pq-registry` | a commitment registry: any Solana address binds, today, the post-quantum key that will own it later |
| `programs/lms` | LMS / LM-OTS verification as a Rust crate used by both programs, with the same test vectors as the SDKs |
| `sdk/` | TypeScript: key generation, signing, verification, vault and registry clients |
| `firmware/` (later) | C implementation for the Pincer1 consent controller, same vectors |

## 1. Why LMS

Of the two standardised stateful schemes,
LMS (RFC 8554) is simpler than XMSS (RFC 8391): one hash call per chain step, no bitmasks, no PRF layer, so
the on-chain verifier stays small.

The classic weakness of stateful schemes, reusing a one-time key, is solved **by the chain**: the vault
account stores the next usable leaf index and refuses anything below it. The state lives where it cannot
be lost or forked.

**Parameters.** LM-OTS `LMOTS_SHA256_N32_W4` (typecode 3): 67 chains of at most 15 steps, 2180-byte OTS
signature. LMS heights `H5, H10, H15, H20` (typecodes 5–8): 32 to about a million signatures per key.
Default `H10` (1024 signatures). W4 is the compute sweet spot: W8 halves the signature but costs 8× the
hashing; W2 doubles the signature for a third of the hashing. Verification of one W4/H10 signature is about
1 100 SHA-256 calls, well inside one Solana transaction with a raised compute budget.

Keys are generated pseudorandomly per RFC 8554 Appendix A:
`x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)`.

## 2. The vault program

### Accounts

**`Vault`** — PDA, seeds `["vault", vault_id]` where `vault_id = sha256(initial lms_pubkey)`.

```
version      u8      = 1
bump         u8
vault_id     [u8;32]
lms_pubkey   [u8;56]   u32 lms_type || u32 lmots_type || I[16] || T[1] (root)[32]
next_q       u32       next usable leaf; signatures with q < next_q are rejected
rotations    u32       how many times the key was replaced
created_slot u64
```

The vault's address never changes, so deposits (plain `SystemProgram::transfer` to the PDA, SPL transfers
to the PDA's associated token accounts) keep working after a key rotation.

**`SigBuffer`** — PDA, seeds `["sig", vault, payer, nonce_le_u64]`. A W4 signature is 2 348–2 828 bytes and a
Solana transaction carries 1 232, so the signature is staged in chunks and verified in one `execute`.

```
version    u8 = 1
bump       u8
vault      Pubkey
payer      Pubkey     the classical key that pays rent; refunded on execute/close
nonce      u64
action     Vec<u8>    ≤ 256 bytes, the Borsh-encoded Action (fixed at open)
sig_len    u16        exact signature length for the vault's parameter set
filled     u16        bytes written so far; writes must be sequential
sig        Vec<u8>    allocated to sig_len at open (Borsh: u32 length prefix), zero until written
```

### Instructions

| ix | signer | effect |
|---|---|---|
| `create_vault(vault_id, lms_pubkey)` | payer | requires `vault_id == sha256(lms_pubkey)` (passed explicitly so the PDA seed is a plain argument the IDL can describe), validates typecodes (LMS 5..8, LMOTS 3), inits `Vault`, `next_q = 0` |
| `open_sig_buffer(nonce, action, sig_len, first_chunk)` | payer | allocates the buffer for one action; `action` must decode, `sig_len` must match the vault's parameter set; `first_chunk` (may be empty) is written at offset 0 |
| `write_sig(offset, chunk)` | payer | appends; `offset == filled` required |
| `close_sig_buffer()` | payer | refunds rent, no effect on the vault |
| `execute()` | anyone | verifies and performs; closes the buffer to `payer` |

`execute` takes the accounts `vault`, `sig_buffer`, `payer` (unsigned, must equal the buffer's payer) and, as
remaining accounts: `TransferSol` → `[to]`; `TransferToken` → `[vault token account, destination token
account, mint, token program]`; `Rotate` → none; `Close` → `[to]` followed by any number of
`[token account, token program]` pairs, each an empty token account owned by the vault that is closed to `to`.

`execute`:

1. `filled == sig_len`, buffer belongs to this vault.
2. `message = sha256("lamport-vault/v1" || vault_pubkey || action_bytes)`.
3. Parse the LMS signature: `q`, OTS signature, `lms_type`, `path[h]`. Require `lms_type` equal to the
   vault's, `q >= vault.next_q`, `q < 2^h`.
4. `lms_verify(vault.lms_pubkey, message, signature)` (RFC 8554 Algorithms 4b and 6).
5. `vault.next_q = q + 1` **before** performing the action.
6. Decode `Action`, check `expiry_slot >= clock.slot`, perform.
7. Close the buffer to `payer`.

Anyone may submit `execute`: the signature already binds the vault and the exact action, and the leaf
counter makes it single-use. `expiry_slot` bounds how long a signed-but-unsubmitted action stays valid.

### Actions (Borsh enum)

```
TransferSol   { to: Pubkey, lamports: u64, expiry_slot: u64 }
TransferToken { mint: Pubkey, to: Pubkey /* token account */, amount: u64, expiry_slot: u64 }
Rotate        { new_lms_pubkey: [u8;56], expiry_slot: u64 }   // next_q resets to 0, rotations += 1
Close         { to: Pubkey, expiry_slot: u64 }                 // all lamports to `to`; token accounts must be empty
```

`TransferSol` leaves the rent-exempt minimum in place. `TransferToken` signs a `transfer_checked` with the
vault PDA; remaining accounts: vault token account, destination token account, mint, token program (Token
and Token-2022). `Rotate` refuses the key already in use (a reset `next_q` on the same key would reopen
spent leaves); never rotate back to a key used before, the derivation in `SPEC-DERIVATION.md` never does.
`Close` requires every vault token account it is given to be empty; token accounts not passed in simply
stay owned by the (now closed) PDA, so move them out first.

**Exhaustion rule.** The last leaf (`q == 2^h - 1`) may only be spent on `Rotate`. A vault can therefore
always move to a fresh key; it can never be stranded with funds and no usable leaf.

### What the program does not do

- No admin, no pause, no fee switch, no upgrade after launch: the upgrade authority is burned at mainnet
  deployment and the build is reproducible so anyone can check the on-chain hash against the source.
- No classical authority anywhere in the funds path. The `payer` only pays rent and gets it back.

## 3. The registry program

`pq-registry` lets any Solana address record **now**, with its ordinary signature, the hash-based key that
should own it once Solana verifies post-quantum signatures natively. On that day the record is proof of
intent made before the attacker existed.

**`Commitment`** — PDA, seeds `["pq", owner]`.

```
version       u8 = 1
bump          u8
owner         Pubkey
scheme        u8       1 = LMS-SHA256 (56-byte public key)
pq_pubkey     [u8;56]
next_q        u32
created_slot  u64
updated_slot  u64
```

| ix | signer | rule |
|---|---|---|
| `commit(pq_pubkey)` | owner (classical) + payer | only when no commitment exists: **first write wins** |
| `open_pq_buffer(nonce, new_pq_pubkey, sig_len)` | payer | allocates a `PqSigBuffer` (PDA `["pqsig", owner, payer, nonce_le_u64]`: version, bump, owner, payer, nonce, new_pq_pubkey, sig_len, filled, sig `Vec<u8>`) |
| `write_pq_sig(offset, chunk)` | payer | appends; `offset == filled` |
| `close_pq_buffer()` | payer | refunds rent |
| `rotate_pq()` | anyone | requires an LMS signature from the **committed** key over `sha256("pq-registry/v1" || owner || new_pq_pubkey)`; `q >= next_q`; then `pq_pubkey = new`, `next_q = 0`, `updated_slot = now`; rotating to the key already committed is refused |

Why first-write-wins: an attacker who later derives the classical private key from the public key must not
be able to overwrite the commitment. After `commit`, only the post-quantum key can change it. The honest
limitation is stated in the docs: a commitment protects an address only if it was made before the key was
broken; addresses with no commitment get no protection from the registry.

## 4. Key derivation (see `SPEC-DERIVATION.md`)

One 24-word phrase yields any number of vault keys. For vault index `k`:

```
master  = BIP-39 seed (64 bytes)
SEED_k  = HMAC-SHA256(key = "lamport-vault/lms-seed/v1", msg = master || u32be(k))
I_k     = HMAC-SHA256(key = "lamport-vault/lms-id/v1",   msg = master || u32be(k))[0..16]
```

The LMS private key is `(SEED_k, I_k, typecodes)`; the public key is recomputed by building the tree.
Recovery = the 24 words plus the vault's typecodes (public, in the account). A `Rotate` to a fresh key uses
`k + 1`, so recovery walks `k` upward until it finds the key matching the vault's current `lms_pubkey`.

## 5. Threat model, in one table

| threat | answer |
|---|---|
| quantum attacker with the vault address and every past signature | sees only hash preimages already revealed for spent leaves; SHA-256 preimage/second-preimage resistance is unaffected by Shor; Grover halves 256 to 128 bits, still out of reach |
| one-time key reused by a buggy signer | the chain refuses `q < next_q`; a reuse never reaches the verifier |
| signer loses count of leaves | sign with any `q >= next_q` (gaps are allowed), read `next_q` from the account first |
| attacker intercepts a staged signature | it binds vault + action + expiry; the only thing they can do is submit it, which performs the owner's own intent |
| attacker breaks the payer's classical key | gets the rent back; nothing else |
| program upgrade by a compromised authority | authority burned; reproducible build |
| stolen 24 words | full control: a vault is quantum-safe, not owner-safe. This is what the Pincer1 robot adds on top |
| the tree runs out | last leaf reserved for `Rotate` |

## 6. Compute and sizes

| item | value |
|---|---|
| LM-OTS W4 signature | 4 + 32 + 67×32 = 2 180 bytes |
| LMS signature, height h | 4 + 2 180 + 4 + 32·h → H5 2 348, H10 2 508, H15 2 668, H20 2 828 |
| public key | 56 bytes |
| verify, hash calls | ≤ 67×15 chain steps + 1 (Q) + 1 (K) + h (path) ≈ 1 010–1 030 |
| `execute` compute | ~115-145k CU measured for H10, worst case ~210k; client requests 400k |
| staging | `open_sig_buffer` with a 708-byte first chunk plus `write_sig` chunks of 900 bytes: H5 and H10 take 3 transactions in total, H15 and H20 take 4 |

## 7. Test vectors

`kat/lms_sha256_w4.json` holds deterministic vectors (H5 and H10, W4) produced by an independent RFC 8554
implementation with fixed `SEED`/`I`. Every implementation in this repository (Rust, TypeScript, later C)
must reproduce the public keys from `SEED`/`I` and verify every signature, and the SDK's own signatures must
verify under the Rust verifier.
