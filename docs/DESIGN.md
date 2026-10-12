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
account stores a used-leaf bitmap and refuses any leaf whose bit is set. The state lives where it cannot
be lost or forked, and a leaf may be spent in any order, so several devices can share one key.

**Parameters.** LM-OTS `LMOTS_SHA256_N32_W4` (typecode 3): 67 chains of at most 15 steps, 2180-byte OTS
signature. LMS heights `H5, H10, H15` (typecodes 5–7): 32, 1 024 or 32 768 signatures per key; the
verifier also knows `H20` (typecode 8) but the vault refuses it, its bitmap would be 128 KB. Default `H10`
(1024 signatures). W4 is the compute sweet spot: W8 halves the signature but costs 8× the
hashing; W2 doubles the signature for a third of the hashing. Verification of one W4/H10 signature is about
1 100 SHA-256 calls, well inside one Solana transaction with a raised compute budget.

Keys are generated pseudorandomly per RFC 8554 Appendix A:
`x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)`.

## 2. The vault program

### Accounts

**`Vault`** — PDA, seeds `["vault", vault_id]` where `vault_id = sha256(initial lms_pubkey)`.

```
version      u8      = 2
bump         u8
vault_id     [u8;32]
lms_pubkey   [u8;56]   u32 lms_type || u32 lmots_type || I[16] || T[1] (root)[32]
spent        u32       leaves spent under the current key (bits set in `used`)
generation   u32       how many times the key was replaced; part of every signed message
created_slot u64
used         Vec<u8>   used-leaf bitmap, 2^h / 8 bytes (H5 4, H10 128, H15 4096); bit q = byte q/8, bit q%8
used_keys    Vec<[u8;16]>  sha256(pubkey)[0..16] of every past key, oldest first; at most MAX_KEY_HISTORY = 128
```

Sizes (discriminator included, no history): H5 126 bytes, H10 250, H15 4 218; every `Rotate` adds 16.

The vault's address never changes, so deposits (plain `SystemProgram::transfer` to the PDA, SPL transfers
to the PDA's associated token accounts) keep working after a key rotation. The tree height is fixed at
creation: the bitmap is sized once, and `Rotate` must keep the typecodes.

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
| `create_vault(vault_id, lms_pubkey)` | payer | requires `vault_id == sha256(lms_pubkey)` (passed explicitly so the PDA seed is a plain argument the IDL can describe), validates typecodes (LMS 5..7, LMOTS 3), inits `Vault` with a clear bitmap sized for the key's height, `generation = 0`, empty history |
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
2. `message = sha256("lamport-vault/v1" || program_id || vault_pubkey || u32le(generation) || action_bytes)`.
   `program_id` is the vault program's own id, `generation` the vault's current value. `MESSAGE_VERSION = 1`
   is the number in the domain string; it changes if this formula ever does.
3. Parse the LMS signature: `q`, OTS signature, `lms_type`, `path[h]`. Require `lms_type` equal to the
   vault's, `q < 2^h`, bit `q` of `used` clear.
4. `lms_verify(vault.lms_pubkey, message, signature)` (RFC 8554 Algorithms 4b and 6).
5. Set bit `q`, `spent += 1`, **before** performing the action.
6. Decode `Action`, check `expiry_slot >= clock.slot`, perform.
7. Close the buffer to `payer`.

Anyone may submit `execute`: the signature already binds the program, the vault, the key generation and
the exact action, and the bitmap makes it single-use. `expiry_slot` bounds how long a
signed-but-unsubmitted action stays valid. A signature made under generation `g` is worthless after a
`Rotate`, even if the new key would have had that leaf free.

### Actions (Borsh enum)

```
TransferSol   { to: Pubkey, lamports: u64, expiry_slot: u64 }
TransferToken { mint: Pubkey, to: Pubkey /* token account */, amount: u64, expiry_slot: u64 }
Rotate        { new_lms_pubkey: [u8;56], expiry_slot: u64 }   // bitmap cleared, spent = 0, generation += 1
Close         { to: Pubkey, expiry_slot: u64 }                 // all lamports to `to`; token accounts must be empty
```

`TransferSol` leaves the rent-exempt minimum in place. `TransferToken` signs a `transfer_checked` with the
vault PDA; remaining accounts: vault token account, destination token account, mint, token program (Token
and Token-2022). `Close` requires every vault token account it is given to be empty; token accounts not
passed in simply stay owned by the (now closed) PDA, so move them out first.

**Rotate.** The new key must have the vault's typecodes (`RotateTypeMismatch`), must not be the current
key or any key in `used_keys` (`KeyReused`: a key whose leaves were spent would come back with a clear
bitmap, and a second OTS signature on a spent leaf is a forgery oracle), and the history must have room
(`HistoryFull`). Then the old key's 16-byte hash is appended to `used_keys`, the account grows by 16
bytes, the bitmap is cleared, `spent = 0`, `generation += 1`. The rent for the 16 bytes is taken from the
staging buffer before the buffer is closed to its payer, so the buffer's payer pays it and `execute`
needs no extra signer. After 128 rotations a vault can still spend and `Close`, but not rotate: close it
and create a new one. The derivation in `SPEC-DERIVATION.md` never produces a key twice.

**Exhaustion rule.** When one free leaf remains before an `execute` (`2^h - spent <= 1`), that leaf may
only be spent on `Rotate`. A vault can therefore always move to a fresh key; it can never be stranded with funds and no
usable leaf.

### Multi-device

The bitmap has no order, so leaves can be partitioned instead of counted. A signer that owns lane `k` of
`n` only ever uses leaves `q ≡ k (mod n)`; devices in different lanes never collide and need no
coordination beyond agreeing on `n`. Each signer must still never sign the same leaf twice: the chain
only sees a leaf once it is submitted, so a signer that crashes between signing and submitting must have
recorded the leaf before signing (the SDK's `reserve(q)` hook). A signed-but-unsubmitted leaf stays valid
until its `expiry_slot`; submitting it later works, submitting it twice does not. The v1.1 direction is
one key per device behind one vault, which removes the shared-state question entirely.

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
version       u8 = 2
bump          u8
owner         Pubkey
scheme        u8       1 = LMS-SHA256 (56-byte public key)
pq_pubkey     [u8;56]
next_q        u32       next usable leaf of the committed key (rotations happen in order)
generation    u32       how many times rotate_pq ran; part of the signed message
created_slot  u64
updated_slot  u64
used_keys     Vec<[u8;16]>  sha256(pubkey)[0..16] of every past key; at most MAX_KEY_HISTORY = 32
```

127 bytes fresh, plus 16 per rotation. A commitment signs once per rotation, so its leaves are spent in
order (`next_q`) and lanes are not needed. The registry accepts H5..H20 keys (no bitmap).

| ix | signer | rule |
|---|---|---|
| `commit(pq_pubkey)` | owner (classical) + payer | only when no commitment exists: **first write wins** |
| `open_pq_buffer(nonce, new_pq_pubkey, sig_len)` | payer | allocates a `PqSigBuffer` (PDA `["pqsig", owner, payer, nonce_le_u64]`: version, bump, owner, payer, nonce, new_pq_pubkey, sig_len, filled, sig `Vec<u8>`) |
| `write_pq_sig(offset, chunk)` | payer | appends; `offset == filled` |
| `close_pq_buffer()` | payer | refunds rent |
| `rotate_pq()` | anyone | requires an LMS signature from the **committed** key over `sha256("pq-registry/v1" || program_id || owner || u32le(generation) || new_pq_pubkey)`; `q >= next_q`; the new key must not be the committed key or any past one (`KeyReused`) and the history must have room (`HistoryFull`); then the old key's hash is appended (16 bytes, rent from the buffer), `pq_pubkey = new`, `next_q = 0`, `generation += 1`, `updated_slot = now` |

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
| one-time key reused by a buggy signer | the chain refuses a leaf whose bit is set; a reuse never reaches the verifier |
| signer loses track of leaves | read the bitmap from the account and take any clear leaf; several devices take disjoint lanes |
| signer crashes after signing, before submitting | the signature stays valid until `expiry_slot`; the signer must have recorded the leaf before signing (`reserve(q)`) so it never signs that leaf again |
| rotate back to an earlier key (A → B → A) | `used_keys` remembers every past key; `Rotate` / `rotate_pq` refuse it, so spent leaves never reopen |
| replay a signature from before a rotation | the message carries `generation`; it verifies under no later key |
| same message, another deployment of the program | the message carries the program id |
| attacker intercepts a staged signature | it binds program + vault + generation + action + expiry; the only thing they can do is submit it, which performs the owner's own intent |
| attacker breaks the payer's classical key | gets the rent back; nothing else |
| program upgrade by a compromised authority | authority burned; reproducible build |
| stolen 24 words | full control: a vault is quantum-safe, not owner-safe. This is what the Pincer1 robot adds on top |
| the tree runs out | the last free leaf is reserved for `Rotate` |
| key history runs out | after 128 rotations (32 for a commitment) the account refuses to rotate; the vault can still spend and `Close` |

## 6. Compute and sizes

| item | value |
|---|---|
| LM-OTS W4 signature | 4 + 32 + 67×32 = 2 180 bytes |
| LMS signature, height h | 4 + 2 180 + 4 + 32·h → H5 2 348, H10 2 508, H15 2 668, H20 2 828 |
| public key | 56 bytes |
| `Vault` account | H5 126, H10 250, H15 4 218 bytes, plus 16 per rotation (at most 128) |
| `Commitment` account | 127 bytes, plus 16 per rotation (at most 32) |
| verify, hash calls | ≤ 67×15 chain steps + 1 (Q) + 1 (K) + h (path) ≈ 1 010–1 030 |
| `execute` compute | ~115-145k CU measured for H10, worst case ~210k; client requests 400k |
| staging | `open_sig_buffer` with a 708-byte first chunk plus `write_sig` chunks of 900 bytes: H5 and H10 take 3 transactions in total, H15 and H20 take 4 |

## 7. Test vectors

`kat/lms_sha256_w4.json` holds deterministic vectors (H5 and H10, W4) produced by an independent RFC 8554
implementation with fixed `SEED`/`I`. Every implementation in this repository (Rust, TypeScript, later C)
must reproduce the public keys from `SEED`/`I` and verify every signature, and the SDK's own signatures must
verify under the Rust verifier.
