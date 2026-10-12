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

The classic weakness of stateful schemes is reusing a one-time key. The chain closes half of it: the vault
account stores a used-leaf bitmap and refuses to *execute* any leaf whose bit is set, in any order, so a
leaf can never be spent twice and several devices can share one key. The other half is the signer's: two
signatures by the same leaf over two different messages, both released before either executes, let an
attacker forge a third for that leaf. No chain can see that. So a signer must reserve a leaf durably before
it signs (the SDK's leaf journal, the Pincer1 controller's flash), must notice when its own record has gone
backwards (a restored backup; see "Signer rollback" below), and devices sharing a key must use disjoint
lanes. A crash between reservation and signing costs one leaf, never the vault. Every signed action also
carries a validity window of at most one day, so a signature that was made and forgotten cannot be
submitted months later.

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
legacy Solana transaction carries 1 232, so the signature is staged in chunks and verified in one `execute`.
On a cluster with transaction v1 (SIMD-0385, 4 096 bytes) the buffer is not needed: `execute_direct` takes the
action and the whole signature as instruction data in one transaction. The staged path stays as the fallback.

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
| `execute_direct(action, signature)` | payer | the same checks and effects as `execute` with the action and the signature taken from the instruction data; one transaction v1, no buffer |

`execute` takes the accounts `vault`, `sig_buffer`, `payer` (unsigned, must equal the buffer's payer) and, as
remaining accounts: `TransferSol` → `[to]`; `TransferToken` → `[vault token account, destination token
account, mint, token program]`; `Rotate` → none; `Close` → `[to]` followed by any number of
`[token account, token program]` pairs, each an empty token account owned by the vault that is closed to `to`.

`execute_direct` takes the accounts `vault`, `payer` (signer, writable) and `system_program`, then the same
remaining accounts as `execute`. `action` must be 1..256 bytes. Steps 2–6 below are one shared code path for
both instructions; they differ only in where the signature comes from and in who pays a `Rotate`'s rent delta.

`execute`:

1. `filled == sig_len`, buffer belongs to this vault.
2. `message = sha256("lamport-vault/v1" || program_id || vault_pubkey || u32le(generation) || action_bytes)`.
   `program_id` is the vault program's own id, `generation` the vault's current value. `MESSAGE_VERSION = 1`
   is the number in the domain string; it changes if this formula ever does.
3. Parse the LMS signature: `q`, OTS signature, `lms_type`, `path[h]`. Require `lms_type` equal to the
   vault's, `q < 2^h`, bit `q` of `used` clear.
4. `lms_verify(vault.lms_pubkey, message, signature)` (RFC 8554 Algorithms 4b and 6).
5. Set bit `q`, `spent += 1`, **before** performing the action.
6. Decode `Action`, check its validity window against `clock.slot` (below), apply the exhaustion rule, perform.
7. Close the buffer to `payer`.

Anyone may submit `execute`: the signature already binds the program, the vault, the key generation and
the exact action, and the bitmap makes it single-use. The validity window bounds how long a
signed-but-unsubmitted action stays valid. A signature made under generation `g` is worthless after a
`Rotate`, even if the new key would have had that leaf free.

### Actions (Borsh enum)

```
TransferSol   { to: Pubkey, lamports: u64, issued_slot: u64, expiry_slot: u64 }                      57 bytes
TransferToken { mint: Pubkey, to: Pubkey /* token account */, amount: u64, issued_slot: u64, expiry_slot: u64 }  89 bytes
Rotate        { new_lms_pubkey: [u8;56], issued_slot: u64, expiry_slot: u64 }   // bitmap cleared, spent = 0, generation += 1   73 bytes
Close         { to: Pubkey, issued_slot: u64, expiry_slot: u64 }                 // all lamports to `to`; token accounts must be empty  49 bytes
```

**Validity window.** Every variant ends in `issued_slot || expiry_slot` (u64 little-endian each). With
`slot` the current slot, `execute` and `execute_direct` require, in this order:

| rule | error |
|---|---|
| `issued_slot <= slot` | `IssuedInFuture` (6030) |
| `expiry_slot >= slot` | `ActionExpired` (6014) |
| `issued_slot <= expiry_slot` and `expiry_slot - issued_slot <= MAX_VALIDITY_SLOTS` | `InvalidValidityWindow` (6031) |

`MAX_VALIDITY_SLOTS = 216 000` (about one day at 400 ms a slot) is an IDL constant and the SDK's
`MAX_VALIDITY_SLOTS`. A signer cannot grant itself a far future: whatever `expiry_slot` it writes, the
window is capped at a day from `issued_slot`, and `issued_slot` cannot be ahead of the clock, so a
signature made today is dead tomorrow. The SDK's `VaultSigner` fills the window itself: `issued_slot` =
the current slot, `expiry_slot` = `issued_slot + 300` (about two minutes) unless the request says
otherwise, and refuses a request whose window the chain would refuse before any leaf is spent.

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
needs no extra signer; in `execute_direct` there is no buffer, so the signing `payer` pays it through a
System Program transfer (hence `system_program` in its accounts). After 128 rotations a vault can still spend and `Close`, but not rotate: close it
and create a new one. The derivation in `SPEC-DERIVATION.md` never produces a key twice.

**Exhaustion rule.** When one free leaf remains before an `execute` (`2^h - spent <= 1`), that leaf may
only be spent on `Rotate`. A vault can therefore always move to a fresh key; it can never be stranded with funds and no
usable leaf.

### Multi-device

The bitmap has no order, so leaves can be partitioned instead of counted. A signer that owns lane `k` of
`n` only ever uses leaves `q ≡ k (mod n)`; devices in different lanes never collide and need no
coordination beyond agreeing on `n`. Each signer must still never sign the same leaf twice: the chain
only sees a leaf once it is submitted, so a signer that crashes between signing and submitting must have
recorded the leaf before signing (the SDK's leaf journal). A signed-but-unsubmitted leaf stays valid
until its `expiry_slot`; submitting it later works, submitting it twice does not. The v1.1 direction is
one key per device behind one vault, which removes the shared-state question entirely.

### Signer rollback

The chain cannot tell a signer that its own memory went backwards. If a signer's state is restored from an
old backup, or a copy of the key on another device signed and executed leaves after that backup, the
restored signer believes leaves are free that it (or its twin) already signed; signatures for them may
still be unsubmitted, and a second signature by the same leaf is the forgery oracle above. The SDK's
`VaultSigner` therefore keeps a **leaf journal** (`LeafJournal`: `load()` / `save()`, with `FileLeafJournal`
for Node, written temp-file-then-rename with fsync, and `MemoryLeafJournal` for one process; a browser
IndexedDB journal follows the same interface) holding, per vault and lane, the key `generation`, the
number of `spent` leaves in the lane at the last sync and the leaves it has `reserved` (written before the
signature exists). Before every signature it compares the journal with the account:

- the chain is at a later `generation` than the journal, or
- the lane has more spent leaves than `spent` plus the journal's own reserved leaves that are now spent

means the journal is **stale**: a state this journal never saw signed and executed leaves. A stale signer
throws `StaleSignerError` for everything except `Rotate`, and stays stale until a rotation it performed
itself lands (it checks the account: generation `+1`, key = its target), after which the journal is reset
for the new generation. `Rotate` is the safe exit because it retires the whole key: every signature made
under the old generation, known to the journal or not, is dead afterwards. `acknowledgeStale()` overrides
the check and is unsafe: it is only correct when the operator knows that no signature made after the
journal's last save is still unsubmitted. A journal that was never written is initialised from the chain;
the rule then protects every later restore. Two signers in one process over the same journal (or two
`FileLeafJournal` objects on one path) are serialised, so they cannot reserve the same leaf.

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
| `open_pq_buffer(nonce, new_pq_pubkey, sig_len, issued_slot, expiry_slot)` | payer | allocates a `PqSigBuffer` (PDA `["pqsig", owner, payer, nonce_le_u64]`: version `u8 = 1`, bump, owner, payer, nonce, new_pq_pubkey `[u8;56]`, issued_slot `u64`, expiry_slot `u64`, sig_len `u16`, filled `u16`, sig `Vec<u8>`; 164 bytes plus the signature) |
| `write_pq_sig(offset, chunk)` | payer | appends; `offset == filled` |
| `close_pq_buffer()` | payer | refunds rent |
| `rotate_pq()` | anyone | requires an LMS signature from the **committed** key over `sha256("pq-registry/v1" || program_id || owner || u32le(generation) || new_pq_pubkey || u64le(issued_slot) || u64le(expiry_slot))`; `q >= next_q`; then the buffer's window must hold at the current slot (`issued_slot <= slot`: `IssuedInFuture`; `expiry_slot >= slot`: `RotationExpired`; `expiry_slot - issued_slot <= MAX_VALIDITY_SLOTS = 216 000`: `InvalidValidityWindow`); the new key must not be the committed key or any past one (`KeyReused`) and the history must have room (`HistoryFull`); then the old key's hash is appended (16 bytes, rent from the buffer), `pq_pubkey = new`, `next_q = 0`, `generation += 1`, `updated_slot = now` |

The window is part of the signed message, so only the committed key chooses it; a buffer opened with a
window other than the signed one fails verification. The SDK's `RegistryClient.rotatePq` fills it like the
vault signer does (issued now, 300 slots).

Why first-write-wins: an attacker who later derives the classical private key from the public key must not
be able to overwrite the commitment. After `commit`, only the post-quantum key can change it. The honest
limitation is stated in the docs: a commitment protects an address only if it was made before the key was
broken; addresses with no commitment get no protection from the registry.

## 4. Key derivation (see `SPEC-DERIVATION.md`)

One 24-word phrase yields any number of vault keys, per cluster and per program. For vault index `k`:

```
master  = BIP-39 seed (64 bytes)
info    = genesis_hash[32] || program_id[32] || u32be(k)
SEED_k  = HKDF-SHA256(ikm = master, salt = "lamport-vault/lms-seed/v2", info = info || "seed")[0..32]
I_k     = HKDF-SHA256(ikm = master, salt = "lamport-vault/lms-id/v2",   info = info || "id")[0..16]
```

`genesis_hash` is the cluster's (devnet `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG`, mainnet
`5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`; the SDK's `CLUSTERS`), `program_id` the vault program's
(the registry program's for the registry key, index `0xFFFFFFFF`). Both are explicit inputs of every
derivation call; there is no default cluster. The LMS private key is `(SEED_k, I_k, typecodes)`; the
public key is recomputed by building the tree. Recovery = the 24 words, the cluster, the program id and the
vault's typecodes (public, in the account). A `Rotate` to a fresh key uses `k + 1`, so recovery walks `k`
upward until it finds the key matching the vault's current `lms_pubkey`. The vault id is not in the info
because it is derived from the first key (circular); the cluster binding is a fence around the keys that
complements the per-message binding of program, account and generation, it does not replace it. Vectors:
`kat/derivation_v2.json`.

## 5. Threat model, in one table

| threat | answer |
|---|---|
| quantum attacker with the vault address and every past signature | sees only hash preimages already revealed for spent leaves; SHA-256 preimage/second-preimage resistance is unaffected by Shor; Grover halves 256 to 128 bits, still out of reach |
| one-time key reused by a buggy signer | the chain refuses a leaf whose bit is set; a reuse never reaches the verifier |
| signer loses track of leaves | read the bitmap from the account and take any clear leaf; several devices take disjoint lanes |
| signer crashes after signing, before submitting | the signature stays valid until `expiry_slot`; the signer must have recorded the leaf before signing (the leaf journal) so it never signs that leaf again |
| signer state restored from an old backup, or a copy of the key on another device moved on | the journal is behind the chain (more spent leaves in its lane than it can account for, or a newer generation): the signer refuses everything but `Rotate` until its own rotation lands, which retires every signature it may have forgotten |
| a signature leaks, or is signed and forgotten, with a far `expiry_slot` | impossible by construction: `expiry_slot - issued_slot <= 216 000` (a day) and `issued_slot` cannot be ahead of the clock, so no signature outlives the day it was issued in |
| the same words used on devnet and on mainnet, or under another deployment of the program | derivation v2 binds every key to the cluster's genesis hash and the program id: those are different keys, and a devnet signature is not even a signature by the mainnet key |
| rotate back to an earlier key (A → B → A) | `used_keys` remembers every past key; `Rotate` / `rotate_pq` refuse it, so spent leaves never reopen |
| replay a signature from before a rotation | the message carries `generation`; it verifies under no later key |
| same message, another deployment of the program | the message carries the program id |
| attacker intercepts a staged signature | it binds program + vault + generation + action + expiry; the only thing they can do is submit it, which performs the owner's own intent |
| attacker breaks the payer's classical key | gets the rent back; nothing else |
| program upgrade by a compromised authority | authority burned; reproducible build |
| stolen 24 words | full control: a vault is quantum-safe, not owner-safe. This is what the Pincer1 robot adds on top |
| the tree runs out | the last free leaf is reserved for `Rotate` |
| rotate to a key the 24 words cannot reproduce (a wrong or injected target) | the chain cannot tell; the SDK's `VaultSigner` refuses a `Rotate` target that is not index k+1 of its `master` seed (`nextKeyMaterial`) unless the caller opts in with `allowForeignKey: true` |
| key history runs out | after 128 rotations (32 for a commitment) the account refuses to rotate; the vault can still spend and `Close` |

## 6. Compute and sizes

| item | value |
|---|---|
| LM-OTS W4 signature | 4 + 32 + 67×32 = 2 180 bytes |
| LMS signature, height h | 4 + 2 180 + 4 + 32·h → H5 2 348, H10 2 508, H15 2 668, H20 2 828 |
| public key | 56 bytes |
| `Vault` account | H5 126, H10 250, H15 4 218 bytes, plus 16 per rotation (at most 128) |
| `Commitment` account | 127 bytes, plus 16 per rotation (at most 32) |
| `Action` | TransferSol 57, TransferToken 89, Rotate 73, Close 49 bytes (16 of each are the validity window) |
| verify, hash calls | ≤ 67×15 chain steps + 1 (Q) + 1 (K) + h (path) ≈ 1 010–1 030 |
| `execute` compute | ~115-145k CU measured for H10, worst case ~210k; client requests 400k |
| staging | `open_sig_buffer` with a 708-byte first chunk plus `write_sig` chunks of 900 bytes: H5 and H10 take 3 transactions in total, H15 and H20 take 4 |
| `execute_direct` transaction v1 | H10: TransferSol 2 871 bytes, TransferToken 3 002, Rotate 2 854, Close 2 897; H15 adds 160; the largest (H15 TransferToken) stays under 3 200 of the 4 096 allowed |
| program binaries | `lamport_vault.so` 305 168 bytes (devnet allocation 310 000); `pq_registry.so` 262 000 bytes (devnet allocation 272 000) |

### Direct (transaction v1) against staged, measured on devnet

Measured with `sdk/packages/vault/scripts/bench-direct.ts` on devnet (solana-core 4.4.0-beta.0, feature
`txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL` active), fresh H10 vault, program
`B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH`, `confirmed` commitment, no priority fee, compute limit 400 000.
Bytes, compute units and fees are what `getTransaction` reports for the confirmed transactions
(`maxSupportedTransactionVersion: 1` for v1); the staged row sums its four transactions
(`open_sig_buffer` with the first chunk, two `write_sig`, `execute`). Wall-clock runs from the first send to the
last confirmation.

| path | action | transactions | bytes on the wire | compute units | fee (lamports) | wall-clock (ms) |
|---|---|---|---|---|---|---|
| direct-v1 | TransferSol | 1 | 2 871 | 124 854 | 5 000 | 632 |
| staged | TransferSol | 4 | 3 614 | 135 626 | 20 000 | 3 700 |
| direct-v1 | TransferToken | 1 | 3 002 | 139 342 | 5 000 | 830 |
| direct-v1 | Rotate | 1 | 2 854 | 124 140 | 5 000 | 933 |
| direct-v1 | Close | 1 | 2 897 | 117 309 | 5 000 | 669 |

Vault `5hSwvMG6BwdNZwke5hDoPX2qKsoSWPvKWV1T1u8bvup6`, program deployed in slot 510 277 112; the 16 bytes of
the validity window (`issued_slot`, `expiry_slot`) are included, so every row is 8 bytes larger than the
same measurement before the window was added.

Compute units vary by a few thousand from one signature to the next (the LM-OTS chain lengths depend on the
message digest). Transaction v1 charges the base fee only, 5 000 lamports per signature; the staged path pays
it four times and also parks the buffer's rent until `execute` returns it. The devnet `Rotate` moved 81 280
lamports from the payer into the vault for the 16 extra bytes.

A v1 message carries the compute-unit limit, the total priority fee in lamports (not a per-unit price) and
the loaded-accounts-data-size limit in its header; a v1 transaction that leaves a field unset gets **zero**,
not the legacy default, so the SDK always writes all three (`@solana/kit` 8.x builds the bytes:
`createTransactionMessage({ version: 1 })` + `compileTransaction`; the signature envelope is `message ||
signatures`, no count prefix, and the SDK assembles it itself). `@solana/web3.js` 1.x can neither build nor
decode v1, so it only forwards the raw bytes.

### Wallet compatibility

Wallet Standard `solana:signAndSendTransaction` (and `solana:signTransaction`) takes the serialised
transaction bytes and gives back a signature, so a v1 transaction needs nothing new from the interface: the
app hands over `messageBytes || 64 zero bytes` (the SDK's `unsignedTransaction`) and the wallet signs the
message, fills the slot and sends. What has to hold is that the wallet's own transaction parser accepts the
version byte `0x81` (wallets built on web3.js 1.x reject it as an unknown version; those on `@solana/kit`
8.x or a current `@solana/transactions` decode it) and that the wallet's RPC accepts 4 096-byte packets. The
feature's `supportedTransactionVersions` set is where a wallet is expected to advertise `1`; until that is
common, the web app should feature-detect by attempting the direct path and falling back to the staged flow
when the wallet refuses to sign or the RPC rejects the bytes, which is exactly `VaultSigner`'s `"auto"`
mode (`isV1Rejection` separates "cannot take v1" from "the program ran and failed"; only the former falls
back, with the same LMS signature, so no leaf is spent twice). The cold signer is unaffected: it signs the
same message either way.

## 7. Account versions and migration

Vault and Commitment accounts carry a `version` byte (currently 2). Decoders refuse other versions. There
is no in-place migration: a vault created under an earlier layout is closed and recreated (devnet vaults
from the first deployment were). Mainnet has never had a deployment, so no live accounts are affected.

## 8. Test vectors

`kat/lms_sha256_w4.json` holds deterministic vectors (H5 and H10, W4) produced by an independent RFC 8554
implementation with fixed `SEED`/`I`. Every implementation in this repository (Rust, TypeScript, later C)
must reproduce the public keys from `SEED`/`I` and verify every signature, and the SDK's own signatures must
verify under the Rust verifier.
