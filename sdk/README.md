# sdk

- `@lamport-robotics/lms`: LM-OTS/LMS over SHA-256, keygen/sign/verify, 24 words -> vault keys
- `@lamport-robotics/vault`: PDAs, Borsh actions, instruction builders, account decoders, `VaultSigner`

ESM, node 22+ and browsers. Deps: `@noble/hashes`, `@scure/bip39`, `@solana/web3.js`. No anchor client,
layouts are encoded by hand.

```sh
cd sdk
npm install
npm test
npm run typecheck
npm run build
npm run kat       # rewrite kat/sdk_signatures.json, kat/vault_encoding.json
npm run bench
```

## `@lamport-robotics/lms`

Parameter sets: `LMOTS_SHA256_N32_W4` (typecode 3; W1/W2/W8 are in the tables and work the same way)
and `LMS_SHA256_M32_H5 … H20` (typecodes 5–8). The vault and the registry accept H5, H10 and H15 with
W4 (`VAULT_LMS_TYPES`); H20 verifies here but is refused on chain. Private keys follow RFC 8554
Appendix A: everything is derived from a 32-byte `SEED` and a 16-byte `I`, so a key is fully described
by `(lmsType, lmotsType, seed, I)`.

```ts
import {
  LmsPrivateKey, lmsVerify, randomKeyMaterial, LMS_SHA256_M32_H10,
  generateMnemonic, mnemonicToMaster, deriveKeyMaterial, recoverKey,
} from "@lamport-robotics/lms";

// 1. A key from random material (tests, throwaway keys)
const key = LmsPrivateKey.generate(randomKeyMaterial(LMS_SHA256_M32_H10)); // 1024 leaves, ~0.25 s in Node
key.publicKey;                       // 56 bytes: u32 lms_type || u32 lmots_type || I[16] || T[1][32]
const sig = key.sign(0, message);    // fresh random C; sig.length === 2508 for H10
lmsVerify(key.publicKey, message, sig); // true

// 2. A key from 24 words (what a wallet does)
const words  = generateMnemonic();                   // 24 words
const master = mnemonicToMaster(words);              // 64-byte BIP-39 seed, optional passphrase
const scope  = { genesisHash: CLUSTERS.devnet.genesisHash, programId: LAMPORT_VAULT_PROGRAM_ID };
const k0     = LmsPrivateKey.generate(deriveKeyMaterial(master, 0, scope)); // vault key index 0, H10/W4

// 3. In a browser, build the tree without freezing the UI
const k = await LmsPrivateKey.generateAsync(deriveKeyMaterial(master, 0, scope), {
  onProgress: (done, total) => render(done / total),
});

// 4. Keep the tree between sessions instead of rebuilding it (interior nodes are public data)
localStorage.setItem("tree", toBase64(k.tree));
const again = LmsPrivateKey.fromTree(deriveKeyMaterial(master, 0, scope), fromBase64(localStorage.getItem("tree")));
```

`sign(q, message, { C })` with an explicit `C` gives deterministic signatures for test vectors; without it
`C` is 32 random bytes, as the RFC specifies. The key object does **not** track which leaves were used:
on Lamport Vault the chain holds a used-leaf bitmap, and the `VaultSigner` below reads it before every
signature.

### Key generation performance

Chain steps are 55-byte hashes, so they go through a single-block sha256 (`sha256SingleBlock`). H10 keygen
is ~0.25s in node, H15 ~7s. `npm run bench`.

### Derivation and recovery

The contract is [`docs/SPEC-DERIVATION.md`](../docs/SPEC-DERIVATION.md). In code:

```
master  = BIP-39 seed (64 bytes, optional passphrase)
info_k  = genesis_hash || program_id || u32be(k)
SEED_k  = HKDF-SHA256(master, salt = "lamport-vault/lms-seed/v2", info = info_k || "seed")
I_k     = HKDF-SHA256(master, salt = "lamport-vault/lms-id/v2",   info = info_k || "id")[0..16]
```

Every key is bound to a cluster (its genesis hash) and a program id: the same words give other keys on
mainnet, or under another deployment. `deriveLmsInputs(master, k, scope)` returns `(SEED_k, I_k)`;
`deriveKeyMaterial` adds the typecodes; `deriveRegistryKeyMaterial` uses the reserved index
`k = 0xFFFFFFFF` for the pq-registry commitment key. `CLUSTERS` has the genesis hashes.

Recovery:

1. Read the vault account (`decodeVault`): it holds the current `lms_pubkey` (56 bytes, with the
   typecodes), the used-leaf bitmap and the key `generation`.
2. Compute `master` from the words (and passphrase, if one was used).
3. `recoverKey(master, lmsPubkey, scope)` walks `k = 0, 1, 2, …` (up to `RECOVERY_MAX_INDEX`, 4096). For each `k` it derives
   `I_k` and compares it with the `I` inside the public key; only a match is expanded into a full tree and
   confirmed against the root. One `Rotate` moves to `k + 1`, so a vault rotated three times is found at
   `k = 3`.
4. Sign with any unspent `q` (`VaultSigner` does this automatically).


## `@lamport-robotics/vault`

The program ids are exported as `LAMPORT_VAULT_PROGRAM_ID` and `PQ_REGISTRY_PROGRAM_ID` (the ids declared
in `programs/`); every builder and client also accepts an explicit `programId`.

### High level

```ts
import { Connection, Keypair } from "@solana/web3.js";
import { FileLeafJournal, VaultSigner, RegistryClient, sweepClosed } from "@lamport-robotics/vault";

const rpc = new Connection("https://api.devnet.solana.com", "confirmed");
const payer = Keypair.fromSecretKey(/* classical key: pays rent and fees, nothing more */);

// key: LmsPrivateKey from the lms package. journal: where the signer records a leaf BEFORE signing it
// (required; FileLeafJournal in Node, BrowserLeafJournal on IndexedDB, or "ephemeral" for memory only).
// A journal belongs to one key: it is keyed by sha256(key.publicKey) (keyFingerprint), here the file
// <dir>/<fingerprint>.json.
const signer = new VaultSigner({ rpc, key, payer, journal: new FileLeafJournal(key.publicKey, { dir: "~/.lamport-vault" }) });
await signer.createVault();                           // one transaction; vault address = PDA of sha256(key.publicKey)
                                                      // refused if the address holds a vault or the tombstone of a closed one

// Deposit: a plain SystemProgram.transfer to signer.vault, from anywhere.

// Withdraw: reads the bitmap + generation, picks a free leaf, signs, sends.
const res = await signer.execute({ kind: "TransferSol", to, lamports: 1_000_000_000n });
res.q;            // leaf used
res.generation;   // key generation the message was bound to
res.mode;         // "staged" (default): [open_sig_buffer, write_sig, write_sig, execute] for an H10 key, in res.signatures
                  // "direct-v1": one execute_direct transaction v1; "auto": direct first, staged if the RPC or wallet refuses v1

// Other actions
await signer.execute({ kind: "TransferToken", mint, to: destinationTokenAccount, amount: 5_000n });
await signer.execute({ kind: "Rotate", newLmsPubkey: nextKey.publicKey });  // bitmap cleared, generation + 1, address unchanged
await signer.execute({ kind: "Close", to });                                  // all lamports to `to`; a Tombstone keeps the address

// Tokens the Close was not handed (closeTokenAccounts) stay owned by the PDA: anyone can sweep them to
// `to`, the tombstone's heir, and nowhere else. One sweep_closed transaction per token account of the mint.
await sweepClosed(rpc, payer, signer.vault, mint);                             // { heir, heirTokenAccount, swept: [{ account, signature }] }
```

A closed vault's address is never reusable (`Close` leaves an 81-byte `Tombstone` holding its own rent and
naming the heir; `create_vault` on it fails `VaultClosed`), so the next vault needs the next key:
`nextFreshKeyIndex(master, scope, rpc)` walks the derivation indices and returns the first whose vault
address is free, skipping tombstones and live vaults; `vaultAddressState(rpc, vault)` is the one-address
check.

`expirySlot` may be given on any action; when omitted the signer uses the current slot plus 300. The
signer refuses a spent leaf, `q` beyond the tree, anything but `Rotate` or `Close` on the last free leaf
(the exhaustion rule), a `Rotate` to a key the vault had before or with other typecodes, and it never reuses a
leaf within one object even before the chain confirms.

The journal is what stops a leaf from ever being signed twice (docs/DESIGN.md "Signer rollback"): the
leaf is written to it before the signature exists, and before every signature it is compared with the
chain; a journal that is behind (restored from a backup, or another copy of the key moved on) makes the
signer refuse everything but `Rotate` (`StaleSignerError`). Journals are keyed by the LMS key's
fingerprint, `sha256(lms_pubkey)` in hex (`keyFingerprint`), because a one-time key is one-time wherever
it is used: a `VaultSigner` refuses a journal built for another key, and a record that names another
vault means the key is being pointed at a second vault, which is refused with no override
(`JournalVaultMismatchError`). The record (`{ v: 2, key, vault, generation, spent, reserved }`) still
carries the vault and the key generation for the stale check. `FileLeafJournal(key, { dir })` writes
`<dir>/<fingerprint>.json` (or `{ path }`) and holds a `<path>.lock` across processes
(`JournalLockedError` when another live process has it); `BrowserLeafJournal({ key })` keeps one
IndexedDB record per key and a Web Lock across tabs. After a `Rotate` the retired key's record is closed
out and the new key starts its own. `journal: "ephemeral"` is for tests and one-shot scripts: a memory
journal that dies with the object, a one-line `console.warn` on the first signature, and
`ephemeral: true` on every result.

Leaves are a bitmap on chain, so several devices can share one key without talking to each other:

```ts
// device k of n only ever uses leaves q ≡ k (mod n); each device keeps its own journal
const phone  = new VaultSigner({ rpc, key, payer, lane: 0, lanes: 2, journal: new BrowserLeafJournal({ key: key.publicKey }) });
const laptop = new VaultSigner({ rpc, key, payer, lane: 1, lanes: 2, journal: new FileLeafJournal(key.publicKey, { dir: "~/.lamport-vault" }) });

// reserve(q) runs BEFORE a leaf is signed, on top of the journal: an extra hook for a secure element
// or a database; throw to veto the leaf.
const robot = new VaultSigner({ rpc, key, payer, journal, reserve: async (q) => store.markUsedOrThrow(q) });
```

`isLeafUsed(vault, q)`, `firstFreeLeaf(vault, lane, lanes)`, `freeLeaves(vault)` and `hasUsedKey(vault, pubkey)`
read a decoded account; `signer.nextQ()` is the lane's next free leaf (`undefined` once exhausted).

After a `Rotate`, construct the next `VaultSigner` with the new key and `vault: signer.vault`; the
vault PDA is derived from the *initial* key and never changes. A vault keeps the hashes of its past
keys, up to `VAULT_MAX_KEY_HISTORY` (128; a commitment `COMMITMENT_MAX_KEY_HISTORY`, 32), and refuses
any of them (`KeyReused`) or a rotate past the cap (`HistoryFull`). With a full history the vault still
spends and `Close`s; the next key gets a new vault, created the same way.

`decodeVault` and `decodeCommitment` accept account version 2 (`VAULT_ACCOUNT_VERSION`,
`COMMITMENT_ACCOUNT_VERSION`) and throw on anything else; there is no in-place migration, an older
vault is closed and a new one created with a fresh key. `decodeVault` on a tombstone throws
`VaultClosedError` (with the decoded tombstone); `decodeVaultOrTombstone` returns whichever of the two
sits at the address, `decodeTombstone` / `isTombstone` read the tombstone itself (`heir` included;
`sweepClosedInstruction` builds one `sweep_closed`, `sweepClosed` finds and sweeps a closed vault's token
accounts for a mint).

The registry:

```ts
const registry = new RegistryClient({ rpc, payer });
await registry.commit(ownerKeypair, pqKey.publicKey);                 // classical owner signs once; first write wins
await registry.rotatePq(owner.publicKey, pqKey, nextPqKey.publicKey); // LMS-signed, staged in a PqSigBuffer: open, 3 writes, rotate_pq
```

### What happens on the wire

A W4/H10 signature is 2 508 bytes and a legacy Solana transaction carries 1 232, so a signed action is staged:

1. `open_sig_buffer(nonce, action, sig_len, first_chunk)` allocates the `SigBuffer` PDA
   `["sig", vault, payer, nonce_le_u64]` and writes as many signature bytes as fit in the same
   transaction (`openSigBufferFirstChunkCapacity`, about 760 bytes for a `TransferSol`).
2. `write_sig(offset, chunk)` appends the rest in chunks of at most 900 bytes; `offset` must equal the
   bytes written so far.
3. `execute()` with a 400 000 CU compute-budget request: verifies the LMS signature over
   `sha256("lamport-vault/v1" || program_id || vault || u32le(generation) || action_bytes)`
   (`vaultMessage`), sets bit `q` of the bitmap, performs the action, and refunds the buffer rent to
   `payer`. `registryMessage` is `sha256("pq-registry/v1" || program_id || owner || u32le(generation) ||
   new_pq_pubkey || u64le(issued_slot) || u64le(expiry_slot))`; `MESSAGE_VERSION` is the `1` in both domain
   strings.

`buildStagedExecution` returns these instructions grouped per transaction without sending anything;
`closeSigBufferInstruction` abandons a half-written buffer and refunds it.

On a cluster with transaction v1 (SIMD-0385: 4 096-byte transactions, version byte `0x81`, compute limit
and priority fee in the message header) the same signed action goes in **one** transaction:
`execute_direct(action, signature)` with accounts `vault`, `payer` (signer), `system_program` and the
action's remaining accounts. `executeDirectInstruction` builds it, `buildDirectV1Transaction` produces the
v1 message bytes (via `@solana/kit` 8.x; `@solana/web3.js` 1.x cannot build or parse v1) plus the unsigned
wire transaction for a wallet, `assembleV1Transaction` appends the signatures, and `sendDirectV1(rpc,
signer, params)` does the round trip. `VaultSigner` exposes it as `mode: "direct-v1"`, and `"auto"` falls back
to the staged flow with the same LMS signature when the wallet or RPC rejects v1 (`isV1Rejection`).
`scripts/bench-direct.ts` measures both paths on devnet; the numbers are in `docs/DESIGN.md` section 6.

### Byte layouts

Everything is plain Borsh behind Anchor's 8-byte discriminators (`sha256("global:<ix>")[0..8]` for
instructions, `sha256("account:<Name>")[0..8]` for accounts). `encodeAction` / `decodeAction` cover the
`Action` enum exactly as in `docs/DESIGN.md`; `decodeVault`, `decodeTombstone`, `decodeSigBuffer`,
`decodeCommitment`, `decodePqSigBuffer` read the accounts. Account order per instruction follows the program's
`#[derive(Accounts)]` structs and is listed at the top of `src/instructions.ts` and `src/registry.ts`.

Byte-exact vectors for all of this live in [`kat/vault_encoding.json`](../kat/vault_encoding.json) so the
Rust tests assert the same bytes.

## vectors

`kat/lms_sha256_w4.json` is from an independent RFC 8554 implementation; `kat/sdk_signatures.json` and
`kat/vault_encoding.json` are written by `npm run kat` and checked by the rust tests.

## custody

A key made in a browser is a hot key. Keep the words offline; the Pincer1 controller can hold the same
material (`seed`, `I`, typecodes) and sign with the owner present.

MIT
