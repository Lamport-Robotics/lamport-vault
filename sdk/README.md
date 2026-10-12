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
and `LMS_SHA256_M32_H5 … H20` (typecodes 5–8). Private keys follow RFC 8554 Appendix A: everything is
derived from a 32-byte `SEED` and a 16-byte `I`, so a key is fully described by `(lmsType, lmotsType,
seed, I)`.

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
const k0     = LmsPrivateKey.generate(deriveKeyMaterial(master, 0)); // vault key index 0, H10/W4

// 3. In a browser, build the tree without freezing the UI
const k = await LmsPrivateKey.generateAsync(deriveKeyMaterial(master, 0), {
  onProgress: (done, total) => render(done / total),
});

// 4. Keep the tree between sessions instead of rebuilding it (interior nodes are public data)
localStorage.setItem("tree", toBase64(k.tree));
const again = LmsPrivateKey.fromTree(deriveKeyMaterial(master, 0), fromBase64(localStorage.getItem("tree")));
```

`sign(q, message, { C })` with an explicit `C` gives deterministic signatures for test vectors; without it
`C` is 32 random bytes, as the RFC specifies. The key object does **not** track which leaves were used:
on Lamport Vault the chain holds `next_q`, and the `VaultSigner` below reads it before every signature.

### Key generation performance

Chain steps are 55-byte hashes, so they go through a single-block sha256 (`sha256SingleBlock`). H10 keygen
is ~0.25s in node, H15 ~7s. `npm run bench`.

### Derivation and recovery

The contract is [`docs/SPEC-DERIVATION.md`](../docs/SPEC-DERIVATION.md). In code:

```
master  = BIP-39 seed (64 bytes)
SEED_k  = HMAC-SHA256(key = "lamport-vault/lms-seed/v1", msg = master || u32be(k))
I_k     = HMAC-SHA256(key = "lamport-vault/lms-id/v1",   msg = master || u32be(k))[0..16]
```

`deriveLmsInputs(master, k)` returns `(SEED_k, I_k)`; `deriveKeyMaterial` adds the typecodes;
`deriveRegistryKeyMaterial` uses the reserved index `k = 0xFFFFFFFF` for the pq-registry commitment key.

Recovery:

1. Read the vault account (`decodeVault`): it holds the current `lms_pubkey` (56 bytes, with the
   typecodes) and `next_q`.
2. Compute `master` from the words (and passphrase, if one was used).
3. `recoverKey(master, lmsPubkey)` walks `k = 0, 1, 2, …` (up to 64 by default). For each `k` it derives
   `I_k` and compares it with the `I` inside the public key; only a match is expanded into a full tree and
   confirmed against the root. One `Rotate` moves to `k + 1`, so a vault rotated three times is found at
   `k = 3`.
4. Sign with any `q >= next_q` (`VaultSigner` does this automatically).


## `@lamport-robotics/vault`

The program ids are exported as `LAMPORT_VAULT_PROGRAM_ID` and `PQ_REGISTRY_PROGRAM_ID` (the ids declared
in `programs/`); every builder and client also accepts an explicit `programId`.

### High level

```ts
import { Connection, Keypair } from "@solana/web3.js";
import { VaultSigner, RegistryClient } from "@lamport-robotics/vault";

const rpc = new Connection("https://api.devnet.solana.com", "confirmed");
const payer = Keypair.fromSecretKey(/* classical key: pays rent and fees, nothing more */);

const signer = new VaultSigner({ rpc, key, payer });  // key: LmsPrivateKey from the lms package
await signer.createVault();                           // one transaction; vault address = PDA of sha256(key.publicKey)

// Deposit: a plain SystemProgram.transfer to signer.vault, from anywhere.

// Withdraw: reads next_q, signs, stages, executes. Returns every transaction signature.
const res = await signer.execute({ kind: "TransferSol", to, lamports: 1_000_000_000n });
res.q;            // leaf used
res.signatures;   // [open_sig_buffer, write_sig, write_sig, execute] for an H10 key

// Other actions
await signer.execute({ kind: "TransferToken", mint, to: destinationTokenAccount, amount: 5_000n });
await signer.execute({ kind: "Rotate", newLmsPubkey: nextKey.publicKey });  // next_q resets, vault address unchanged
await signer.execute({ kind: "Close", to });                                  // all lamports to `to`
```

`expirySlot` may be given on any action; when omitted the signer uses the current slot plus 300. The
signer refuses `q < next_q`, `q` beyond the tree, and anything but `Rotate` on the last leaf (the
exhaustion rule), and it never reuses a leaf within one process even before the chain confirms.

After a `Rotate`, construct the next `VaultSigner` with the new key and `vault: signer.vault`; the
vault PDA is derived from the *initial* key and never changes.

The registry:

```ts
const registry = new RegistryClient({ rpc, payer });
await registry.commit(ownerKeypair, pqKey.publicKey);                 // classical owner signs once; first write wins
await registry.rotatePq(owner.publicKey, pqKey, nextPqKey.publicKey); // LMS-signed, staged in a PqSigBuffer: open, 3 writes, rotate_pq
```

### What happens on the wire

A W4/H10 signature is 2 508 bytes and a Solana transaction carries 1 232, so a signed action is staged:

1. `open_sig_buffer(nonce, action, sig_len, first_chunk)` allocates the `SigBuffer` PDA
   `["sig", vault, payer, nonce_le_u64]` and writes as many signature bytes as fit in the same
   transaction (`openSigBufferFirstChunkCapacity`, about 760 bytes for a `TransferSol`).
2. `write_sig(offset, chunk)` appends the rest in chunks of at most 900 bytes; `offset` must equal the
   bytes written so far.
3. `execute()` with a 400 000 CU compute-budget request: verifies the LMS signature over
   `sha256("lamport-vault/v1" || vault || action_bytes)`, sets `next_q = q + 1`, performs the action, and
   refunds the buffer rent to `payer`.

`buildStagedExecution` returns these instructions grouped per transaction without sending anything;
`closeSigBufferInstruction` abandons a half-written buffer and refunds it.

### Byte layouts

Everything is plain Borsh behind Anchor's 8-byte discriminators (`sha256("global:<ix>")[0..8]` for
instructions, `sha256("account:<Name>")[0..8]` for accounts). `encodeAction` / `decodeAction` cover the
`Action` enum exactly as in `docs/DESIGN.md`; `decodeVault`, `decodeSigBuffer`, `decodeCommitment`,
`decodePqSigBuffer` read the accounts. Account order per instruction follows the program's
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
