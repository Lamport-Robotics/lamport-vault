# lamport-vault

Post-quantum custody for Solana. Funds sit in a program account that only moves on a hash-based
signature (LMS, RFC 8554). The vault keeps a used-leaf bitmap on chain, so a one-time key can't be
reused even if the signer loses track.

Only assumption: SHA-256.

```
programs/lms            LM-OTS / LMS verify (used on chain), keygen + sign for tooling
programs/lamport-vault  the vault program
programs/pq-registry    bind a PQ key to an existing address now, use it when the protocol catches up
sdk/                    @lamport-robotics/lms, @lamport-robotics/vault
kat/                    test vectors shared by every implementation
docs/                   design notes, key derivation, how to verify a deployment
```

## build

Needs anchor 0.32.1, agave 2.3.x, node 22+. Programs build with platform-tools v1.56 (pinned in
`programs/*/Cargo.toml`, fetched on first build).

```sh
export COPYFILE_DISABLE=1   # macOS
cargo test --workspace --features lamport-lms/sign
anchor build && anchor test
cd sdk && npm i && npm test
```

## how a withdrawal works

Sign `sha256("lamport-vault/v1" || program_id || vault || u32le(generation) || action)` with any unspent
leaf `q`. On a cluster with transaction v1 the ~2.5 KB signature and the action go in one
`execute_direct` transaction. Where v1 isn't available yet the signature is staged into a buffer account
over a few transactions and `execute` picks it up; same message, same leaf, the buffer rent comes back.
Either way the program verifies the signature, sets bit `q` in the vault's bitmap, does the action.
`generation` counts key rotations and is part of the message, so a signature made before a rotate is
worthless after it.

Keys are LMS over SHA-256, trees of height 5, 10 or 15 (32, 1 024 or 32 768 leaves), LM-OTS W4. Rotate
installs a fresh key at the same address, never one the vault had before: the vault remembers 128 past
keys (a registry commitment 32). When that history is full the vault can still spend and `Close`;
the next key goes in a new vault. `Close` leaves a tombstone at the address, so a closed vault can never
be recreated and no signature from before the close can replay. The last free leaf is only ever spent on
Rotate, so a vault can't get stuck. Accounts carry version 2; there's no in-place migration, an older
vault is closed and a new one created with a fresh key.

Key derivation from the 24 words, `issued_slot` and the v2 derivation: `docs/SPEC-DERIVATION.md`,
`docs/DESIGN.md`.

## devnet

lamport_vault `B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH`
pq_registry   `48J2BtWFjEUbGPYf1yMPBkHxpy4dLo69gK2znQR2q2ad`

`scripts/verify-deploy.sh lamport-vault <id> --url devnet` builds and compares with the chain, no
Docker. `docs/VERIFY.md` has the CI path and the mainnet plan; `SECURITY.md` says where to report.

## caveats

Quantum-safe is not owner-safe: the 24 words are everything. Keys made in a browser are hot keys.
Not audited yet, no mainnet deployment yet, don't put real money in it.

MIT
