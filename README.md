# lamport-vault

Post-quantum custody for Solana. Funds sit in a program account that only moves on a hash-based
signature (LMS, RFC 8554). The vault keeps the one-time-key counter on chain, so a leaf can't be
reused even if the signer loses track.

Only assumption: SHA-256.

```
programs/lms            LM-OTS / LMS verify (used on chain), keygen + sign for tooling
programs/lamport-vault  the vault program
programs/pq-registry    bind a PQ key to an existing address now, use it when the protocol catches up
sdk/                    @lamport-robotics/lms, @lamport-robotics/vault
kat/                    test vectors shared by every implementation
docs/                   design notes, key derivation
```

## build

Needs anchor 0.32, agave 2.x, node 22+.

```sh
export COPYFILE_DISABLE=1   # macOS
cargo test -p lamport-lms --features sign
anchor build && anchor test
cd sdk && npm i && npm test
```

## how a withdrawal works

Sign `sha256("lamport-vault/v1" || program_id || vault || u32le(generation) || action)` with any unspent
leaf `q`. The ~2.5 KB signature is staged into a buffer account over a few transactions, then `execute`
verifies it, marks leaf `q` spent in the vault's bitmap, does the action and refunds the buffer. Rotate
installs a fresh key at the same address (never one the vault had before); the last free leaf is reserved
for that so a vault can't get stuck.

## devnet

lamport_vault `B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH`
pq_registry   `48J2BtWFjEUbGPYf1yMPBkHxpy4dLo69gK2znQR2q2ad`

## caveats

Quantum-safe is not owner-safe: the 24 words are everything. Keys made in a browser are hot keys.
Not audited yet, don't put real money in it.

MIT
