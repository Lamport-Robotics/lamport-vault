# Lamport Vault key derivation, v2

This document is the recovery contract. Any wallet that implements it can recover a Lamport Vault from the
owner's 24 words without Lamport Robotics software. v2 replaces v1 outright: v1 keys were never used on
mainnet (there has been no mainnet deployment), and devnet vaults are disposable.

## Inputs

- `mnemonic`: a BIP-39 phrase (12–24 words; 24 recommended). Passphrase optional, default empty.
- `master`: the 64-byte BIP-39 seed derived from the phrase (PBKDF2-HMAC-SHA512, 2048 rounds, salt
  `"mnemonic" || passphrase`), exactly as every BIP-39 wallet computes it.
- `genesis_hash`: the 32-byte genesis hash of the cluster the vault lives on (`getGenesisHash`), the
  bytes behind the base58 string:

  | cluster | genesis hash (base58) |
  |---|---|
  | devnet | `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG` |
  | mainnet-beta | `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d` |

  Any other cluster (a local validator, a fork) is named the same way by its own genesis hash.
- `program_id`: the 32-byte id of the program the key will own an account under: the vault program for
  vault keys, the registry program for the registry key. Another deployment of the same code is another
  program id and gets other keys.
- `k`: vault key index, `u32`, starting at 0. Each `Rotate` uses the next index.

Nothing is implicit: an implementation takes the genesis hash and the program id as explicit inputs
(`deriveKeyMaterial(master, k, { genesisHash, programId })` in the SDK). There is no default cluster.

## Derivation

```
info_seed = genesis_hash[32] || program_id[32] || u32be(k) || ASCII "seed"      // 72 bytes
info_id   = genesis_hash[32] || program_id[32] || u32be(k) || ASCII "id"        // 70 bytes

SEED_k = HKDF-SHA256(ikm = master, salt = ASCII "lamport-vault/lms-seed/v2", info = info_seed, L = 32)
I_k    = HKDF-SHA256(ikm = master, salt = ASCII "lamport-vault/lms-id/v2",   info = info_id,   L = 16)
```

HKDF is RFC 5869 with SHA-256 (extract with the salt as the HMAC key, then expand); `L` is the output
length, so `SEED_k` is the first and only 32-byte block and `I_k` the first 16 bytes of the first block.

`SEED_k` and `I_k` are the LMS private key inputs of RFC 8554 Appendix A. With the typecodes
(`lms_type`, `lmots_type`) the private key is complete:

```
x_q[i] = SHA-256(I_k || u32str(q) || u16str(i) || u8str(0xff) || SEED_k)
```

The public key is `u32str(lms_type) || u32str(lmots_type) || I_k || T[1]`, where `T[1]` is the Merkle root
computed per RFC 8554 Section 5.3.

### The registry key

The `pq-registry` commitment key uses the reserved index `k = 0xFFFFFFFF` with the **registry** program id
in the info, so it never collides with a vault key (different `k`, and a different program id).

### Why the vault id is not in the info

A vault's address is derived from its first key (`vault_id = sha256(initial lms_pubkey)`), so binding the
key to the vault id would be circular: the key has to exist before the vault does. The cluster and the
program id are known before the first key is made, which is why they are what the derivation binds to.

### What the cluster binding is for, and what it is not

With the genesis hash in the info, the same words produce different keys on devnet and on mainnet, and
different keys under another deployment of the program. A key made for a devnet vault therefore cannot be
the key of a mainnet vault, and a devnet signature cannot even be a signature by the mainnet key.

This complements the message binding and does not replace it. Every signed message already carries the
program id, the vault (or owner) address and the key generation (`DESIGN.md` section 2), so a signature
is only ever valid under one program, one account and one key generation, and the validity window bounds
it in time. Derivation separation is a second, independent fence around the keys themselves; the message
binding is what makes each signature single-purpose.

## Typecodes

| name | value | use |
|---|---|---|
| `LMOTS_SHA256_N32_W4` | 3 | the only LM-OTS type the vault program accepts |
| `LMS_SHA256_M32_H5` | 5 | tests, tiny vaults |
| `LMS_SHA256_M32_H10` | 6 | default |
| `LMS_SHA256_M32_H15` | 7 | |
| `LMS_SHA256_M32_H20` | 8 | registry only (the vault refuses it) |

## Recovery procedure

1. Compute `master` from the words.
2. Know the cluster (its genesis hash) and the vault program id.
3. Read the vault account: `lms_pubkey` (56 bytes: typecodes, `I`, root), `generation` and the used-leaf
   bitmap `used`.
4. For `k = 0, 1, 2, …` (stop at 64): derive `I_k`; if it differs from the `I` in `lms_pubkey`, next `k`.
   Otherwise derive `SEED_k`, build the tree with the account's typecodes and compare the public key with
   `lms_pubkey`. The first match is the current key. (`I_k` is 16 bytes; comparing it first means one tree
   build in the normal case.)
5. Sign with any leaf `q` whose bit in `used` is clear (bit `q` is byte `q / 8`, bit `q % 8`). Leaves are
   not ordered; the chain refuses a set bit. Keep your own record of the leaves you sign (the SDK's leaf
   journal), since a leaf you signed but have not yet submitted still reads as free on chain.
6. Bind every message to the vault's current `generation` (`DESIGN.md` section 2). A later `Rotate` goes to
   index `k + 1`.

For the registry: the commitment account holds `pq_pubkey` and `next_q`; the key is index `0xFFFFFFFF`
under the registry program id, and the next usable leaf is `next_q` (registry leaves are spent in order).

## Test vectors

`kat/derivation_v2.json` holds vectors produced by this specification's TypeScript implementation: for a
master seed (the BIP-39 reference phrase with and without the `TREZOR` passphrase), a cluster, a program id
and `k`, it lists the two HKDF `info` strings, `SEED_k`, `I_k` and the resulting `LMS_SHA256_M32_H5` /
`LMOTS_SHA256_N32_W4` public key. Every implementation (TypeScript, Rust, firmware) must reproduce all of
them.

## Why HKDF with the cluster and program in the info

`master` is shared with the owner's classical wallets (Solana `m/44'/501'/…`, EVM, Bitcoin). The HKDF salt
is a domain separator: nothing about a vault key can be learned from a classical key or vice versa, and a
future `v3` changes the salt strings, not the words. The info carries what the key is for, so one phrase
yields independent key families per cluster and per program without any of them knowing about the others.
