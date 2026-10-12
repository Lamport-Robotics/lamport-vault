# Lamport Vault key derivation, v1

This document is the recovery contract. Any wallet that implements it can recover a Lamport Vault from the
owner's 24 words without Lamport Robotics software.

## Inputs

- `mnemonic`: a BIP-39 phrase (12–24 words; 24 recommended). Passphrase optional, default empty.
- `master`: the 64-byte BIP-39 seed derived from the phrase (PBKDF2-HMAC-SHA512, 2048 rounds, salt
  `"mnemonic" || passphrase`), exactly as every BIP-39 wallet computes it.
- `k`: vault key index, `u32`, starting at 0. Each `Rotate` uses the next index.

## Derivation

```
SEED_k = HMAC-SHA256(key = ASCII "lamport-vault/lms-seed/v1", msg = master || u32be(k))   // 32 bytes
I_k    = HMAC-SHA256(key = ASCII "lamport-vault/lms-id/v1",   msg = master || u32be(k))[0..16]
```

`SEED_k` and `I_k` are the LMS private key inputs of RFC 8554 Appendix A. With the typecodes
(`lms_type`, `lmots_type`) the private key is complete:

```
x_q[i] = SHA-256(I_k || u32str(q) || u16str(i) || u8str(0xff) || SEED_k)
```

The public key is `u32str(lms_type) || u32str(lmots_type) || I_k || T[1]`, where `T[1]` is the Merkle root
computed per RFC 8554 Section 5.3.

## Typecodes

| name | value | use |
|---|---|---|
| `LMOTS_SHA256_N32_W4` | 3 | the only LM-OTS type the vault program accepts in v1 |
| `LMS_SHA256_M32_H5` | 5 | tests, tiny vaults |
| `LMS_SHA256_M32_H10` | 6 | default |
| `LMS_SHA256_M32_H15` | 7 | |
| `LMS_SHA256_M32_H20` | 8 | |

### SHA-256/192 keys (RFC 9858), if a program accepts them

`lamport-lms` and `@lamport-robotics/lms` also implement RFC 9858's SHA-256/192 sets
(`LMOTS_SHA256_N24_W4` = 7, `LMOTS_SHA256_N24_W8` = 8, `LMS_SHA256_M24_H*` = 10..13), whose `SEED` is
24 bytes. Both libraries take the **first 24 bytes** of the 32-byte `SEED_k` above, so the same words and
the same `k` give a SHA-256/192 key without a second derivation string. `I_k` is unchanged. Neither
program accepts these keys today (their key arrays are 56 bytes; a SHA-256/192 key is 48).

## Recovery procedure

1. Compute `master` from the words.
2. Read the vault account: `lms_pubkey` (56 bytes) and `next_q`.
3. For `k = 0, 1, 2, …` (stop at 64): derive `SEED_k, I_k`, build the tree with the account's typecodes,
   compare the resulting public key with `lms_pubkey`. The first match is the current key.
4. Sign with any leaf `q >= next_q`.

The registry (`pq-registry`) uses the same derivation with the reserved index `k = 0xFFFFFFFF` so the
commitment key never collides with a vault key.

## Why HMAC and not the LMS tree itself

`master` is shared with the owner's classical wallets (Solana `m/44'/501'/…`, EVM, Bitcoin). The HMAC with a
fixed ASCII key is a domain separator: nothing about a vault key can be learned from a classical key or vice
versa, and a future `v2` derivation changes the string, not the words.
