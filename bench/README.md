# LMS verification compute benchmark

Measures the Solana compute units of one `LmsPublicKey::parse` + `lms_verify`, the work the vault's
`execute` does, for each parameter set. The program (`lms-cu`) reads the public key, message and signature
from an account, as the vault reads a staged signature from its buffer. Sixteen signatures per set, 32-byte
messages (the size of the vault's action digest), leaves spread across the tree.

```sh
export COPYFILE_DISABLE=1                                   # macOS
cd bench/gen && cargo run --release                         # writes lms-cu/vectors.bin
cd ../lms-cu && cargo build-sbf                             # builds target/deploy/lms_cu.so
cd .. && npm i --no-save litesvm@0.8.0 @solana/web3.js@1 && node run.mjs
```

Neither crate is a workspace member; both have their own `[workspace]` table. `lms-cu` enables
`lamport-lms`'s `sha256-192` feature; the vault and registry programs do not.

## Results

LiteSVM 0.8.0, platform-tools v1.52, `cargo build-sbf` 3.1.12. The compute-budget instruction's 150 CU is
subtracted.

| parameter set | signature | public key | CU min | CU avg | CU max |
|---|---|---|---|---|---|
| SHA-256 N32 W4 H10, `main` before this branch | 2 508 B | 56 B | 107 105 | 118 587 | 134 651 |
| SHA-256 N32 W4 H10, this branch | 2 508 B | 56 B | 108 446 | 119 588 | 135 182 |
| **SHA-256/192 N24 W4 H10** (RFC 9858) | **1 500 B** | **48 B** | **81 729** | **93 186** | **102 099** |
| SHA-256/192 N24 W8 H10 (RFC 9858) | 900 B | 48 B | 555 226 | 685 086 | 852 046 |
| SHA-256/192 N24 W8 H5 (RFC 9858) | 780 B | 48 B | 603 642 | 674 754 | 702 582 |

The N32 baseline matches DESIGN.md's devnet measurement (~115–145k CU for `execute` on H10), so the
harness measures the same work.

**Cost of the change to existing keys:** +1 001 CU on average (+0.8%) for N32 W4. A first version that
zeroed the unused tail of every digest cost +13%, because each `fill` became a `sol_memset` syscall; the
verifier is now monomorphized on the hash length and never zeroes in the hot loop.

## Program size

The RFC 9858 sets sit behind the `sha256-192` feature, which the programs do not enable, so their verifier
contains only the SHA-256 path. `cargo build-sbf`, same toolchain:

| program | `main` | this branch | difference |
|---|---|---|---|
| `lamport_vault.so` | 303 096 | 305 512 | +2 416 |
| `pq_registry.so` | 258 800 | 261 128 | +2 328 |

The vault stays 4 488 bytes under its 310 000-byte devnet allocation. Without the feature gate it was 309 432,
568 bytes under.

## What it means for the vault

- **N24 W4 H10** is smaller and cheaper: 40% shorter signatures, 21% fewer compute units,
  one less staging transaction (1 500 bytes is a 708-byte first chunk plus one 792-byte write, against two
  writes today), and roughly 1 000 fewer bytes in an `execute_direct` transaction v1.
- **N24 W8** is not worth it: about 5.8× the compute for 600 fewer bytes, and by our byte count it still
  does not fit every action in a 1 232-byte legacy transaction (not measured).
- **The trade-off** is the security level. SHA-256/192 gives about 192-bit classical security (RFC 9858
  Section 8), against about 256 bits for SHA-256. Against a quantum attacker the generic bound is 2^96 hash
  evaluations rather than 2^128; RFC 9858 argues that the depth Grover's algorithm needs puts this out of
  reach, and NIST SP 800-208 already lists 192-bit parameter sets. It is a judgment call, not a free upgrade.

Signing in a browser is also cheaper: an H10 W4 key needs 1 024 × 51 × 16 ≈ 0.84M hashes to build,
against 1 024 × 67 × 16 ≈ 1.1M for SHA-256 W4.
