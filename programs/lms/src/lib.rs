//! # lamport-lms
//!
//! Leighton-Micali hash-based signatures ([RFC 8554]) for Solana programs and
//! the tooling around them.
//!
//! The crate has two halves:
//!
//! * **Verification** (always compiled, `no_std`, no heap except one scratch
//!   vector): LM-OTS Algorithm 4b and LMS Algorithm 6, built on
//!   `solana_sha256_hasher::hashv`, which is the SHA-256 syscall when the crate
//!   is compiled for `target_os = "solana"` and a software SHA-256 everywhere
//!   else. The same code runs in the vault program and in host tests.
//! * **Key generation and signing** (feature `sign`): RFC 8554 Appendix A
//!   pseudorandom private keys from `(SEED, I)`, Merkle tree construction
//!   (Section 5.3, Appendix C), and signature generation (Algorithms 3 and
//!   5.4.1). This half needs `std` and is used by `lms-tool` and the tests.
//!
//! ## Parameter sets
//!
//! RFC 8554 defines SHA-256 with 32-byte output (`n = m = 32`). RFC 9858 adds
//! SHA-256/192: the same SHA-256, truncated to its first 24 bytes
//! (`n = m = 24`), which is still one `sol_sha256` syscall per hash. Its
//! SHAKE256 rows are not implemented (no SHAKE syscall on Solana). The LMS
//! and LM-OTS halves of a key must use the same length.
//!
//! ### LM-OTS typecodes (RFC 8554 Table 1)
//!
//! | name                  | typecode | w | p   | ls | signature bytes | accepted |
//! |-----------------------|----------|---|-----|----|-----------------|----------|
//! | `LMOTS_SHA256_N32_W1` | 1        | 1 | 265 | 7  | 8516            | no       |
//! | `LMOTS_SHA256_N32_W2` | 2        | 2 | 133 | 6  | 4292            | no       |
//! | `LMOTS_SHA256_N32_W4` | 3        | 4 | 67  | 4  | 2180            | **yes**  |
//! | `LMOTS_SHA256_N32_W8` | 4        | 8 | 34  | 0  | 1124            | no       |
//! | `LMOTS_SHA256_N24_W1` | 5        | 1 | 200 | 8  | 4828            | no       |
//! | `LMOTS_SHA256_N24_W2` | 6        | 2 | 101 | 6  | 2452            | no       |
//! | `LMOTS_SHA256_N24_W4` | 7        | 4 | 51  | 4  | 1252            | **yes**  |
//! | `LMOTS_SHA256_N24_W8` | 8        | 8 | 26  | 0  | 652             | yes      |
//!
//! The arithmetic (`coef`, checksum, chain lengths) is written for any `w` in
//! `{1, 2, 4, 8}`; the table above carries all four rows. Only W4 is marked
//! accepted because its 67 chains of 15 steps are the compute sweet spot on
//! Solana. Accepting another row means adding it to [`LmotsType::ACCEPTED`] and
//! raising [`MAX_P`] (the scratch space bound); nothing else changes.
//!
//! ### LMS typecodes (RFC 8554 Table 2)
//!
//! | name                 | typecode | height h | leaves    | signature bytes (with W4) | accepted |
//! |----------------------|----------|----------|-----------|---------------------------|----------|
//! | `LMS_SHA256_M32_H5`  | 5        | 5        | 32        | 2348                      | yes      |
//! | `LMS_SHA256_M32_H10` | 6        | 10       | 1 024     | 2508                      | yes      |
//! | `LMS_SHA256_M32_H15` | 7        | 15       | 32 768    | 2668                      | yes      |
//! | `LMS_SHA256_M32_H20` | 8        | 20       | 1 048 576 | 2828                      | yes      |
//! | `LMS_SHA256_M32_H25` | 9        | 25       | 33 554 432| 2988                      | no       |
//!
//! | name                 | typecode | height h | leaves    | signature bytes (with N24 W4) | accepted |
//! |----------------------|----------|----------|-----------|-------------------------------|----------|
//! | `LMS_SHA256_M24_H5`  | 10       | 5        | 32        | 1380                          | yes      |
//! | `LMS_SHA256_M24_H10` | 11       | 10       | 1 024     | 1500                          | yes      |
//! | `LMS_SHA256_M24_H15` | 12       | 15       | 32 768    | 1620                          | yes      |
//! | `LMS_SHA256_M24_H20` | 13       | 20       | 1 048 576 | 1740                          | yes      |
//!
//! "Accepted" is what this crate parses. Each program decides for itself:
//! the vault and the registry still take 56-byte (SHA-256) keys only.
//!
//! ## Byte layouts
//!
//! ```text
//! LMS public key (24 + m bytes: 56 for SHA-256, 48 for SHA-256/192)
//!   u32 lms_type || u32 lmots_type || I[16] || T[1][m]
//!
//! LM-OTS signature (4 + n (p+1) bytes)
//!   u32 lmots_type || C[n] || y[0][n] || ... || y[p-1][n]
//!
//! LMS signature (4 + lmots_sig + 4 + m h bytes)
//!   u32 q || lmots_signature || u32 lms_type || path[0][m] || ... || path[h-1][m]
//! ```
//!
//! All integers are big-endian (network byte order), as in the RFC.
//!
//! ## Domain separation (RFC 8554 Section 7.1)
//!
//! | constant   | value    | used in                                   |
//! |------------|----------|-------------------------------------------|
//! | `D_PBLC`   | `0x8080` | hash of all chain ends into the OTS key K |
//! | `D_MESG`   | `0x8181` | hash of the message with randomizer C     |
//! | `D_LEAF`   | `0x8282` | leaf node of the Merkle tree              |
//! | `D_INTR`   | `0x8383` | interior node of the Merkle tree          |
//! | `j = 0xff` | Appendix A private-key derivation, `i < p`     |
//! | `i = 0xfffd, j = 0xff` | this crate's deterministic randomizer C (signing only; verifiers never see it) |
//!
//! [RFC 8554]: https://www.rfc-editor.org/rfc/rfc8554
//! [RFC 9858]: https://www.rfc-editor.org/rfc/rfc9858

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

pub mod error;
pub mod hash;
pub mod lmots;
pub mod lms;
pub mod params;

#[cfg(feature = "sign")]
pub mod sign;

pub use error::Error;
pub use lmots::{lmots_public_key_candidate, parse_lmots_signature, LmotsSignature};
pub use lms::{
    lms_root_candidate, lms_signature_len, lms_verify, parse_lms_signature, peek_q, verify_parsed,
    public_key_len, LmsPublicKey, LmsSignature, LMS_PUBLIC_KEY_LEN,
};
pub use params::{LmotsType, LmsType, MAX_P, N};

#[cfg(feature = "sign")]
pub use sign::{LmsPrivateKey, LmsTree};
