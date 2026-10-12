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
//! Only SHA-256 with 32-byte output (`n = m = 32`) is defined by RFC 8554.
//!
//! ### LM-OTS typecodes (RFC 8554 Table 1)
//!
//! | name                  | typecode | w | p   | ls | signature bytes | `parse` (program) | `parse_any` |
//! |-----------------------|----------|---|-----|----|-----------------|-------------------|-------------|
//! | `LMOTS_SHA256_N32_W1` | 1        | 1 | 265 | 7  | 8516            | no                | yes         |
//! | `LMOTS_SHA256_N32_W2` | 2        | 2 | 133 | 6  | 4292            | no                | yes         |
//! | `LMOTS_SHA256_N32_W4` | 3        | 4 | 67  | 4  | 2180            | **yes**           | yes         |
//! | `LMOTS_SHA256_N32_W8` | 4        | 8 | 34  | 0  | 1124            | no                | yes         |
//!
//! The arithmetic (`coef`, checksum, chain lengths) is written for any `w` in
//! `{1, 2, 4, 8}` and the signer and verifier run all four rows: the RFC 8554
//! Appendix F vectors (W8 and W4) and the Cisco hash-sigs vectors (W1, W2, W4,
//! W8) in `kat/` pass through the same code. Which rows a *parser* admits is a
//! policy chosen by the caller: [`LmsPublicKey::parse`] and
//! [`LmotsType::from_typecode`] use [`LmotsType::ACCEPTED`] (W4 only), which is
//! what the vault program calls and therefore what is accepted on chain; W4's
//! 67 chains of 15 steps are the compute sweet spot on Solana.
//! [`LmsPublicKey::parse_any`] / [`LmotsType::ALL`] admit every row for tooling
//! and tests. Changing the on-chain policy means changing
//! [`LmotsType::ACCEPTED`]; nothing else in the crate depends on it.
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
//! ## Byte layouts
//!
//! ```text
//! LMS public key (56 bytes)
//!   u32 lms_type || u32 lmots_type || I[16] || T[1][32]
//!
//! LM-OTS signature (4 + 32 (p+1) bytes)
//!   u32 lmots_type || C[32] || y[0][32] || ... || y[p-1][32]
//!
//! LMS signature (4 + lmots_sig + 4 + 32 h bytes)
//!   u32 q || lmots_signature || u32 lms_type || path[0][32] || ... || path[h-1][32]
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
//! | `i = 0xfffd, j = 0xff` | deterministic randomizer C (signing only; verifiers never see it; same convention as hash-sigs and RFC 8554 Appendix F test case 2) |
//!
//! [RFC 8554]: https://www.rfc-editor.org/rfc/rfc8554

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
    LmsPublicKey, LmsSignature, LMS_PUBLIC_KEY_LEN,
};
pub use params::{LmotsType, LmsType, MAX_P, N};

#[cfg(feature = "sign")]
pub use sign::{LmsPrivateKey, LmsTree};
