//! Parameter sets: RFC 8554 Tables 1 and 2 (SHA-256, `n = m = 32`) and the
//! SHA-256/192 rows of RFC 9858 Tables 1 and 2 (`n = m = 24`).
//!
//! SHA-256/192 is SHA-256 with the output truncated to its first 24 bytes
//! (RFC 9858 Section 2), so on Solana it is the same `sol_sha256` syscall.
//! RFC 9858's SHAKE256 rows are not implemented: Solana has no SHAKE syscall.

use crate::error::Error;

/// Largest hash output length in bytes. Buffers are sized for it; a 24-byte
/// parameter set uses the first 24 bytes and keeps the rest zero.
pub const N: usize = 32;

/// Upper bound on `p` among the accepted LM-OTS parameter sets. Sizes the
/// scratch space used by the verifier. Raise it when accepting W1 or W2.
pub const MAX_P: usize = 67;

/// LM-OTS parameter set (RFC 8554 Table 1).
///
/// The enum carries all four SHA-256 rows so that the arithmetic in
/// [`crate::lmots`] can be written once. Which rows a parser accepts is a
/// separate list, [`LmotsType::ACCEPTED`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum LmotsType {
    /// `LMOTS_SHA256_N32_W1`
    Sha256N32W1 = 1,
    /// `LMOTS_SHA256_N32_W2`
    Sha256N32W2 = 2,
    /// `LMOTS_SHA256_N32_W4`
    Sha256N32W4 = 3,
    /// `LMOTS_SHA256_N32_W8`
    Sha256N32W8 = 4,
    /// `LMOTS_SHA256_N24_W1` (RFC 9858)
    Sha256N24W1 = 5,
    /// `LMOTS_SHA256_N24_W2` (RFC 9858)
    Sha256N24W2 = 6,
    /// `LMOTS_SHA256_N24_W4` (RFC 9858)
    Sha256N24W4 = 7,
    /// `LMOTS_SHA256_N24_W8` (RFC 9858)
    Sha256N24W8 = 8,
}

impl LmotsType {
    /// Parameter sets this build accepts in public keys and signatures.
    ///
    /// The two RFC 9858 rows are accepted by the parser; whether a program
    /// accepts them is the program's own decision (its key arrays, account
    /// layouts and compute budget).
    #[cfg(feature = "sha256-192")]
    pub const ACCEPTED: &'static [LmotsType] =
        &[LmotsType::Sha256N32W4, LmotsType::Sha256N24W4, LmotsType::Sha256N24W8];
    /// Parameter sets this build accepts (without the `sha256-192` feature).
    #[cfg(not(feature = "sha256-192"))]
    pub const ACCEPTED: &'static [LmotsType] = &[LmotsType::Sha256N32W4];

    /// Looks a typecode up in Table 1 and checks it is in [`Self::ACCEPTED`].
    pub fn from_typecode(code: u32) -> Result<Self, Error> {
        let t = match code {
            1 => LmotsType::Sha256N32W1,
            2 => LmotsType::Sha256N32W2,
            3 => LmotsType::Sha256N32W4,
            4 => LmotsType::Sha256N32W8,
            #[cfg(feature = "sha256-192")]
            5 => LmotsType::Sha256N24W1,
            #[cfg(feature = "sha256-192")]
            6 => LmotsType::Sha256N24W2,
            #[cfg(feature = "sha256-192")]
            7 => LmotsType::Sha256N24W4,
            #[cfg(feature = "sha256-192")]
            8 => LmotsType::Sha256N24W8,
            _ => return Err(Error::UnknownLmotsType),
        };
        if Self::ACCEPTED.contains(&t) {
            Ok(t)
        } else {
            Err(Error::UnknownLmotsType)
        }
    }

    /// The four-byte typecode.
    pub const fn typecode(self) -> u32 {
        self as u32
    }

    /// Hash output length `n` in bytes: 32, or 24 for the RFC 9858 rows.
    pub const fn n(self) -> usize {
        match self {
            LmotsType::Sha256N32W1 | LmotsType::Sha256N32W2 | LmotsType::Sha256N32W4 | LmotsType::Sha256N32W8 => 32,
            LmotsType::Sha256N24W1 | LmotsType::Sha256N24W2 | LmotsType::Sha256N24W4 | LmotsType::Sha256N24W8 => 24,
        }
    }

    /// Winternitz width `w` in bits.
    pub const fn w(self) -> u32 {
        match self {
            LmotsType::Sha256N32W1 | LmotsType::Sha256N24W1 => 1,
            LmotsType::Sha256N32W2 | LmotsType::Sha256N24W2 => 2,
            LmotsType::Sha256N32W4 | LmotsType::Sha256N24W4 => 4,
            LmotsType::Sha256N32W8 | LmotsType::Sha256N24W8 => 8,
        }
    }

    /// Number of chains `p` (RFC 8554 Table 1 / Appendix B, RFC 9858 Table 1).
    pub const fn p(self) -> usize {
        match self {
            LmotsType::Sha256N32W1 => 265,
            LmotsType::Sha256N32W2 => 133,
            LmotsType::Sha256N32W4 => 67,
            LmotsType::Sha256N32W8 => 34,
            LmotsType::Sha256N24W1 => 200,
            LmotsType::Sha256N24W2 => 101,
            LmotsType::Sha256N24W4 => 51,
            LmotsType::Sha256N24W8 => 26,
        }
    }

    /// Checksum left shift `ls` (RFC 8554 Table 1 / Appendix B, RFC 9858 Table 1).
    pub const fn ls(self) -> u32 {
        match self {
            LmotsType::Sha256N32W1 => 7,
            LmotsType::Sha256N32W2 => 6,
            LmotsType::Sha256N32W4 => 4,
            LmotsType::Sha256N32W8 => 0,
            LmotsType::Sha256N24W1 => 8,
            LmotsType::Sha256N24W2 => 6,
            LmotsType::Sha256N24W4 => 4,
            LmotsType::Sha256N24W8 => 0,
        }
    }

    /// Number of chain steps from a private element to its public end: `2^w - 1`.
    pub const fn chain_len(self) -> u32 {
        (1u32 << self.w()) - 1
    }

    /// Number of `w`-bit digits in the `n`-byte message hash: `8n / w`.
    pub const fn hash_digits(self) -> usize {
        (8 * self.n()) / (self.w() as usize)
    }

    /// LM-OTS signature length: `4 + n (p + 1)`.
    pub const fn signature_len(self) -> usize {
        4 + self.n() * (self.p() + 1)
    }
}

/// LMS parameter set (RFC 8554 Table 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum LmsType {
    /// `LMS_SHA256_M32_H5`, 32 leaves.
    Sha256M32H5 = 5,
    /// `LMS_SHA256_M32_H10`, 1 024 leaves.
    Sha256M32H10 = 6,
    /// `LMS_SHA256_M32_H15`, 32 768 leaves.
    Sha256M32H15 = 7,
    /// `LMS_SHA256_M32_H20`, 1 048 576 leaves.
    Sha256M32H20 = 8,
    /// `LMS_SHA256_M24_H5` (RFC 9858), 32 leaves.
    Sha256M24H5 = 10,
    /// `LMS_SHA256_M24_H10` (RFC 9858), 1 024 leaves.
    Sha256M24H10 = 11,
    /// `LMS_SHA256_M24_H15` (RFC 9858), 32 768 leaves.
    Sha256M24H15 = 12,
    /// `LMS_SHA256_M24_H20` (RFC 9858), 1 048 576 leaves.
    Sha256M24H20 = 13,
}

impl LmsType {
    /// Parameter sets this build accepts.
    #[cfg(feature = "sha256-192")]
    pub const ACCEPTED: &'static [LmsType] = &[
        LmsType::Sha256M32H5,
        LmsType::Sha256M32H10,
        LmsType::Sha256M32H15,
        LmsType::Sha256M32H20,
        LmsType::Sha256M24H5,
        LmsType::Sha256M24H10,
        LmsType::Sha256M24H15,
        LmsType::Sha256M24H20,
    ];
    /// Parameter sets this build accepts (without the `sha256-192` feature).
    #[cfg(not(feature = "sha256-192"))]
    pub const ACCEPTED: &'static [LmsType] = &[
        LmsType::Sha256M32H5,
        LmsType::Sha256M32H10,
        LmsType::Sha256M32H15,
        LmsType::Sha256M32H20,
    ];

    /// Looks a typecode up in RFC 8554 Table 2 or RFC 9858 Table 2 (H25 is
    /// not implemented).
    pub fn from_typecode(code: u32) -> Result<Self, Error> {
        match code {
            5 => Ok(LmsType::Sha256M32H5),
            6 => Ok(LmsType::Sha256M32H10),
            7 => Ok(LmsType::Sha256M32H15),
            8 => Ok(LmsType::Sha256M32H20),
            #[cfg(feature = "sha256-192")]
            10 => Ok(LmsType::Sha256M24H5),
            #[cfg(feature = "sha256-192")]
            11 => Ok(LmsType::Sha256M24H10),
            #[cfg(feature = "sha256-192")]
            12 => Ok(LmsType::Sha256M24H15),
            #[cfg(feature = "sha256-192")]
            13 => Ok(LmsType::Sha256M24H20),
            _ => Err(Error::UnknownLmsType),
        }
    }

    /// Node length `m` in bytes: 32, or 24 for the RFC 9858 rows.
    pub const fn m(self) -> usize {
        match self {
            LmsType::Sha256M32H5 | LmsType::Sha256M32H10 | LmsType::Sha256M32H15 | LmsType::Sha256M32H20 => 32,
            LmsType::Sha256M24H5 | LmsType::Sha256M24H10 | LmsType::Sha256M24H15 | LmsType::Sha256M24H20 => 24,
        }
    }

    /// The four-byte typecode.
    pub const fn typecode(self) -> u32 {
        self as u32
    }

    /// Tree height `h`.
    pub const fn height(self) -> u32 {
        match self {
            LmsType::Sha256M32H5 | LmsType::Sha256M24H5 => 5,
            LmsType::Sha256M32H10 | LmsType::Sha256M24H10 => 10,
            LmsType::Sha256M32H15 | LmsType::Sha256M24H15 => 15,
            LmsType::Sha256M32H20 | LmsType::Sha256M24H20 => 20,
        }
    }

    /// Number of leaves, `2^h`.
    pub const fn leaf_count(self) -> u32 {
        1u32 << self.height()
    }

    /// Index of the last leaf, `2^h - 1`.
    pub const fn last_leaf(self) -> u32 {
        self.leaf_count() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_1_matches_appendix_b() {
        // u = ceil(8n/w); v = ceil((floor(lg((2^w-1)*u)) + 1) / w); ls = 16 - v*w; p = u + v
        for t in [
            LmotsType::Sha256N32W1,
            LmotsType::Sha256N32W2,
            LmotsType::Sha256N32W4,
            LmotsType::Sha256N32W8,
            LmotsType::Sha256N24W1,
            LmotsType::Sha256N24W2,
            LmotsType::Sha256N24W4,
            LmotsType::Sha256N24W8,
        ] {
            let w = t.w();
            let u = (8 * t.n() as u32).div_ceil(w);
            let x = (t.chain_len()) * u;
            let lg = 31 - x.leading_zeros(); // floor(lg(x))
            let v = (lg + 1).div_ceil(w);
            assert_eq!(t.p() as u32, u + v, "{t:?} p");
            assert_eq!(t.ls(), 16 - v * w, "{t:?} ls");
            assert_eq!(t.hash_digits() as u32, u, "{t:?} u");
        }
        assert_eq!(LmotsType::Sha256N32W4.signature_len(), 2180);
        assert_eq!(LmotsType::Sha256N32W1.signature_len(), 8516);
        assert_eq!(LmotsType::Sha256N32W2.signature_len(), 4292);
        assert_eq!(LmotsType::Sha256N32W8.signature_len(), 1124);
        assert_eq!(LmotsType::Sha256N24W4.signature_len(), 1252);
        assert_eq!(LmotsType::Sha256N24W8.signature_len(), 652);
        assert!(LmotsType::ACCEPTED.iter().all(|t| t.p() <= MAX_P));
    }

    #[test]
    #[cfg(not(feature = "sha256-192"))]
    fn only_w4_accepted_without_the_feature() {
        assert_eq!(LmotsType::from_typecode(3), Ok(LmotsType::Sha256N32W4));
        for c in [0u32, 1, 2, 4, 5, 6, 7, 8, 9, u32::MAX] {
            assert_eq!(LmotsType::from_typecode(c), Err(Error::UnknownLmotsType));
        }
        for c in [0u32, 4, 9, 10, 11, 12, 13, 14, u32::MAX] {
            assert_eq!(LmsType::from_typecode(c), Err(Error::UnknownLmsType));
        }
    }

    #[test]
    #[cfg(feature = "sha256-192")]
    fn only_w4_and_rfc9858_w4_w8_accepted() {
        assert_eq!(LmotsType::from_typecode(3), Ok(LmotsType::Sha256N32W4));
        assert_eq!(LmotsType::from_typecode(7), Ok(LmotsType::Sha256N24W4));
        assert_eq!(LmotsType::from_typecode(8), Ok(LmotsType::Sha256N24W8));
        for c in [0u32, 1, 2, 4, 5, 6, 9, u32::MAX] {
            assert_eq!(LmotsType::from_typecode(c), Err(Error::UnknownLmotsType));
        }
        for (c, h) in [(5u32, 5u32), (6, 10), (7, 15), (8, 20)] {
            assert_eq!(LmsType::from_typecode(c).unwrap().height(), h);
        }
        for (c, h) in [(10u32, 5u32), (11, 10), (12, 15), (13, 20)] {
            let t = LmsType::from_typecode(c).unwrap();
            assert_eq!((t.height(), t.m()), (h, 24));
        }
        for c in [0u32, 4, 9, 14, u32::MAX] {
            assert_eq!(LmsType::from_typecode(c), Err(Error::UnknownLmsType));
        }
    }
}
