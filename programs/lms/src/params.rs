//! Parameter sets: RFC 8554 Table 1 (LM-OTS) and Table 2 (LMS).

use crate::error::Error;

/// Hash output length in bytes (`n` for LM-OTS, `m` for LMS). SHA-256 only.
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
}

impl LmotsType {
    /// Parameter sets this build accepts in public keys and signatures.
    pub const ACCEPTED: &'static [LmotsType] = &[LmotsType::Sha256N32W4];

    /// Looks a typecode up in Table 1 and checks it is in [`Self::ACCEPTED`].
    pub fn from_typecode(code: u32) -> Result<Self, Error> {
        let t = match code {
            1 => LmotsType::Sha256N32W1,
            2 => LmotsType::Sha256N32W2,
            3 => LmotsType::Sha256N32W4,
            4 => LmotsType::Sha256N32W8,
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

    /// Winternitz width `w` in bits.
    pub const fn w(self) -> u32 {
        match self {
            LmotsType::Sha256N32W1 => 1,
            LmotsType::Sha256N32W2 => 2,
            LmotsType::Sha256N32W4 => 4,
            LmotsType::Sha256N32W8 => 8,
        }
    }

    /// Number of chains `p` (Table 1 / Appendix B).
    pub const fn p(self) -> usize {
        match self {
            LmotsType::Sha256N32W1 => 265,
            LmotsType::Sha256N32W2 => 133,
            LmotsType::Sha256N32W4 => 67,
            LmotsType::Sha256N32W8 => 34,
        }
    }

    /// Checksum left shift `ls` (Table 1 / Appendix B).
    pub const fn ls(self) -> u32 {
        match self {
            LmotsType::Sha256N32W1 => 7,
            LmotsType::Sha256N32W2 => 6,
            LmotsType::Sha256N32W4 => 4,
            LmotsType::Sha256N32W8 => 0,
        }
    }

    /// Number of chain steps from a private element to its public end: `2^w - 1`.
    pub const fn chain_len(self) -> u32 {
        (1u32 << self.w()) - 1
    }

    /// Number of `w`-bit digits in the `n`-byte message hash: `8n / w`.
    pub const fn hash_digits(self) -> usize {
        (8 * N) / (self.w() as usize)
    }

    /// LM-OTS signature length: `4 + n (p + 1)`.
    pub const fn signature_len(self) -> usize {
        4 + N * (self.p() + 1)
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
}

impl LmsType {
    /// Parameter sets this build accepts.
    pub const ACCEPTED: &'static [LmsType] = &[
        LmsType::Sha256M32H5,
        LmsType::Sha256M32H10,
        LmsType::Sha256M32H15,
        LmsType::Sha256M32H20,
    ];

    /// Looks a typecode up in Table 2 (H25 is not implemented).
    pub fn from_typecode(code: u32) -> Result<Self, Error> {
        match code {
            5 => Ok(LmsType::Sha256M32H5),
            6 => Ok(LmsType::Sha256M32H10),
            7 => Ok(LmsType::Sha256M32H15),
            8 => Ok(LmsType::Sha256M32H20),
            _ => Err(Error::UnknownLmsType),
        }
    }

    /// The four-byte typecode.
    pub const fn typecode(self) -> u32 {
        self as u32
    }

    /// Tree height `h`.
    pub const fn height(self) -> u32 {
        match self {
            LmsType::Sha256M32H5 => 5,
            LmsType::Sha256M32H10 => 10,
            LmsType::Sha256M32H15 => 15,
            LmsType::Sha256M32H20 => 20,
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
        ] {
            let w = t.w();
            let u = (8 * N as u32).div_ceil(w);
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
    }

    #[test]
    fn only_w4_accepted() {
        assert_eq!(LmotsType::from_typecode(3), Ok(LmotsType::Sha256N32W4));
        for c in [0u32, 1, 2, 4, 5, u32::MAX] {
            assert_eq!(LmotsType::from_typecode(c), Err(Error::UnknownLmotsType));
        }
        for (c, h) in [(5u32, 5u32), (6, 10), (7, 15), (8, 20)] {
            assert_eq!(LmsType::from_typecode(c).unwrap().height(), h);
        }
        for c in [0u32, 4, 9, u32::MAX] {
            assert_eq!(LmsType::from_typecode(c), Err(Error::UnknownLmsType));
        }
    }
}
