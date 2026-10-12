//! Error type shared by parsing and verification.

/// Why a public key or signature was rejected.
///
/// Every variant is a parse or verification failure; none leaks anything about
/// secret material (verification has no secrets).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Error {
    /// The LMS typecode is not one this crate accepts (see [`crate::LmsType`]).
    UnknownLmsType = 1,
    /// The LM-OTS typecode is not one this crate accepts (see [`crate::LmotsType`]).
    UnknownLmotsType = 2,
    /// A public key was not exactly `24 + m` bytes (56 for SHA-256, 48 for SHA-256/192).
    PublicKeyLength = 3,
    /// A signature was shorter or longer than its typecodes require.
    SignatureLength = 4,
    /// The LM-OTS typecode inside the signature differs from the public key's.
    LmotsTypeMismatch = 5,
    /// The LMS typecode inside the signature differs from the public key's.
    LmsTypeMismatch = 6,
    /// `q >= 2^h`: the leaf index is outside the tree.
    LeafOutOfRange = 7,
    /// The recomputed root does not equal `T[1]` in the public key.
    InvalidSignature = 8,
    /// The LMS and LM-OTS parameter sets use different hash lengths (`m != n`).
    HashLengthMismatch = 9,
}

impl Error {
    /// Short stable name, usable in program logs.
    pub const fn name(self) -> &'static str {
        match self {
            Error::UnknownLmsType => "UnknownLmsType",
            Error::UnknownLmotsType => "UnknownLmotsType",
            Error::PublicKeyLength => "PublicKeyLength",
            Error::SignatureLength => "SignatureLength",
            Error::LmotsTypeMismatch => "LmotsTypeMismatch",
            Error::LmsTypeMismatch => "LmsTypeMismatch",
            Error::LeafOutOfRange => "LeafOutOfRange",
            Error::InvalidSignature => "InvalidSignature",
            Error::HashLengthMismatch => "HashLengthMismatch",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
