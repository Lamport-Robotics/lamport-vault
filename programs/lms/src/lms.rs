//! LMS N-time signatures (RFC 8554 Section 5): public key and signature
//! parsing, Algorithm 6 / 6a verification.

use subtle::ConstantTimeEq;

use crate::error::Error;
use crate::hash::{interior_hash, leaf_hash, Digest};
use crate::lmots::{lmots_public_key_candidate, parse_lmots_signature, LmotsSignature};
use alloc::vec::Vec;

use crate::params::{LmotsType, LmsType, N};

/// Length of a serialized SHA-256 (`m = 32`) LMS public key: `4 + 4 + 16 + 32`.
pub const LMS_PUBLIC_KEY_LEN: usize = 56;

/// Length of a serialized public key for `lms_type`: `4 + 4 + 16 + m`
/// (56 for SHA-256, 48 for RFC 9858 SHA-256/192).
pub const fn public_key_len(lms_type: LmsType) -> usize {
    24 + lms_type.m()
}

/// A parsed LMS public key.
///
/// Layout: `u32 lms_type || u32 lmots_type || I[16] || T[1][m]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LmsPublicKey {
    /// Tree parameter set.
    pub lms_type: LmsType,
    /// One-time signature parameter set used at the leaves.
    pub lmots_type: LmotsType,
    /// The 16-byte key pair identifier `I`.
    pub i: [u8; 16],
    /// The Merkle root `T[1]` (`m` bytes, zero-padded to 32).
    pub t1: Digest,
}

impl LmsPublicKey {
    /// Parses the serialized form (Algorithm 6, steps 1 and 2): 56 bytes for
    /// SHA-256 keys, 48 for SHA-256/192 keys. The LMS and LM-OTS parameter
    /// sets must use the same hash length (RFC 9858 Section 5).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 8 {
            return Err(Error::PublicKeyLength);
        }
        let lms_type = LmsType::from_typecode(u32::from_be_bytes(bytes[0..4].try_into().unwrap()))?;
        let lmots_type =
            LmotsType::from_typecode(u32::from_be_bytes(bytes[4..8].try_into().unwrap()))?;
        if bytes.len() != public_key_len(lms_type) {
            return Err(Error::PublicKeyLength);
        }
        if lms_type.m() != lmots_type.n() {
            return Err(Error::HashLengthMismatch);
        }
        let mut i = [0u8; 16];
        i.copy_from_slice(&bytes[8..24]);
        let mut t1 = [0u8; N];
        t1[..lms_type.m()].copy_from_slice(&bytes[24..]);
        Ok(LmsPublicKey {
            lms_type,
            lmots_type,
            i,
            t1,
        })
    }

    /// Serializes a SHA-256 (`m = 32`) key to its 56-byte form.
    ///
    /// # Panics
    /// For a SHA-256/192 key, which is 48 bytes; use [`Self::encode`].
    pub fn to_bytes(&self) -> [u8; LMS_PUBLIC_KEY_LEN] {
        assert_eq!(self.lms_type.m(), 32, "48-byte SHA-256/192 key: use encode()");
        self.encode().try_into().expect("56 bytes")
    }

    /// Serializes any key: `4 + 4 + 16 + m` bytes.
    pub fn encode(&self) -> Vec<u8> {
        let m = self.lms_type.m();
        let mut out = Vec::with_capacity(public_key_len(self.lms_type));
        out.extend_from_slice(&self.lms_type.typecode().to_be_bytes());
        out.extend_from_slice(&self.lmots_type.typecode().to_be_bytes());
        out.extend_from_slice(&self.i);
        out.extend_from_slice(&self.t1[..m]);
        out
    }

    /// Exact signature length for this key's parameter sets.
    pub const fn signature_len(&self) -> usize {
        lms_signature_len(self.lms_type, self.lmots_type)
    }
}

/// Exact LMS signature length: `4 + lmots_sig_len + 4 + m h`.
pub const fn lms_signature_len(lms_type: LmsType, lmots_type: LmotsType) -> usize {
    4 + lmots_type.signature_len() + 4 + lms_type.m() * (lms_type.height() as usize)
}

/// A parsed LMS signature, borrowing the caller's bytes.
///
/// Layout: `u32 q || lmots_signature || u32 lms_type || path[0] || ... || path[h-1]`.
#[derive(Clone, Copy, Debug)]
pub struct LmsSignature<'a> {
    /// Leaf index.
    pub q: u32,
    /// The one-time signature for leaf `q`.
    pub lmots: LmotsSignature<'a>,
    /// Tree parameter set, equal to the public key's.
    pub lms_type: LmsType,
    /// Authentication path, `h * m` bytes, `path[0]` adjacent to the leaf.
    pub path: &'a [u8],
}

impl<'a> LmsSignature<'a> {
    /// `path[i]`, `m` bytes.
    #[inline(always)]
    pub fn path(&self, i: usize) -> &'a [u8] {
        let m = self.lms_type.m();
        &self.path[i * m..(i + 1) * m]
    }
}

/// Reads only the leaf index `q` (first four bytes) without further checks.
///
/// Handy for a program that wants to compare `q` with its stored counter
/// before paying for the full verification. Returns `None` if there are fewer
/// than four bytes.
pub fn peek_q(sig: &[u8]) -> Option<u32> {
    sig.get(0..4).map(|b| u32::from_be_bytes(b.try_into().unwrap()))
}

/// Parses an LMS signature against a public key (Algorithm 6a, steps 1 and 2).
///
/// Checks both typecodes against the key, the exact length, and `q < 2^h`.
pub fn parse_lms_signature<'a>(
    bytes: &'a [u8],
    pk: &LmsPublicKey,
) -> Result<LmsSignature<'a>, Error> {
    if bytes.len() < 8 {
        return Err(Error::SignatureLength);
    }
    let q = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    let ots_code = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    if ots_code != pk.lmots_type.typecode() {
        return Err(Error::LmotsTypeMismatch);
    }
    let ots_len = pk.lmots_type.signature_len();
    if bytes.len() < 4 + ots_len + 4 {
        return Err(Error::SignatureLength);
    }
    let lms_code = u32::from_be_bytes(bytes[4 + ots_len..8 + ots_len].try_into().unwrap());
    if lms_code != pk.lms_type.typecode() {
        return Err(Error::LmsTypeMismatch);
    }
    if bytes.len() != pk.signature_len() {
        return Err(Error::SignatureLength);
    }
    if q >= pk.lms_type.leaf_count() {
        return Err(Error::LeafOutOfRange);
    }
    let lmots = parse_lmots_signature(&bytes[4..4 + ots_len], pk.lmots_type)?;
    Ok(LmsSignature {
        q,
        lmots,
        lms_type: pk.lms_type,
        path: &bytes[8 + ots_len..],
    })
}

/// Algorithm 6a, steps 3 to 5: the candidate root `Tc` for a parsed signature.
/// Only the first `m` bytes are meaningful.
pub fn lms_root_candidate(pk: &LmsPublicKey, message: &[u8], sig: &LmsSignature<'_>) -> Digest {
    match pk.lms_type.m() {
        #[cfg(feature = "sha256-192")]
        24 => root_candidate::<24>(pk, message, sig),
        _ => root_candidate::<32>(pk, message, sig),
    }
}

fn root_candidate<const M: usize>(pk: &LmsPublicKey, message: &[u8], sig: &LmsSignature<'_>) -> Digest {
    let kc = lmots_public_key_candidate(&sig.lmots, &pk.i, sig.q, message);
    let h = pk.lms_type.height() as usize;
    let mut node_num = pk.lms_type.leaf_count() + sig.q;
    let mut tmp = leaf_hash(&pk.i, node_num, &kc, M);
    for i in 0..h {
        let parent = node_num / 2;
        let sibling: &[u8; M] = sig.path[i * M..(i + 1) * M].try_into().expect("m-byte slice");
        tmp = if node_num & 1 == 1 {
            interior_hash(&pk.i, parent, sibling, &tmp, M)
        } else {
            interior_hash(&pk.i, parent, &tmp, sibling, M)
        };
        node_num = parent;
    }
    tmp
}

/// Algorithm 6: verifies `signature` over `message` under `pk`.
///
/// Parses the signature against the key, recomputes the root and compares it
/// with `T[1]` in constant time. Returns `Ok(q)` with the leaf index used.
pub fn lms_verify(pk: &LmsPublicKey, message: &[u8], signature: &[u8]) -> Result<u32, Error> {
    let sig = parse_lms_signature(signature, pk)?;
    verify_parsed(pk, message, &sig)
}

/// Algorithm 6 on an already parsed signature (for callers that inspected `q`
/// and the typecodes first).
pub fn verify_parsed(
    pk: &LmsPublicKey,
    message: &[u8],
    sig: &LmsSignature<'_>,
) -> Result<u32, Error> {
    let tc = lms_root_candidate(pk, message, sig);
    let m = pk.lms_type.m();
    if bool::from(tc[..m].ct_eq(&pk.t1[..m])) {
        Ok(sig.q)
    } else {
        Err(Error::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_lengths_match_design_table() {
        let w4 = LmotsType::Sha256N32W4;
        assert_eq!(lms_signature_len(LmsType::Sha256M32H5, w4), 2348);
        assert_eq!(lms_signature_len(LmsType::Sha256M32H10, w4), 2508);
        assert_eq!(lms_signature_len(LmsType::Sha256M32H15, w4), 2668);
        assert_eq!(lms_signature_len(LmsType::Sha256M32H20, w4), 2828);
    }

    #[test]
    fn public_key_round_trip() {
        let mut bytes = [0u8; 56];
        bytes[3] = 6;
        bytes[7] = 3;
        for (k, b) in bytes[8..].iter_mut().enumerate() {
            *b = k as u8;
        }
        let pk = LmsPublicKey::parse(&bytes).unwrap();
        assert_eq!(pk.lms_type, LmsType::Sha256M32H10);
        assert_eq!(pk.lmots_type, LmotsType::Sha256N32W4);
        assert_eq!(pk.to_bytes(), bytes);
        assert_eq!(pk.signature_len(), 2508);

        assert_eq!(LmsPublicKey::parse(&bytes[..55]), Err(Error::PublicKeyLength));
        let mut bad = bytes;
        bad[3] = 9;
        assert_eq!(LmsPublicKey::parse(&bad), Err(Error::UnknownLmsType));
        let mut bad = bytes;
        bad[7] = 4;
        assert_eq!(LmsPublicKey::parse(&bad), Err(Error::UnknownLmotsType));
        // SHA-256 tree with a SHA-256/192 one-time signature
        #[cfg(feature = "sha256-192")]
        {
            let mut bad = bytes;
            bad[7] = 7;
            assert_eq!(LmsPublicKey::parse(&bad), Err(Error::HashLengthMismatch));
        }
    }

    #[test]
    #[cfg(feature = "sha256-192")]
    fn sha256_192_public_key_round_trip() {
        let mut bytes = [0u8; 48];
        bytes[3] = 11; // LMS_SHA256_M24_H10
        bytes[7] = 7; // LMOTS_SHA256_N24_W4
        for (k, b) in bytes[8..].iter_mut().enumerate() {
            *b = k as u8 + 1;
        }
        let pk = LmsPublicKey::parse(&bytes).unwrap();
        assert_eq!(pk.lms_type, LmsType::Sha256M24H10);
        assert_eq!(pk.encode(), bytes.to_vec());
        assert_eq!(&pk.t1[24..], &[0u8; 8]);
        assert_eq!(pk.signature_len(), 4 + 1252 + 4 + 240);
        assert_eq!(LmsPublicKey::parse(&[&bytes[..], &[0u8; 8]].concat()), Err(Error::PublicKeyLength));
        let mut bad = bytes;
        bad[7] = 3; // SHA-256/192 tree with a SHA-256 one-time signature
        assert_eq!(LmsPublicKey::parse(&bad), Err(Error::HashLengthMismatch));
    }

    #[test]
    #[cfg(feature = "sha256-192")]
    fn rfc9858_signature_lengths() {
        assert_eq!(lms_signature_len(LmsType::Sha256M24H10, LmotsType::Sha256N24W4), 1500);
        assert_eq!(lms_signature_len(LmsType::Sha256M24H10, LmotsType::Sha256N24W8), 900);
        assert_eq!(lms_signature_len(LmsType::Sha256M24H5, LmotsType::Sha256N24W8), 780);
    }
}
