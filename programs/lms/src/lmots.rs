//! LM-OTS one-time signatures (RFC 8554 Section 4): parsing and Algorithm 4b.

use alloc::vec::Vec;

use crate::error::Error;
use crate::hash::{h, h_n, message_hash, Digest, D_PBLC};
use crate::params::{LmotsType, N};

/// A parsed LM-OTS signature, borrowing the caller's bytes.
///
/// Layout: `u32 typecode || C[n] || y[0] || ... || y[p-1]`, each `y[i]` `n` bytes.
#[derive(Clone, Copy, Debug)]
pub struct LmotsSignature<'a> {
    /// Parameter set, equal to the public key's.
    pub lmots_type: LmotsType,
    /// The randomizer `C`, `n` bytes.
    pub c: &'a [u8],
    /// The `p` chain values, `p * n` bytes.
    pub y: &'a [u8],
}

impl<'a> LmotsSignature<'a> {
    /// Chain value `y[i]`, `n` bytes.
    #[inline(always)]
    pub fn y(&self, i: usize) -> &'a [u8] {
        let n = self.lmots_type.n();
        &self.y[i * n..(i + 1) * n]
    }
}

/// Parses an LM-OTS signature (Algorithm 4b, steps 1 and 2).
///
/// `expected` is the typecode from the public key; the signature's own
/// typecode must match it and the length must be exactly `4 + n (p + 1)`.
pub fn parse_lmots_signature(
    bytes: &[u8],
    expected: LmotsType,
) -> Result<LmotsSignature<'_>, Error> {
    if bytes.len() < 4 {
        return Err(Error::SignatureLength);
    }
    let code = u32::from_be_bytes(bytes[0..4].try_into().expect("4 bytes"));
    if code != expected.typecode() {
        return Err(Error::LmotsTypeMismatch);
    }
    if bytes.len() != expected.signature_len() {
        return Err(Error::SignatureLength);
    }
    let n = expected.n();
    Ok(LmotsSignature {
        lmots_type: expected,
        c: &bytes[4..4 + n],
        y: &bytes[4 + n..],
    })
}

/// `coef(S, i, w)`: the `i`-th `w`-bit digit of `S`, read left to right
/// (RFC 8554 Section 3.1.3).
#[inline(always)]
pub fn coef(s: &[u8], i: usize, w: u32) -> u32 {
    let byte = s[(i * w as usize) / 8] as u32;
    let per_byte = 8 / w as usize;
    let shift = 8 - (w * ((i % per_byte) as u32) + w);
    ((1u32 << w) - 1) & (byte >> shift)
}

/// `Cksm(S)` (Algorithm 2): `sum_i ((2^w - 1) - coef(S, i, w)) << ls`, as a
/// 16-bit value.
#[inline(always)]
pub fn checksum(q: &Digest, t: LmotsType) -> u16 {
    let w = t.w();
    let max = t.chain_len();
    let mut sum: u32 = 0;
    for i in 0..t.hash_digits() {
        sum += max - coef(q, i, w);
    }
    ((sum << t.ls()) & 0xffff) as u16
}

/// The `p` Winternitz digits of `Q || Cksm(Q)`.
///
/// Returns a `Vec` because `p` depends on the parameter set; the allocation
/// is a few dozen bytes.
pub fn digits(q: &Digest, t: LmotsType) -> Vec<u8> {
    let n = t.n();
    let mut buf = [0u8; N + 2];
    buf[..n].copy_from_slice(&q[..n]);
    buf[n..n + 2].copy_from_slice(&checksum(q, t).to_be_bytes());
    let w = t.w();
    (0..t.p()).map(|i| coef(&buf, i, w) as u8).collect()
}

/// Algorithm 4b: computes the public key candidate `Kc` from a signature, a
/// message and the identifiers `I`, `q`.
///
/// Returns `Kc`; the caller compares it with the expected `K` (Algorithm 4a)
/// or feeds it into the LMS tree (Algorithm 6a). This function never fails:
/// a wrong signature produces a wrong `Kc`, which the comparison catches.
pub fn lmots_public_key_candidate(
    sig: &LmotsSignature<'_>,
    i_id: &[u8; 16],
    q: u32,
    message: &[u8],
) -> Digest {
    // Monomorphized on n so the hot loop has fixed-size slices, exactly as
    // before RFC 9858 support: a runtime n costs ~10% more compute on chain.
    match sig.lmots_type.n() {
        24 => candidate::<24>(sig, i_id, q, message),
        _ => candidate::<32>(sig, i_id, q, message),
    }
}

fn candidate<const NN: usize>(sig: &LmotsSignature<'_>, i_id: &[u8; 16], q: u32, message: &[u8]) -> Digest {
    let t = sig.lmots_type;
    let qh = message_hash(i_id, q, sig.c, message, NN);
    let a = digits(&qh, t);
    let chain_len = t.chain_len() as u8;
    let qb = q.to_be_bytes();

    // z[i] = chain y[i] from step a[i] up to 2^w - 1.
    let mut z: Vec<Digest> = Vec::with_capacity(t.p());
    for (i, &ai) in a.iter().enumerate() {
        let yi = &sig.y[i * NN..(i + 1) * NN];
        // For n = 32 this is the plain 32-byte array copy the verifier always did; the branch
        // is resolved at compile time.
        let mut tmp: Digest = if NN == N {
            yi.try_into().expect("32-byte slice")
        } else {
            let mut d = [0u8; N];
            d[..NN].copy_from_slice(yi);
            d
        };
        let mut j = ai;
        let ib = (i as u16).to_be_bytes();
        while j < chain_len {
            // chain_step, written out so every slice length is a compile-time constant.
            tmp = h(&[i_id, &qb, &ib, &[j], &tmp[..NN]]);
            j += 1;
        }
        z.push(tmp);
    }

    // Kc = H(I || u32str(q) || u16str(D_PBLC) || z[0] || ... || z[p-1])
    let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + t.p());
    parts.push(i_id);
    parts.push(&qb);
    parts.push(&D_PBLC);
    for zi in &z {
        parts.push(&zi[..NN]);
    }
    h_n(&parts, NN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coef_examples_from_rfc() {
        // S = 0x1234: coef(S, 7, 1) = 0, coef(S, 0, 4) = 1
        let s = [0x12u8, 0x34];
        assert_eq!(coef(&s, 7, 1), 0);
        assert_eq!(coef(&s, 0, 4), 1);
        assert_eq!(coef(&s, 1, 4), 2);
        assert_eq!(coef(&s, 2, 4), 3);
        assert_eq!(coef(&s, 3, 4), 4);
        assert_eq!(coef(&s, 0, 8), 0x12);
        assert_eq!(coef(&s, 1, 8), 0x34);
        assert_eq!(coef(&s, 3, 1), 1);
        assert_eq!(coef(&s, 0, 2), 0);
        assert_eq!(coef(&s, 1, 2), 1);
    }

    #[test]
    fn checksum_bounds_w4() {
        let t = LmotsType::Sha256N32W4;
        // all-zero hash: every digit 0, sum = 64 * 15 = 960, << 4 = 15360
        assert_eq!(checksum(&[0u8; 32], t), 960 << 4);
        // all-0xff hash: every digit 15, sum = 0
        assert_eq!(checksum(&[0xffu8; 32], t), 0);
        let d = digits(&[0u8; 32], t);
        assert_eq!(d.len(), 67);
        // 15360 = 0x3C00 -> digits 3, 12, 0
        assert_eq!(&d[64..], &[3, 12, 0]);
    }

    #[test]
    fn checksum_bounds_n24() {
        // W4: 48 digits of 0 -> sum 48 * 15 = 720, << 4 = 11520 = 0x2D00 -> digits 2, 13, 0
        let t = LmotsType::Sha256N24W4;
        let d = digits(&[0u8; 32], t);
        assert_eq!(d.len(), 51);
        assert_eq!(&d[48..], &[2, 13, 0]);
        // W8: 24 digits of 0 -> sum 24 * 255 = 6120 = 0x17E8, ls 0 -> digits 0x17, 0xE8
        let t = LmotsType::Sha256N24W8;
        let d = digits(&[0u8; 32], t);
        assert_eq!(d.len(), 26);
        assert_eq!(&d[24..], &[0x17, 0xe8]);
    }
}
