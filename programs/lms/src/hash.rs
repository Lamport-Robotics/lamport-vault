//! The hash function `H` of RFC 8554 (SHA-256) and RFC 9858 (SHA-256/192),
//! and the fixed strings that go into its security-string prefix.
//!
//! Every function takes the output length `n` (32 or 24). A [`Digest`] is
//! always the full 32-byte SHA-256 output; an `n = 24` value is its first 24
//! bytes, and bytes `24..32` are never read: hash inputs take `&digest[..n]`
//! and comparisons take `[..m]`. Leaving the tail alone, rather than zeroing
//! it, keeps the verifier's hot loop free of extra `sol_memset` syscalls.

/// A hash value: the first `n` bytes of a SHA-256 output. Bytes `n..32` are unspecified.
pub type Digest = [u8; 32];

/// `D_PBLC`: hashing all chain ends into the LM-OTS public key `K`.
pub const D_PBLC: [u8; 2] = [0x80, 0x80];
/// `D_MESG`: hashing the message together with the randomizer `C`.
pub const D_MESG: [u8; 2] = [0x81, 0x81];
/// `D_LEAF`: a leaf of the LMS tree.
pub const D_LEAF: [u8; 2] = [0x82, 0x82];
/// `D_INTR`: an interior node of the LMS tree.
pub const D_INTR: [u8; 2] = [0x83, 0x83];

/// `H(parts[0] || parts[1] || ...)`.
///
/// On `target_os = "solana"` this is one `sol_sha256` syscall; everywhere else
/// it is the `sha2` crate. Passing the parts separately avoids assembling the
/// input in a buffer first.
#[inline(always)]
pub fn h(parts: &[&[u8]]) -> Digest {
    solana_sha256_hasher::hashv(parts).to_bytes()
}

/// `H` truncated to `n` bytes: SHA-256 for `n = 32`, SHA-256/192 for `n = 24`
/// (RFC 9858 Section 2: the leftmost 192 bits of SHA-256). Truncation is by
/// the caller reading only `[..n]`; the full digest is returned.
#[inline(always)]
pub fn h_n(parts: &[&[u8]], n: usize) -> Digest {
    debug_assert!(n == 24 || n == 32);
    h(parts)
}

/// Returns `d` with bytes `n..32` zeroed: the canonical form stored in a
/// public key. Not used on the verification path.
#[inline]
pub fn truncated(mut d: Digest, n: usize) -> Digest {
    d[n..].fill(0);
    d
}

/// One Winternitz chain step:
/// `H(I || u32str(q) || u16str(i) || u8str(j) || tmp)`.
#[inline(always)]
pub fn chain_step(i_id: &[u8; 16], q: u32, i: u16, j: u8, tmp: &Digest, n: usize) -> Digest {
    h_n(&[i_id, &q.to_be_bytes(), &i.to_be_bytes(), &[j], &tmp[..n]], n)
}

/// `H(I || u32str(q) || u16str(D_MESG) || C || message)`; `c` is `n` bytes.
#[inline(always)]
pub fn message_hash(i_id: &[u8; 16], q: u32, c: &[u8], message: &[u8], n: usize) -> Digest {
    h_n(&[i_id, &q.to_be_bytes(), &D_MESG, c, message], n)
}

/// `H(I || u32str(r) || u16str(D_LEAF) || ots_pub_hash)`.
#[inline(always)]
pub fn leaf_hash(i_id: &[u8; 16], r: u32, ots_pub_hash: &Digest, m: usize) -> Digest {
    h_n(&[i_id, &r.to_be_bytes(), &D_LEAF, &ots_pub_hash[..m]], m)
}

/// `H(I || u32str(r) || u16str(D_INTR) || left || right)`.
#[inline(always)]
pub fn interior_hash(i_id: &[u8; 16], r: u32, left: &[u8], right: &[u8], m: usize) -> Digest {
    h_n(&[i_id, &r.to_be_bytes(), &D_INTR, &left[..m], &right[..m]], m)
}
