//! The hash function `H` of RFC 8554, SHA-256, and the fixed strings that go
//! into its security-string prefix.

/// Output of `H`, `n = m = 32` bytes.
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

/// One Winternitz chain step:
/// `H(I || u32str(q) || u16str(i) || u8str(j) || tmp)`.
#[inline(always)]
pub fn chain_step(i_id: &[u8; 16], q: u32, i: u16, j: u8, tmp: &Digest) -> Digest {
    h(&[i_id, &q.to_be_bytes(), &i.to_be_bytes(), &[j], tmp])
}

/// `H(I || u32str(q) || u16str(D_MESG) || C || message)`.
#[inline(always)]
pub fn message_hash(i_id: &[u8; 16], q: u32, c: &[u8; 32], message: &[u8]) -> Digest {
    h(&[i_id, &q.to_be_bytes(), &D_MESG, c, message])
}

/// `H(I || u32str(r) || u16str(D_LEAF) || ots_pub_hash)`.
#[inline(always)]
pub fn leaf_hash(i_id: &[u8; 16], r: u32, ots_pub_hash: &Digest) -> Digest {
    h(&[i_id, &r.to_be_bytes(), &D_LEAF, ots_pub_hash])
}

/// `H(I || u32str(r) || u16str(D_INTR) || left || right)`.
#[inline(always)]
pub fn interior_hash(i_id: &[u8; 16], r: u32, left: &Digest, right: &Digest) -> Digest {
    h(&[i_id, &r.to_be_bytes(), &D_INTR, left, right])
}
