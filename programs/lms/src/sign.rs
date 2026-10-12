//! Key generation (RFC 8554 Appendix A, Section 5.3) and signing (Algorithm 3,
//! Section 5.4.1). Compiled only with the `sign` feature.
//!
//! The private key is `(lms_type, lmots_type, I, SEED)`. Every LM-OTS private
//! element is derived on demand:
//!
//! ```text
//! x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)
//! ```
//!
//! so no secret state besides `SEED` ever needs storing. The leaf counter lives
//! on-chain (the vault's `next_q`), not here: the caller chooses `q`.
//!
//! The randomizer `C` of Algorithm 3 is derived deterministically unless the
//! caller supplies one:
//!
//! ```text
//! C_q = H(I || u32str(q) || u16str(0xfffd) || u8str(0xff) || SEED)
//! ```
//!
//! `i = 0xfffd` never occurs as a chain index (`i < 265`) so this input is
//! distinct from every other use of `H` in the scheme. Verifiers never look at
//! how `C` was produced; the independent known-answer vectors in `kat/` use a
//! random `C` and verify under this crate just the same.

use alloc::vec::Vec;

use crate::hash::{chain_step, h, interior_hash, leaf_hash, message_hash, Digest, D_PBLC};
use crate::lmots::digits;
use crate::lms::LmsPublicKey;
use crate::params::{LmotsType, LmsType, N};

/// An LMS private key in the Appendix A pseudorandom form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LmsPrivateKey {
    /// Tree parameter set.
    pub lms_type: LmsType,
    /// Leaf one-time signature parameter set.
    pub lmots_type: LmotsType,
    /// Key pair identifier `I`.
    pub i: [u8; 16],
    /// The 32-byte secret seed.
    pub seed: [u8; N],
}

/// All nodes of an LMS Merkle tree, indexed RFC style: `nodes[r]` is `T[r]`
/// for `1 <= r < 2^(h+1)`; `nodes[0]` is unused.
#[derive(Clone, Debug)]
pub struct LmsTree {
    height: u32,
    nodes: Vec<Digest>,
}

impl LmsTree {
    /// Tree height.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// The root `T[1]`.
    pub fn root(&self) -> Digest {
        self.nodes[1]
    }

    /// `T[r]`.
    pub fn node(&self, r: u32) -> Digest {
        self.nodes[r as usize]
    }

    /// Authentication path for leaf `q`: `path[0]` is the leaf's sibling,
    /// `path[h-1]` the sibling of the root's child on the leaf's side.
    pub fn path(&self, q: u32) -> Vec<Digest> {
        let mut node = (1u32 << self.height) + q;
        let mut out = Vec::with_capacity(self.height as usize);
        while node > 1 {
            out.push(self.nodes[(node ^ 1) as usize]);
            node /= 2;
        }
        out
    }
}

impl LmsPrivateKey {
    /// Builds a private key from its parts.
    pub fn new(lms_type: LmsType, lmots_type: LmotsType, i: [u8; 16], seed: [u8; N]) -> Self {
        LmsPrivateKey {
            lms_type,
            lmots_type,
            i,
            seed,
        }
    }

    /// Appendix A: `x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)`.
    pub fn ots_private_element(&self, q: u32, i: u16) -> Digest {
        h(&[&self.i, &q.to_be_bytes(), &i.to_be_bytes(), &[0xff], &self.seed])
    }

    /// Deterministic randomizer `C` for leaf `q` (see the module docs).
    pub fn randomizer(&self, q: u32) -> Digest {
        h(&[
            &self.i,
            &q.to_be_bytes(),
            &0xfffdu16.to_be_bytes(),
            &[0xff],
            &self.seed,
        ])
    }

    /// Algorithm 1: the LM-OTS public key hash `K` of leaf `q`.
    pub fn ots_public_hash(&self, q: u32) -> Digest {
        let t = self.lmots_type;
        let steps = t.chain_len() as u8;
        let mut y: Vec<Digest> = Vec::with_capacity(t.p());
        for i in 0..t.p() {
            let mut tmp = self.ots_private_element(q, i as u16);
            for j in 0..steps {
                tmp = chain_step(&self.i, q, i as u16, j, &tmp);
            }
            y.push(tmp);
        }
        let qb = q.to_be_bytes();
        let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + t.p());
        parts.push(&self.i);
        parts.push(&qb);
        parts.push(&D_PBLC);
        for yi in &y {
            parts.push(yi);
        }
        h(&parts)
    }

    /// Section 5.3: builds every node of the tree. Cost is `2^h` LM-OTS key
    /// generations (about 1 000 hashes each for W4): instant for H5, well
    /// under a second for H10, and roughly a minute for H15 on a laptop.
    pub fn tree(&self) -> LmsTree {
        let height = self.lms_type.height();
        let leaves = 1usize << height;
        let mut nodes = vec![[0u8; N]; 2 * leaves];
        for q in 0..leaves {
            let r = (leaves + q) as u32;
            nodes[r as usize] = leaf_hash(&self.i, r, &self.ots_public_hash(q as u32));
        }
        for r in (1..leaves).rev() {
            nodes[r] = interior_hash(&self.i, r as u32, &nodes[2 * r], &nodes[2 * r + 1]);
        }
        LmsTree { height, nodes }
    }

    /// The public key for an already built tree.
    pub fn public_key_from_tree(&self, tree: &LmsTree) -> LmsPublicKey {
        LmsPublicKey {
            lms_type: self.lms_type,
            lmots_type: self.lmots_type,
            i: self.i,
            t1: tree.root(),
        }
    }

    /// Builds the tree and returns the public key.
    pub fn public_key(&self) -> LmsPublicKey {
        self.public_key_from_tree(&self.tree())
    }

    /// Algorithm 3 with the deterministic randomizer: the LM-OTS signature of
    /// `message` with leaf `q`, `4 + n (p + 1)` bytes.
    pub fn ots_sign(&self, q: u32, message: &[u8]) -> Vec<u8> {
        self.ots_sign_with_randomizer(q, message, &self.randomizer(q))
    }

    /// Algorithm 3 with a caller-supplied randomizer `C`.
    pub fn ots_sign_with_randomizer(&self, q: u32, message: &[u8], c: &Digest) -> Vec<u8> {
        let t = self.lmots_type;
        let qh = message_hash(&self.i, q, c, message);
        let a = digits(&qh, t);
        let mut out = Vec::with_capacity(t.signature_len());
        out.extend_from_slice(&t.typecode().to_be_bytes());
        out.extend_from_slice(c);
        for (i, &ai) in a.iter().enumerate() {
            let mut tmp = self.ots_private_element(q, i as u16);
            for j in 0..ai {
                tmp = chain_step(&self.i, q, i as u16, j, &tmp);
            }
            out.extend_from_slice(&tmp);
        }
        out
    }

    /// Section 5.4.1: the LMS signature of `message` with leaf `q`, using a
    /// prebuilt tree for the authentication path.
    ///
    /// # Panics
    /// If `q >= 2^h`. The caller is responsible for never reusing a leaf; in
    /// Lamport Vault the chain enforces that with `next_q`.
    pub fn sign_with_tree(&self, tree: &LmsTree, q: u32, message: &[u8]) -> Vec<u8> {
        assert!(q < self.lms_type.leaf_count(), "leaf index out of range");
        assert_eq!(tree.height(), self.lms_type.height(), "tree height mismatch");
        let mut out = Vec::with_capacity(self.public_key_from_tree(tree).signature_len());
        out.extend_from_slice(&q.to_be_bytes());
        out.extend_from_slice(&self.ots_sign(q, message));
        out.extend_from_slice(&self.lms_type.typecode().to_be_bytes());
        for node in tree.path(q) {
            out.extend_from_slice(&node);
        }
        out
    }

    /// Builds the tree and signs. Prefer [`Self::sign_with_tree`] when signing
    /// more than once with the same key.
    pub fn sign(&self, q: u32, message: &[u8]) -> Vec<u8> {
        self.sign_with_tree(&self.tree(), q, message)
    }
}
