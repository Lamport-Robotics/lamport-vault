//! Account layouts.

use anchor_lang::prelude::*;
use lamport_lms::{LmsType, LMS_PUBLIC_KEY_LEN};

use crate::error::VaultError;

/// Upper bound on a Borsh-encoded [`crate::Action`].
pub const MAX_ACTION_LEN: usize = 256;

/// Length of a `used_keys` entry: `sha256(lms_pubkey)[0..16]`.
pub const KEY_HASH_LEN: usize = 16;

/// The vault. PDA `["vault", vault_id]`, `vault_id = sha256(initial lms_pubkey)`.
///
/// The address never changes: deposits keep working across key rotations.
///
/// Leaf state is a bitmap, not a counter: any unspent leaf may be used in any
/// order, so several signers can own disjoint lanes of one key. The tree
/// height is fixed at creation (the bitmap is sized for it); `Rotate` must keep
/// the parameter set.
#[account]
#[derive(Debug)]
pub struct Vault {
    /// Layout version, 2.
    pub version: u8,
    /// PDA bump.
    pub bump: u8,
    /// `sha256(initial lms_pubkey)`; fixed for the life of the vault.
    pub vault_id: [u8; 32],
    /// Current LMS public key: `u32 lms_type || u32 lmots_type || I[16] || T[1][32]`.
    pub lms_pubkey: [u8; 56],
    /// Leaves spent under the current key (bits set in `used`).
    pub spent: u32,
    /// Key generation: how many times the key was replaced. Part of the signed message.
    pub generation: u32,
    /// Slot of creation.
    pub created_slot: u64,
    /// Used-leaf bitmap of the current key, `2^h / 8` bytes; bit `q` (byte
    /// `q / 8`, bit `q % 8`) set means leaf `q` is spent. Zeroed on `Rotate`.
    pub used: Vec<u8>,
    /// `sha256(lms_pubkey)[0..16]` of every **past** key, oldest first. `Rotate`
    /// refuses any key listed here and the current one; at most
    /// [`crate::MAX_KEY_HISTORY`] entries, after which the vault must `Close`.
    pub used_keys: Vec<[u8; KEY_HASH_LEN]>,
}

impl Vault {
    /// Current layout version.
    pub const VERSION: u8 = 2;
    /// Bytes before the two vectors: discriminator and fixed fields.
    pub const FIXED: usize = 8 + 1 + 1 + 32 + LMS_PUBLIC_KEY_LEN + 4 + 4 + 8;

    /// Bitmap length for a tree of `lms_type`: `2^h / 8` bytes (H5 4, H10 128, H15 4096).
    pub const fn bitmap_len(lms_type: LmsType) -> usize {
        (lms_type.leaf_count() as usize) / 8
    }

    /// Account size including the discriminator, for a tree of `lms_type` with
    /// `history` past keys recorded.
    pub const fn space(lms_type: LmsType, history: usize) -> usize {
        Self::FIXED + (4 + Self::bitmap_len(lms_type)) + (4 + KEY_HASH_LEN * history)
    }

    /// The `used_keys` entry for an LMS public key.
    pub fn key_hash(lms_pubkey: &[u8; LMS_PUBLIC_KEY_LEN]) -> [u8; KEY_HASH_LEN] {
        let full = solana_sha256_hasher::hashv(&[lms_pubkey]).to_bytes();
        let mut out = [0u8; KEY_HASH_LEN];
        out.copy_from_slice(&full[..KEY_HASH_LEN]);
        out
    }

    /// True if `lms_pubkey` is the current key or any past one.
    pub fn has_used_key(&self, lms_pubkey: &[u8; LMS_PUBLIC_KEY_LEN]) -> bool {
        *lms_pubkey == self.lms_pubkey || self.used_keys.contains(&Self::key_hash(lms_pubkey))
    }

    /// Whether leaf `q` is spent. Out-of-range leaves count as spent.
    pub fn leaf_used(&self, q: u32) -> bool {
        match self.used.get((q / 8) as usize) {
            Some(byte) => byte & (1u8 << (q % 8)) != 0,
            None => true,
        }
    }

    /// Marks leaf `q` spent. Errors if it already is or lies outside the bitmap.
    pub fn spend_leaf(&mut self, q: u32) -> Result<()> {
        let byte = self
            .used
            .get_mut((q / 8) as usize)
            .ok_or(VaultError::LeafOutOfRange)?;
        let mask = 1u8 << (q % 8);
        require!(*byte & mask == 0, VaultError::LeafAlreadyUsed);
        *byte |= mask;
        self.spent = self.spent.checked_add(1).ok_or(VaultError::Overflow)?;
        Ok(())
    }
}

/// Staging area for one signature. PDA `["sig", vault, payer, nonce_le_u64]`.
#[account]
#[derive(Debug)]
pub struct SigBuffer {
    /// Layout version, 1.
    pub version: u8,
    /// PDA bump.
    pub bump: u8,
    /// The vault this signature is for.
    pub vault: Pubkey,
    /// The classical key that paid rent; refunded on execute or close.
    pub payer: Pubkey,
    /// Caller-chosen nonce (lets one payer stage several actions).
    pub nonce: u64,
    /// Borsh-encoded [`crate::Action`], fixed at open.
    pub action: Vec<u8>,
    /// Exact signature length for the vault's parameter set.
    pub sig_len: u16,
    /// Bytes written so far; writes must be sequential.
    pub filled: u16,
    /// Signature bytes, `sig_len` long, zero until written.
    pub sig: Vec<u8>,
}

impl SigBuffer {
    /// Current layout version.
    pub const VERSION: u8 = 1;

    /// Account size including the discriminator.
    pub const fn space(action_len: usize, sig_len: usize) -> usize {
        8 + 1 + 1 + 32 + 32 + 8 + (4 + action_len) + 2 + 2 + (4 + sig_len)
    }

    /// Copies `chunk` at `filled` and advances it.
    pub fn append(&mut self, chunk: &[u8]) -> Result<()> {
        let start = self.filled as usize;
        let end = start
            .checked_add(chunk.len())
            .ok_or(VaultError::ChunkOutOfBounds)?;
        require!(end <= self.sig_len as usize, VaultError::ChunkOutOfBounds);
        self.sig[start..end].copy_from_slice(chunk);
        self.filled = end as u16;
        Ok(())
    }
}
