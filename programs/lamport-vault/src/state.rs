//! Account layouts.

use anchor_lang::prelude::*;
use lamport_lms::LMS_PUBLIC_KEY_LEN;

use crate::error::VaultError;

/// Upper bound on a Borsh-encoded [`crate::Action`].
pub const MAX_ACTION_LEN: usize = 256;

/// The vault. PDA `["vault", vault_id]`, `vault_id = sha256(initial lms_pubkey)`.
///
/// The address never changes: deposits keep working across key rotations.
#[account]
#[derive(Debug)]
pub struct Vault {
    /// Layout version, 1.
    pub version: u8,
    /// PDA bump.
    pub bump: u8,
    /// `sha256(initial lms_pubkey)`; fixed for the life of the vault.
    pub vault_id: [u8; 32],
    /// Current LMS public key: `u32 lms_type || u32 lmots_type || I[16] || T[1][32]`.
    pub lms_pubkey: [u8; 56],
    /// Next usable leaf. Signatures with `q < next_q` are rejected.
    pub next_q: u32,
    /// How many times the key was replaced.
    pub rotations: u32,
    /// Slot of creation.
    pub created_slot: u64,
}

impl Vault {
    /// Current layout version.
    pub const VERSION: u8 = 1;
    /// Account size including the 8-byte discriminator.
    pub const SPACE: usize = 8 + 1 + 1 + 32 + LMS_PUBLIC_KEY_LEN + 4 + 4 + 8;
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
