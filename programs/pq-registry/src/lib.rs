//! # pq-registry
//!
//! Lets any Solana address record, today, with its ordinary signature, the
//! hash-based key that should own it later. See `docs/DESIGN.md` section 3.
//!
//! * `commit` is first-write-wins: the `init` constraint fails if a commitment
//!   for `owner` already exists, so a classical key that is broken later cannot
//!   overwrite an earlier commitment.
//! * `rotate_pq` replaces the committed key and needs an LMS signature from
//!   the key currently committed, staged through a buffer exactly like the
//!   vault does. After a rotation `next_q` resets to 0 for the new key.
//!   Rotating to a key that was committed before is the owner's own replay
//!   risk (an old rotation signature would be valid again); the derivation in
//!   `docs/SPEC-DERIVATION.md` never produces the same key twice.
//!
//! No admin, no authority: after `commit` only the post-quantum key can change
//! the record, and nobody can delete it.

#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use lamport_lms::{parse_lms_signature, verify_parsed, LmsPublicKey, LMS_PUBLIC_KEY_LEN};

declare_id!("48J2BtWFjEUbGPYf1yMPBkHxpy4dLo69gK2znQR2q2ad");

/// Seed prefix of the `Commitment` PDA: `["pq", owner]`.
pub const PQ_SEED: &[u8] = b"pq";
/// Seed prefix of the rotation staging buffer: `["pqsig", owner, payer, nonce_le]`.
pub const PQ_SIG_SEED: &[u8] = b"pqsig";
/// Domain prefix of every signed rotation message.
pub const MESSAGE_DOMAIN: &[u8] = b"pq-registry/v1";
/// `scheme` value for an LMS-SHA256 key (56-byte public key).
pub const SCHEME_LMS_SHA256: u8 = 1;

const _: () = assert!(LMS_PUBLIC_KEY_LEN == 56);

/// `message = sha256("pq-registry/v1" || owner || new_pq_pubkey)`.
pub fn signed_message(owner: &Pubkey, new_pq_pubkey: &[u8; 56]) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[MESSAGE_DOMAIN, owner.as_ref(), new_pq_pubkey]).to_bytes()
}

fn parse_key(bytes: &[u8; 56]) -> Result<LmsPublicKey> {
    LmsPublicKey::parse(bytes).map_err(|e| match e {
        lamport_lms::Error::UnknownLmsType => error!(RegistryError::InvalidLmsType),
        lamport_lms::Error::UnknownLmotsType => error!(RegistryError::InvalidLmotsType),
        _ => error!(RegistryError::InvalidPublicKey),
    })
}

#[program]
pub mod pq_registry {
    use super::*;

    /// Records `pq_pubkey` for `owner`. Fails if a commitment already exists.
    pub fn commit(ctx: Context<Commit>, pq_pubkey: [u8; 56]) -> Result<()> {
        parse_key(&pq_pubkey)?;
        let c = &mut ctx.accounts.commitment;
        let slot = Clock::get()?.slot;
        c.version = Commitment::VERSION;
        c.bump = ctx.bumps.commitment;
        c.owner = ctx.accounts.owner.key();
        c.scheme = SCHEME_LMS_SHA256;
        c.pq_pubkey = pq_pubkey;
        c.next_q = 0;
        c.created_slot = slot;
        c.updated_slot = slot;
        Ok(())
    }

    /// Allocates a staging buffer for one rotation to `new_pq_pubkey`.
    /// `sig_len` must be the exact signature length of the committed key's
    /// parameter set. The signature itself arrives through `write_pq_sig`.
    pub fn open_pq_buffer(ctx: Context<OpenPqBuffer>, nonce: u64, new_pq_pubkey: [u8; 56], sig_len: u16) -> Result<()> {
        parse_key(&new_pq_pubkey)?;
        let pk = parse_key(&ctx.accounts.commitment.pq_pubkey)?;
        require!(sig_len as usize == pk.signature_len(), RegistryError::SignatureLengthMismatch);
        let b = &mut ctx.accounts.pq_sig_buffer;
        b.version = PqSigBuffer::VERSION;
        b.bump = ctx.bumps.pq_sig_buffer;
        b.owner = ctx.accounts.commitment.owner;
        b.payer = ctx.accounts.payer.key();
        b.nonce = nonce;
        b.new_pq_pubkey = new_pq_pubkey;
        b.sig_len = sig_len;
        b.filled = 0;
        b.sig = vec![0u8; sig_len as usize];
        Ok(())
    }

    /// Appends `chunk` at `offset == filled`.
    pub fn write_pq_sig(ctx: Context<WritePqSig>, offset: u16, chunk: Vec<u8>) -> Result<()> {
        let b = &mut ctx.accounts.pq_sig_buffer;
        require!(offset == b.filled, RegistryError::OffsetMismatch);
        b.append(&chunk)
    }

    /// Refunds the buffer's rent to its payer.
    pub fn close_pq_buffer(_ctx: Context<ClosePqBuffer>) -> Result<()> {
        Ok(())
    }

    /// Verifies the staged signature with the committed key and replaces it.
    pub fn rotate_pq(ctx: Context<RotatePq>) -> Result<()> {
        let b = &ctx.accounts.pq_sig_buffer;
        require!(b.filled == b.sig_len, RegistryError::SignatureIncomplete);
        let c = &mut ctx.accounts.commitment;
        let message = signed_message(&c.owner, &b.new_pq_pubkey);
        let pk = parse_key(&c.pq_pubkey)?;
        let sig = parse_lms_signature(&b.sig, &pk).map_err(|e| {
            msg!("lms parse: {}", e.name());
            match e {
                lamport_lms::Error::LeafOutOfRange => error!(RegistryError::LeafOutOfRange),
                lamport_lms::Error::LmsTypeMismatch | lamport_lms::Error::LmotsTypeMismatch => {
                    error!(RegistryError::SignatureTypeMismatch)
                }
                _ => error!(RegistryError::SignatureMalformed),
            }
        })?;
        require!(sig.q >= c.next_q, RegistryError::LeafAlreadyUsed);
        verify_parsed(&pk, &message, &sig).map_err(|_| error!(RegistryError::InvalidSignature))?;
        c.next_q = sig.q.checked_add(1).ok_or(RegistryError::LeafOutOfRange)?;

        let new_key = b.new_pq_pubkey;
        parse_key(&new_key)?;
        require!(new_key != c.pq_pubkey, RegistryError::SameKeyRotation);
        c.pq_pubkey = new_key;
        c.next_q = 0;
        c.updated_slot = Clock::get()?.slot;
        Ok(())
    }
}

/// One address's post-quantum commitment. PDA `["pq", owner]`.
#[account]
#[derive(Debug)]
pub struct Commitment {
    /// Layout version, 1.
    pub version: u8,
    /// PDA bump.
    pub bump: u8,
    /// The classical address this commitment is for.
    pub owner: Pubkey,
    /// Key scheme; 1 = LMS-SHA256.
    pub scheme: u8,
    /// The committed public key.
    pub pq_pubkey: [u8; 56],
    /// Next usable leaf of the committed key.
    pub next_q: u32,
    /// Slot of `commit`.
    pub created_slot: u64,
    /// Slot of the last `commit` or `rotate_pq`.
    pub updated_slot: u64,
}

impl Commitment {
    /// Current layout version.
    pub const VERSION: u8 = 1;
    /// Account size including the discriminator.
    pub const SPACE: usize = 8 + 1 + 1 + 32 + 1 + 56 + 4 + 8 + 8;
}

/// Staging buffer for one rotation. PDA `["pqsig", owner, payer, nonce_le]`.
#[account]
#[derive(Debug)]
pub struct PqSigBuffer {
    /// Layout version, 1.
    pub version: u8,
    /// PDA bump.
    pub bump: u8,
    /// The commitment owner this rotation is for.
    pub owner: Pubkey,
    /// Rent payer, refunded on rotate or close.
    pub payer: Pubkey,
    /// Caller-chosen nonce.
    pub nonce: u64,
    /// The key to rotate to.
    pub new_pq_pubkey: [u8; 56],
    /// Exact signature length.
    pub sig_len: u16,
    /// Bytes written so far.
    pub filled: u16,
    /// Signature bytes.
    pub sig: Vec<u8>,
}

impl PqSigBuffer {
    /// Current layout version.
    pub const VERSION: u8 = 1;

    /// Account size including the discriminator.
    pub const fn space(sig_len: usize) -> usize {
        8 + 1 + 1 + 32 + 32 + 8 + 56 + 2 + 2 + (4 + sig_len)
    }

    /// Copies `chunk` at `filled` and advances it.
    pub fn append(&mut self, chunk: &[u8]) -> Result<()> {
        let start = self.filled as usize;
        let end = start.checked_add(chunk.len()).ok_or(RegistryError::ChunkOutOfBounds)?;
        require!(end <= self.sig_len as usize, RegistryError::ChunkOutOfBounds);
        self.sig[start..end].copy_from_slice(chunk);
        self.filled = end as u16;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Commit<'info> {
    /// The address being committed; must sign with its classical key.
    pub owner: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = Commitment::SPACE,
        seeds = [PQ_SEED, owner.key().as_ref()],
        bump,
    )]
    pub commitment: Account<'info, Commitment>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(nonce: u64, new_pq_pubkey: [u8; 56], sig_len: u16)]
pub struct OpenPqBuffer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub commitment: Account<'info, Commitment>,
    #[account(
        init,
        payer = payer,
        space = PqSigBuffer::space(sig_len as usize),
        seeds = [PQ_SIG_SEED, commitment.owner.as_ref(), payer.key().as_ref(), &nonce.to_le_bytes()],
        bump,
    )]
    pub pq_sig_buffer: Account<'info, PqSigBuffer>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WritePqSig<'info> {
    pub payer: Signer<'info>,
    #[account(mut, has_one = payer @ RegistryError::WrongPayer)]
    pub pq_sig_buffer: Account<'info, PqSigBuffer>,
}

#[derive(Accounts)]
pub struct ClosePqBuffer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, close = payer, has_one = payer @ RegistryError::WrongPayer)]
    pub pq_sig_buffer: Account<'info, PqSigBuffer>,
}

#[derive(Accounts)]
pub struct RotatePq<'info> {
    #[account(mut)]
    pub commitment: Account<'info, Commitment>,
    #[account(
        mut,
        close = payer,
        has_one = payer @ RegistryError::WrongPayer,
        constraint = pq_sig_buffer.owner == commitment.owner @ RegistryError::OwnerMismatch,
    )]
    pub pq_sig_buffer: Account<'info, PqSigBuffer>,
    /// CHECK: receives the buffer's rent; identity enforced by `has_one = payer`.
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
}

/// Error codes, numbered from 6000.
#[error_code]
pub enum RegistryError {
    #[msg("LMS typecode must be 5..=8 (H5, H10, H15, H20)")]
    InvalidLmsType,
    #[msg("LM-OTS typecode must be 3 (SHA256_N32_W4)")]
    InvalidLmotsType,
    #[msg("public key is malformed")]
    InvalidPublicKey,
    #[msg("sig_len is not the signature length of the committed key's parameter set")]
    SignatureLengthMismatch,
    #[msg("offset must equal the number of bytes written so far")]
    OffsetMismatch,
    #[msg("chunk would write past sig_len")]
    ChunkOutOfBounds,
    #[msg("signature buffer is not completely written")]
    SignatureIncomplete,
    #[msg("signature typecodes differ from the committed key")]
    SignatureTypeMismatch,
    #[msg("signature is malformed")]
    SignatureMalformed,
    #[msg("leaf index q is outside the tree")]
    LeafOutOfRange,
    #[msg("leaf index q is below next_q: already used")]
    LeafAlreadyUsed,
    #[msg("LMS signature does not verify")]
    InvalidSignature,
    #[msg("rotation to the key already committed")]
    SameKeyRotation,
    #[msg("buffer belongs to another owner")]
    OwnerMismatch,
    #[msg("signer is not the buffer's payer")]
    WrongPayer,
}
