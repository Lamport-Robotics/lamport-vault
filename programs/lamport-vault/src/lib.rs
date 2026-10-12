//! # lamport-vault
//!
//! A program-owned account that moves funds only on an LMS (RFC 8554)
//! hash-based signature. See `docs/DESIGN.md` section 2 for the contract this
//! program implements; the comments here point at the step they realise.
//!
//! There is no admin, authority, pause or fee switch anywhere in this program.
//! The classical `payer` only pays rent for the staging buffer and gets it
//! back.

#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{
    self, CloseAccount, Mint, TokenAccount, TransferChecked,
};
use lamport_lms::{parse_lms_signature, verify_parsed, LmsPublicKey, LMS_PUBLIC_KEY_LEN};

pub mod action;
pub mod error;
pub mod state;

pub use action::Action;
pub use error::VaultError;
pub use state::{SigBuffer, Vault, MAX_ACTION_LEN};

declare_id!("B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH");

/// Seed prefix of the `Vault` PDA: `["vault", vault_id]`.
pub const VAULT_SEED: &[u8] = b"vault";
/// Seed prefix of the `SigBuffer` PDA: `["sig", vault, payer, nonce_le]`.
pub const SIG_SEED: &[u8] = b"sig";
/// Domain prefix of every signed message.
pub const MESSAGE_DOMAIN: &[u8] = b"lamport-vault/v1";

// Anchor's IDL generator wants literal array lengths, so the account and
// instruction types below say `[u8; 56]`; this pins that literal to the crate.
const _: () = assert!(LMS_PUBLIC_KEY_LEN == 56);

/// `vault_id = sha256(initial lms_pubkey)`.
pub fn vault_id_for(lms_pubkey: &[u8; LMS_PUBLIC_KEY_LEN]) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[lms_pubkey]).to_bytes()
}

/// `message = sha256("lamport-vault/v1" || vault_pubkey || action_bytes)`.
pub fn signed_message(vault: &Pubkey, action_bytes: &[u8]) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[MESSAGE_DOMAIN, vault.as_ref(), action_bytes]).to_bytes()
}

/// Parses and validates a 56-byte LMS public key for use in a vault.
fn parse_vault_key(bytes: &[u8; LMS_PUBLIC_KEY_LEN]) -> Result<LmsPublicKey> {
    LmsPublicKey::parse(bytes).map_err(|e| match e {
        lamport_lms::Error::UnknownLmsType => error!(VaultError::InvalidLmsType),
        lamport_lms::Error::UnknownLmotsType => error!(VaultError::InvalidLmotsType),
        _ => error!(VaultError::InvalidPublicKey),
    })
}

#[program]
pub mod lamport_vault {
    use super::*;

    /// Creates a vault for `lms_pubkey`. Typecodes must be LMS 5..=8 and
    /// LM-OTS 3. `next_q` starts at 0. Anyone can pay; nobody controls the
    /// vault afterwards except the holder of the LMS private key.
    ///
    /// `vault_id` must equal `sha256(lms_pubkey)`. It is passed explicitly so
    /// the PDA seed is a plain argument that the IDL can describe (Anchor's
    /// IDL generator cannot follow a hash of an argument inside `seeds`).
    pub fn create_vault(ctx: Context<CreateVault>, vault_id: [u8; 32], lms_pubkey: [u8; 56]) -> Result<()> {
        parse_vault_key(&lms_pubkey)?;
        require!(vault_id == vault_id_for(&lms_pubkey), VaultError::VaultIdMismatch);
        let vault = &mut ctx.accounts.vault;
        vault.version = Vault::VERSION;
        vault.bump = ctx.bumps.vault;
        vault.vault_id = vault_id;
        vault.lms_pubkey = lms_pubkey;
        vault.next_q = 0;
        vault.rotations = 0;
        vault.created_slot = Clock::get()?.slot;
        Ok(())
    }

    /// Allocates a staging buffer for one action. `action` is the Borsh
    /// encoding of an [`Action`] (checked to decode here so a typo fails
    /// early), `sig_len` must be the exact signature length for the vault's
    /// current parameter set, and `first_chunk` may carry the first signature
    /// bytes so an H10 signature needs three transactions instead of four
    /// (DESIGN.md section 6). Pass an empty vector to skip it.
    pub fn open_sig_buffer(
        ctx: Context<OpenSigBuffer>,
        nonce: u64,
        action: Vec<u8>,
        sig_len: u16,
        first_chunk: Vec<u8>,
    ) -> Result<()> {
        require!(!action.is_empty() && action.len() <= MAX_ACTION_LEN, VaultError::ActionTooLarge);
        Action::decode(&action)?;
        let pk = parse_vault_key(&ctx.accounts.vault.lms_pubkey)?;
        require!(sig_len as usize == pk.signature_len(), VaultError::SignatureLengthMismatch);

        let buf = &mut ctx.accounts.sig_buffer;
        buf.version = SigBuffer::VERSION;
        buf.bump = ctx.bumps.sig_buffer;
        buf.vault = ctx.accounts.vault.key();
        buf.payer = ctx.accounts.payer.key();
        buf.nonce = nonce;
        buf.action = action;
        buf.sig_len = sig_len;
        buf.filled = 0;
        buf.sig = vec![0u8; sig_len as usize];
        buf.append(&first_chunk)
    }

    /// Appends `chunk` at `offset`, which must equal the bytes written so far.
    pub fn write_sig(ctx: Context<WriteSig>, offset: u16, chunk: Vec<u8>) -> Result<()> {
        let buf = &mut ctx.accounts.sig_buffer;
        require!(offset == buf.filled, VaultError::OffsetMismatch);
        buf.append(&chunk)
    }

    /// Refunds the buffer's rent to its payer. No effect on the vault.
    pub fn close_sig_buffer(_ctx: Context<CloseSigBuffer>) -> Result<()> {
        Ok(())
    }

    /// Verifies the staged signature and performs the action. Anyone may call
    /// it: the signature binds the vault and the exact action, and the leaf
    /// counter makes it single-use. The buffer's rent returns to its payer.
    ///
    /// Remaining accounts, by action:
    /// * `TransferSol`: `[to (writable)]`
    /// * `TransferToken`: `[vault token account (w), destination token account (w), mint, token program]`
    /// * `Rotate`: none
    /// * `Close`: `[to (w)]`, then any number of `[token account (w), token program]` pairs,
    ///   each an empty token account owned by the vault; they are closed to `to`.
    pub fn execute<'info>(ctx: Context<'_, '_, 'info, 'info, Execute<'info>>) -> Result<()> {
        let buf = &ctx.accounts.sig_buffer;
        // 1. buffer complete and bound to this vault (binding also checked by has_one).
        require!(buf.filled == buf.sig_len, VaultError::SignatureIncomplete);

        let vault_key = ctx.accounts.vault.key();
        let vault = &mut ctx.accounts.vault;

        // 2. message
        let message = signed_message(&vault_key, &buf.action);

        // 3. parse: typecodes equal to the vault's, q < 2^h, exact length; then q >= next_q.
        let pk = parse_vault_key(&vault.lms_pubkey)?;
        let sig = parse_lms_signature(&buf.sig, &pk).map_err(|e| {
            msg!("lms parse: {}", e.name());
            match e {
                lamport_lms::Error::LeafOutOfRange => error!(VaultError::LeafOutOfRange),
                lamport_lms::Error::LmsTypeMismatch | lamport_lms::Error::LmotsTypeMismatch => {
                    error!(VaultError::SignatureTypeMismatch)
                }
                _ => error!(VaultError::SignatureMalformed),
            }
        })?;
        require!(sig.q >= vault.next_q, VaultError::LeafAlreadyUsed);

        // 4. verify (Algorithms 4b + 6).
        verify_parsed(&pk, &message, &sig).map_err(|_| error!(VaultError::InvalidSignature))?;

        // 5. burn the leaf before doing anything else.
        let q = sig.q;
        vault.next_q = q.checked_add(1).ok_or(VaultError::LeafOutOfRange)?;

        // 6. decode, expiry, exhaustion rule, perform.
        let action = Action::decode(&buf.action)?;
        let clock = Clock::get()?;
        require!(action.expiry_slot() >= clock.slot, VaultError::ActionExpired);
        if q == pk.lms_type.last_leaf() {
            require!(matches!(action, Action::Rotate { .. }), VaultError::LastLeafReservedForRotate);
        }

        let vault_id = vault.vault_id;
        let bump = vault.bump;
        let signer_seeds: &[&[u8]] = &[VAULT_SEED, &vault_id, &[bump]];
        let remaining = ctx.remaining_accounts;

        match action {
            Action::TransferSol { to, lamports, .. } => {
                let to_ai = remaining.first().ok_or(VaultError::MissingAccount)?;
                require_keys_eq!(to_ai.key(), to, VaultError::WrongDestination);
                require_keys_neq!(to, vault_key, VaultError::SelfTransfer);
                let vault_ai = vault.to_account_info();
                let min = Rent::get()?.minimum_balance(vault_ai.data_len());
                let available = vault_ai.lamports().saturating_sub(min);
                require!(lamports <= available, VaultError::InsufficientFunds);
                vault_ai.sub_lamports(lamports)?;
                to_ai.add_lamports(lamports)?;
            }
            Action::TransferToken { mint, to, amount, .. } => {
                require!(remaining.len() >= 4, VaultError::MissingAccount);
                let from_ai = &remaining[0];
                let to_ai = &remaining[1];
                let mint_ai = &remaining[2];
                let token_program = &remaining[3];
                require!(
                    token_program.key() == anchor_spl::token::ID
                        || token_program.key() == anchor_spl::token_2022::ID,
                    VaultError::InvalidTokenProgram
                );
                require_keys_eq!(mint_ai.key(), mint, VaultError::WrongMint);
                require_keys_eq!(to_ai.key(), to, VaultError::WrongDestination);
                require_keys_eq!(*mint_ai.owner, token_program.key(), VaultError::InvalidTokenProgram);
                let decimals = InterfaceAccount::<Mint>::try_from(mint_ai)?.decimals;
                token_interface::transfer_checked(
                    CpiContext::new_with_signer(
                        token_program.clone(),
                        TransferChecked {
                            from: from_ai.clone(),
                            mint: mint_ai.clone(),
                            to: to_ai.clone(),
                            authority: vault.to_account_info(),
                        },
                        &[signer_seeds],
                    ),
                    amount,
                    decimals,
                )?;
            }
            Action::Rotate { new_lms_pubkey, .. } => {
                parse_vault_key(&new_lms_pubkey)?;
                require!(new_lms_pubkey != vault.lms_pubkey, VaultError::SameKeyRotation);
                vault.lms_pubkey = new_lms_pubkey;
                vault.next_q = 0;
                vault.rotations = vault.rotations.checked_add(1).ok_or(VaultError::Overflow)?;
            }
            Action::Close { to, .. } => {
                let to_ai = remaining.first().ok_or(VaultError::MissingAccount)?;
                require_keys_eq!(to_ai.key(), to, VaultError::WrongDestination);
                require_keys_neq!(to, vault_key, VaultError::SelfTransfer);
                require_keys_neq!(to, ctx.accounts.sig_buffer.key(), VaultError::SelfTransfer);
                let pairs = &remaining[1..];
                require!(pairs.chunks_exact(2).remainder().is_empty(), VaultError::MissingAccount);
                for pair in pairs.chunks_exact(2) {
                    let acc_ai = &pair[0];
                    let token_program = &pair[1];
                    require!(
                        token_program.key() == anchor_spl::token::ID
                            || token_program.key() == anchor_spl::token_2022::ID,
                        VaultError::InvalidTokenProgram
                    );
                    require_keys_eq!(*acc_ai.owner, token_program.key(), VaultError::InvalidTokenProgram);
                    let acc = InterfaceAccount::<TokenAccount>::try_from(acc_ai)?;
                    require_keys_eq!(acc.owner, vault_key, VaultError::InvalidTokenProgram);
                    require!(acc.amount == 0, VaultError::TokenAccountNotEmpty);
                    token_interface::close_account(CpiContext::new_with_signer(
                        token_program.clone(),
                        CloseAccount {
                            account: acc_ai.clone(),
                            destination: to_ai.clone(),
                            authority: vault.to_account_info(),
                        },
                        &[signer_seeds],
                    ))?;
                }
                vault.close(to_ai.clone())?;
            }
        }

        // 7. the buffer is closed to `payer` by the `close = payer` constraint.
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(vault_id: [u8; 32])]
pub struct CreateVault<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = Vault::SPACE,
        seeds = [VAULT_SEED, vault_id.as_ref()],
        bump,
    )]
    pub vault: Account<'info, Vault>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(nonce: u64, action: Vec<u8>, sig_len: u16)]
pub struct OpenSigBuffer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub vault: Account<'info, Vault>,
    #[account(
        init,
        payer = payer,
        space = SigBuffer::space(action.len(), sig_len as usize),
        seeds = [SIG_SEED, vault.key().as_ref(), payer.key().as_ref(), &nonce.to_le_bytes()],
        bump,
    )]
    pub sig_buffer: Account<'info, SigBuffer>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WriteSig<'info> {
    pub payer: Signer<'info>,
    #[account(mut, has_one = payer @ VaultError::WrongPayer)]
    pub sig_buffer: Account<'info, SigBuffer>,
}

#[derive(Accounts)]
pub struct CloseSigBuffer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, close = payer, has_one = payer @ VaultError::WrongPayer)]
    pub sig_buffer: Account<'info, SigBuffer>,
}

#[derive(Accounts)]
pub struct Execute<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(
        mut,
        close = payer,
        has_one = vault @ VaultError::VaultMismatch,
        has_one = payer @ VaultError::WrongPayer,
    )]
    pub sig_buffer: Account<'info, SigBuffer>,
    /// CHECK: receives the buffer's rent; identity enforced by `has_one = payer`.
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
}
