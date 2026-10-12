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
use lamport_lms::{parse_lms_signature, verify_parsed, LmsPublicKey, LmsType, LMS_PUBLIC_KEY_LEN};

pub mod action;
pub mod error;
pub mod state;

pub use action::Action;
pub use error::VaultError;
pub use state::{SigBuffer, Vault, KEY_HASH_LEN, MAX_ACTION_LEN};

declare_id!("B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH");

/// Seed prefix of the `Vault` PDA: `["vault", vault_id]`.
pub const VAULT_SEED: &[u8] = b"vault";
/// Seed prefix of the `SigBuffer` PDA: `["sig", vault, payer, nonce_le]`.
pub const SIG_SEED: &[u8] = b"sig";
/// Version of the signed-message format; `MESSAGE_DOMAIN` ends in it.
pub const MESSAGE_VERSION: u8 = 1;
/// Domain prefix of every signed message.
pub const MESSAGE_DOMAIN: &[u8] = b"lamport-vault/v1";

/// Most past keys a vault remembers. Rotating beyond it fails with
/// `HistoryFull`; the vault must then `Close` and be recreated. Each entry is
/// 16 bytes of account data.
#[cfg(not(feature = "small-history"))]
#[constant]
pub const MAX_KEY_HISTORY: u16 = 128;
/// Test build cap (feature `small-history`), so tests can reach `HistoryFull`.
#[cfg(feature = "small-history")]
#[constant]
pub const MAX_KEY_HISTORY: u16 = 2;

/// LMS parameter sets a vault may use: H5, H10, H15. H20 is parsed by the
/// crate but refused here (its 128 KB bitmap would not fit the account).
pub const ACCEPTED_LMS_TYPES: &[LmsType] = &[LmsType::Sha256M32H5, LmsType::Sha256M32H10, LmsType::Sha256M32H15];

// Anchor's IDL generator wants literal array lengths, so the account and
// instruction types below say `[u8; 56]`; this pins that literal to the crate.
const _: () = assert!(LMS_PUBLIC_KEY_LEN == 56);

/// `vault_id = sha256(initial lms_pubkey)`.
pub fn vault_id_for(lms_pubkey: &[u8; LMS_PUBLIC_KEY_LEN]) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[lms_pubkey]).to_bytes()
}

/// `message = sha256("lamport-vault/v1" || program_id || vault_pubkey || u32le(generation) || action_bytes)`.
///
/// `generation` is the vault's key generation at signing time, so a signature
/// made under one key is meaningless under any later key, even if a later key
/// had the same leaf index free. The program id keeps a message from being
/// valid under another deployment of this code.
pub fn signed_message(vault: &Pubkey, generation: u32, action_bytes: &[u8]) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[
        MESSAGE_DOMAIN,
        ID.as_ref(),
        vault.as_ref(),
        &generation.to_le_bytes(),
        action_bytes,
    ])
    .to_bytes()
}

/// Parses and validates a 56-byte LMS public key for use in a vault.
fn parse_vault_key(bytes: &[u8; LMS_PUBLIC_KEY_LEN]) -> Result<LmsPublicKey> {
    let pk = LmsPublicKey::parse(bytes).map_err(|e| match e {
        lamport_lms::Error::UnknownLmsType => error!(VaultError::InvalidLmsType),
        lamport_lms::Error::UnknownLmotsType => error!(VaultError::InvalidLmotsType),
        _ => error!(VaultError::InvalidPublicKey),
    })?;
    require!(ACCEPTED_LMS_TYPES.contains(&pk.lms_type), VaultError::InvalidLmsType);
    Ok(pk)
}

#[program]
pub mod lamport_vault {
    use super::*;

    /// Creates a vault for `lms_pubkey`. Typecodes must be LMS 5..=7 and
    /// LM-OTS 3. The used-leaf bitmap is sized for the key's height and starts
    /// clear. Anyone can pay; nobody controls the vault afterwards except the
    /// holder of the LMS private key.
    ///
    /// `vault_id` must equal `sha256(lms_pubkey)`. It is passed explicitly so
    /// the PDA seed is a plain argument that the IDL can describe (Anchor's
    /// IDL generator cannot follow a hash of an argument inside `seeds`).
    pub fn create_vault(ctx: Context<CreateVault>, vault_id: [u8; 32], lms_pubkey: [u8; 56]) -> Result<()> {
        let pk = parse_vault_key(&lms_pubkey)?;
        require!(vault_id == vault_id_for(&lms_pubkey), VaultError::VaultIdMismatch);
        let vault = &mut ctx.accounts.vault;
        vault.version = Vault::VERSION;
        vault.bump = ctx.bumps.vault;
        vault.vault_id = vault_id;
        vault.lms_pubkey = lms_pubkey;
        vault.spent = 0;
        vault.generation = 0;
        vault.created_slot = Clock::get()?.slot;
        vault.used = vec![0u8; Vault::bitmap_len(pk.lms_type)];
        vault.used_keys = Vec::new();
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
    /// it: the signature binds the program, the vault, the key generation and
    /// the exact action, and the used-leaf bitmap makes it single-use. The
    /// buffer's rent returns to its payer; on `Rotate` the rent for the
    /// vault's extra `used_keys` entry (16 bytes) is taken out of the buffer
    /// first, so the buffer's payer pays it.
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

        // 2. message, bound to this program, the vault and the key generation.
        let message = signed_message(&vault_key, vault.generation, &buf.action);

        // 3. parse: typecodes equal to the vault's, q < 2^h, exact length; then leaf q unspent.
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
        require!(!vault.leaf_used(sig.q), VaultError::LeafAlreadyUsed);

        // 4. verify (Algorithms 4b + 6).
        verify_parsed(&pk, &message, &sig).map_err(|_| error!(VaultError::InvalidSignature))?;

        // 5. burn the leaf before doing anything else. `last_free` is read first:
        //    the exhaustion rule looks at the free leaves before this one is spent.
        let last_free = pk.lms_type.leaf_count() - vault.spent <= 1;
        vault.spend_leaf(sig.q)?;

        // 6. decode, expiry, exhaustion rule, perform.
        let action = Action::decode(&buf.action)?;
        let clock = Clock::get()?;
        require!(action.expiry_slot() >= clock.slot, VaultError::ActionExpired);
        // Exhaustion rule: when this is the last free leaf it may only Rotate.
        if last_free {
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
                let new_pk = parse_vault_key(&new_lms_pubkey)?;
                // The bitmap is sized for the height at creation: keep the parameter set.
                require!(
                    new_pk.lms_type == pk.lms_type && new_pk.lmots_type == pk.lmots_type,
                    VaultError::RotateTypeMismatch
                );
                // A key that was ever installed has spent leaves; with a clear
                // bitmap they would be reusable. Refuse it for good.
                require!(!vault.has_used_key(&new_lms_pubkey), VaultError::KeyReused);
                require!(vault.used_keys.len() < MAX_KEY_HISTORY as usize, VaultError::HistoryFull);

                // Grow the account by one history entry. The rent delta comes
                // out of the staging buffer, which is closed to its payer at exit.
                let vault_ai = vault.to_account_info();
                let new_len = Vault::space(pk.lms_type, vault.used_keys.len() + 1);
                let rent = Rent::get()?;
                let delta = rent
                    .minimum_balance(new_len)
                    .saturating_sub(rent.minimum_balance(vault_ai.data_len()));
                if delta > 0 {
                    let buf_ai = ctx.accounts.sig_buffer.to_account_info();
                    buf_ai.sub_lamports(delta)?;
                    vault_ai.add_lamports(delta)?;
                }
                vault_ai.resize(new_len)?;

                let old_key = vault.lms_pubkey;
                vault.used_keys.push(Vault::key_hash(&old_key));
                vault.lms_pubkey = new_lms_pubkey;
                vault.used.iter_mut().for_each(|b| *b = 0);
                vault.spent = 0;
                vault.generation = vault.generation.checked_add(1).ok_or(VaultError::Overflow)?;
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
#[instruction(vault_id: [u8; 32], lms_pubkey: [u8; 56])]
pub struct CreateVault<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = Vault::space(parse_vault_key(&lms_pubkey)?.lms_type, 0),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_is_domain_program_vault_generation_le_action() {
        let vault = Pubkey::new_unique();
        let action = [0x03u8; 41];
        let mut concat = Vec::new();
        concat.extend_from_slice(b"lamport-vault/v1");
        concat.extend_from_slice(ID.as_ref());
        concat.extend_from_slice(vault.as_ref());
        concat.extend_from_slice(&[0x02, 0x01, 0x00, 0x00]); // u32le(0x0102)
        concat.extend_from_slice(&action);
        assert_eq!(signed_message(&vault, 0x0102, &action), solana_sha256_hasher::hash(&concat).to_bytes());
        assert!(MESSAGE_DOMAIN.ends_with(format!("/v{MESSAGE_VERSION}").as_bytes()));
    }

    #[test]
    fn message_changes_with_every_input() {
        let vault = Pubkey::new_unique();
        let action = Action::Close { to: Pubkey::new_unique(), expiry_slot: 1 }.encode();
        let base = signed_message(&vault, 0, &action);
        assert_ne!(base, signed_message(&vault, 1, &action), "generation must bind");
        assert_ne!(base, signed_message(&Pubkey::new_unique(), 0, &action), "vault must bind");
        let other = Action::Close { to: Pubkey::new_unique(), expiry_slot: 1 }.encode();
        assert_ne!(base, signed_message(&vault, 0, &other), "action must bind");
        assert_eq!(base, signed_message(&vault, 0, &action), "deterministic");
    }

    fn fresh(lms_type: LmsType) -> Vault {
        let mut key = [7u8; 56];
        key[..4].copy_from_slice(&lms_type.typecode().to_be_bytes());
        key[4..8].copy_from_slice(&3u32.to_be_bytes());
        Vault {
            version: Vault::VERSION,
            bump: 0,
            vault_id: vault_id_for(&key),
            lms_pubkey: key,
            spent: 0,
            generation: 0,
            created_slot: 0,
            used: vec![0u8; Vault::bitmap_len(lms_type)],
            used_keys: Vec::new(),
        }
    }

    #[test]
    fn bitmap_marks_leaves_once_in_any_order() {
        let mut v = fresh(LmsType::Sha256M32H5);
        assert_eq!(v.used.len(), 4);
        for q in [31u32, 0, 9, 1] {
            assert!(!v.leaf_used(q));
            v.spend_leaf(q).unwrap();
            assert!(v.leaf_used(q));
        }
        assert_eq!(v.spent, 4);
        assert_eq!(v.used, [0b0000_0011, 0b0000_0010, 0, 0b1000_0000]);
        assert!(v.spend_leaf(9).is_err(), "second spend of a leaf");
        assert_eq!(v.spent, 4);
        assert!(v.leaf_used(32), "outside the tree counts as spent");
        assert!(v.spend_leaf(32).is_err());
    }

    #[test]
    fn key_history() {
        let mut v = fresh(LmsType::Sha256M32H10);
        let current = v.lms_pubkey;
        assert!(v.has_used_key(&current), "the current key counts as used");
        let next = [8u8; 56];
        assert!(!v.has_used_key(&next));
        v.used_keys.push(Vault::key_hash(&current));
        v.lms_pubkey = next;
        assert!(v.has_used_key(&current), "a past key stays used");
        assert!(v.has_used_key(&next));
        assert_eq!(Vault::key_hash(&next).len(), KEY_HASH_LEN);
        assert_eq!(&Vault::key_hash(&next)[..], &solana_sha256_hasher::hash(&next).to_bytes()[..16]);
    }

    #[test]
    fn sizes_per_height() {
        assert_eq!(Vault::FIXED, 114);
        assert_eq!(Vault::bitmap_len(LmsType::Sha256M32H5), 4);
        assert_eq!(Vault::bitmap_len(LmsType::Sha256M32H10), 128);
        assert_eq!(Vault::bitmap_len(LmsType::Sha256M32H15), 4096);
        assert_eq!(Vault::space(LmsType::Sha256M32H5, 0), 126);
        assert_eq!(Vault::space(LmsType::Sha256M32H10, 0), 250);
        assert_eq!(Vault::space(LmsType::Sha256M32H15, 0), 4218);
        // The biggest vault (H15, full history) is under one realloc step and the 10 KB class.
        assert!(Vault::space(LmsType::Sha256M32H15, 128) <= 10 * 1024);
        assert!(!ACCEPTED_LMS_TYPES.contains(&LmsType::Sha256M32H20));
    }
}
