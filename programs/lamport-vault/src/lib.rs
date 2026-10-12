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
use anchor_lang::error::ErrorCode;
use anchor_spl::associated_token::{self, get_associated_token_address_with_program_id, AssociatedToken, Create as CreateAta};
use anchor_spl::token_interface::{self, CloseAccount, TransferChecked};
use lamport_lms::{parse_lms_signature, verify_parsed, LmsPublicKey, LmsType, LMS_PUBLIC_KEY_LEN};

pub mod action;
pub mod error;
pub mod state;

pub use action::Action;
pub use error::VaultError;
pub use state::{SigBuffer, Tombstone, Vault, KEY_HASH_LEN, MAX_ACTION_LEN};

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
/// `HistoryFull`; the vault must then `Close` and a new one be created with a
/// fresh key. Each entry is 16 bytes of account data.
#[cfg(not(feature = "small-history"))]
#[constant]
pub const MAX_KEY_HISTORY: u16 = 128;
/// Test build cap (feature `small-history`), so tests can reach `HistoryFull`.
#[cfg(feature = "small-history")]
#[constant]
pub const MAX_KEY_HISTORY: u16 = 2;

/// Longest validity window of an action, in slots: `expiry_slot - issued_slot`
/// must not exceed it. 216 000 slots is about one day at 400 ms, so a signature
/// that leaks or is forgotten stops being submittable within a day of signing,
/// whatever expiry the signer wrote.
#[constant]
pub const MAX_VALIDITY_SLOTS: u64 = 216_000;

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

/// What the signature check establishes before any state changes.
#[derive(Debug, Clone, Copy)]
pub struct Verified {
    /// Leaf index the signature spends.
    pub q: u32,
    /// Whether this was the last free leaf before spending it (exhaustion rule:
    /// only `Rotate` or `Close` may spend it).
    pub last_free: bool,
    /// The vault's parsed key.
    pub pk: LmsPublicKey,
}

/// Steps 2–4 of `execute` (DESIGN.md section 2): bind the message to this
/// program, the vault and its key generation; parse the signature against the
/// vault's parameter set; refuse a spent leaf; verify. Pure: nothing changes.
/// Shared by `execute` (signature from the staging buffer) and
/// `execute_direct` (signature from instruction data).
pub fn verify_action_signature(vault: &Vault, vault_key: &Pubkey, action_bytes: &[u8], signature: &[u8]) -> Result<Verified> {
    let message = signed_message(vault_key, vault.generation, action_bytes);
    let pk = parse_vault_key(&vault.lms_pubkey)?;
    let sig = parse_lms_signature(signature, &pk).map_err(|e| match e {
        lamport_lms::Error::LeafOutOfRange => error!(VaultError::LeafOutOfRange),
        lamport_lms::Error::LmsTypeMismatch | lamport_lms::Error::LmotsTypeMismatch => {
            error!(VaultError::SignatureTypeMismatch)
        }
        _ => error!(VaultError::SignatureMalformed),
    })?;
    require!(!vault.leaf_used(sig.q), VaultError::LeafAlreadyUsed);
    verify_parsed(&pk, &message, &sig).map_err(|_| error!(VaultError::InvalidSignature))?;
    // The exhaustion rule looks at the free leaves before this one is spent.
    let last_free = pk.lms_type.leaf_count() - vault.spent <= 1;
    Ok(Verified { q: sig.q, last_free, pk })
}

/// The validity-window rule shared by every action: not issued in the future,
/// not expired, `issued_slot <= expiry_slot <= issued_slot + MAX_VALIDITY_SLOTS`.
pub fn check_validity_window(issued_slot: u64, expiry_slot: u64, slot: u64) -> Result<()> {
    require!(issued_slot <= slot, VaultError::IssuedInFuture);
    require!(expiry_slot >= slot, VaultError::ActionExpired);
    require!(
        expiry_slot >= issued_slot && expiry_slot - issued_slot <= MAX_VALIDITY_SLOTS,
        VaultError::InvalidValidityWindow
    );
    Ok(())
}

/// Step 6 before the action runs: decode, validity window, exhaustion rule. Pure.
pub fn check_action(action_bytes: &[u8], slot: u64, last_free: bool) -> Result<Action> {
    let action = Action::decode(action_bytes)?;
    let (issued_slot, expiry_slot) = action.window();
    check_validity_window(issued_slot, expiry_slot, slot)?;
    // Exhaustion rule: the last free leaf may only Rotate or Close. Transfers
    // are refused so the vault always keeps a way out: a fresh key, or, when
    // the key history is full and Rotate would fail, the exit.
    if last_free {
        require!(
            matches!(action, Action::Rotate { .. } | Action::Close { .. }),
            VaultError::LastLeafReservedForRotate
        );
    }
    Ok(action)
}

/// Where the rent for a `Rotate`'s extra 16 bytes comes from.
enum RentSource<'a, 'info> {
    /// The staging buffer (program-owned, debited directly; closed to its payer at exit).
    Buffer(&'a AccountInfo<'info>),
    /// The signing payer of `execute_direct`, via a System Program transfer.
    Payer { payer: &'a AccountInfo<'info>, system_program: &'a AccountInfo<'info> },
}

/// Creates `account`, a PDA of this program signed with `seeds`, with `space`
/// bytes of zeroed data, rent paid by `payer`: `create_account` when the
/// address holds no lamports, otherwise a top-up to the rent-exempt minimum,
/// `allocate` and `assign` (the two paths Anchor's `init` takes, so a deposit
/// made before the vault existed is kept). An address that already holds data
/// makes the system program's `allocate` fail with `AccountAlreadyInUse`.
fn create_pda_account<'info>(
    payer: &AccountInfo<'info>,
    account: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
    space: usize,
    seeds: &[&[u8]],
) -> Result<()> {
    use anchor_lang::system_program::{allocate, assign, create_account, transfer, Allocate, Assign, CreateAccount, Transfer};
    let rent = Rent::get()?.minimum_balance(space);
    let current = account.lamports();
    let signer: &[&[&[u8]]] = &[seeds];
    if current == 0 {
        let cpi = CpiContext::new_with_signer(system_program.clone(), CreateAccount { from: payer.clone(), to: account.clone() }, signer);
        return create_account(cpi, rent, space as u64, &ID);
    }
    let top_up = rent.saturating_sub(current);
    if top_up > 0 {
        transfer(CpiContext::new(system_program.clone(), Transfer { from: payer.clone(), to: account.clone() }), top_up)?;
    }
    allocate(
        CpiContext::new_with_signer(system_program.clone(), Allocate { account_to_allocate: account.clone() }, signer),
        space as u64,
    )?;
    assign(CpiContext::new_with_signer(system_program.clone(), Assign { account_to_assign: account.clone() }, signer), &ID)
}

/// Serializes `value` (discriminator first) over the start of `account`'s data.
fn write_account<T: AccountSerialize>(account: &AccountInfo, value: &T) -> Result<()> {
    let mut data = account.try_borrow_mut_data()?;
    let mut dst: &mut [u8] = &mut data;
    value.try_serialize(&mut dst)
}

fn is_token_program(key: &Pubkey) -> bool {
    *key == anchor_spl::token::ID || *key == anchor_spl::token_2022::ID
}

// Token and Token-2022 share their base layouts (`spl_token::state`): a Mint is
// 82 bytes with `decimals` at 44 and `is_initialized` at 45; an Account is 165
// bytes with `owner` at 32..64, `amount` at 64..72 and `state` at 108.
// Token-2022 appends an account-type byte at 165 (1 = Mint, 2 = Account) before
// any extensions. Reading the fields directly keeps the extension-parsing code
// of `InterfaceAccount` out of the binary; the token program re-validates both
// accounts in the CPI that follows.
const MINT_LEN: usize = 82;
const TOKEN_ACCOUNT_LEN: usize = 165;

/// `decimals` of an initialized Token / Token-2022 mint.
fn mint_decimals(ai: &AccountInfo) -> Result<u8> {
    let data = ai.try_borrow_data()?;
    let shape_ok = data.len() == MINT_LEN || (data.len() > TOKEN_ACCOUNT_LEN && data[TOKEN_ACCOUNT_LEN] == 1);
    require!(shape_ok && data[45] == 1, ErrorCode::AccountDidNotDeserialize);
    Ok(data[44])
}

/// `(mint, owner, amount)` of an initialized Token / Token-2022 token account
/// (`mint` at 0..32).
fn token_account_fields(ai: &AccountInfo) -> Result<(Pubkey, Pubkey, u64)> {
    let data = ai.try_borrow_data()?;
    let shape_ok = data.len() == TOKEN_ACCOUNT_LEN || (data.len() > TOKEN_ACCOUNT_LEN && data[TOKEN_ACCOUNT_LEN] == 2);
    require!(shape_ok && data[108] != 0, ErrorCode::AccountDidNotDeserialize);
    let mint = Pubkey::new_from_array(data[..32].try_into().unwrap());
    let owner = Pubkey::new_from_array(data[32..64].try_into().unwrap());
    let amount = u64::from_le_bytes(data[64..72].try_into().unwrap());
    Ok((mint, owner, amount))
}

/// Verifies, burns the leaf, checks the action and performs it. Both entry
/// points end here; they differ only in where the signature and the Rotate
/// rent come from.
fn verify_and_act<'info>(
    vault: &mut Account<'info, Vault>,
    action_bytes: &[u8],
    signature: &[u8],
    rent_source: RentSource<'_, 'info>,
    remaining: &'info [AccountInfo<'info>],
) -> Result<()> {
    let vault_key = vault.key();
    let verified = verify_action_signature(vault, &vault_key, action_bytes, signature)?;
    // 5. burn the leaf before doing anything else.
    vault.spend_leaf(verified.q)?;
    // 6. decode, validity window, exhaustion rule, perform.
    let slot = Clock::get()?.slot;
    let action = check_action(action_bytes, slot, verified.last_free)?;
    let pk = verified.pk;

    let vault_id = vault.vault_id;
    let bump = vault.bump;
    let signer_seeds: &[&[u8]] = &[VAULT_SEED, &vault_id, &[bump]];

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
            require!(is_token_program(token_program.key), VaultError::InvalidTokenProgram);
            require_keys_eq!(mint_ai.key(), mint, VaultError::WrongMint);
            require_keys_eq!(to_ai.key(), to, VaultError::WrongDestination);
            require_keys_eq!(*mint_ai.owner, token_program.key(), VaultError::InvalidTokenProgram);
            let decimals = mint_decimals(mint_ai)?;
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

            // Grow the account by one history entry. The rent delta comes out
            // of the staging buffer (closed to its payer at exit) or, with no
            // buffer, straight from the signing payer.
            let vault_ai = vault.to_account_info();
            let new_len = Vault::space(pk.lms_type, vault.used_keys.len() + 1);
            let rent = Rent::get()?;
            let delta = rent
                .minimum_balance(new_len)
                .saturating_sub(rent.minimum_balance(vault_ai.data_len()));
            if delta > 0 {
                match rent_source {
                    RentSource::Buffer(buf_ai) => {
                        buf_ai.sub_lamports(delta)?;
                        vault_ai.add_lamports(delta)?;
                    }
                    RentSource::Payer { payer, system_program } => {
                        anchor_lang::system_program::transfer(
                            CpiContext::new(
                                system_program.clone(),
                                anchor_lang::system_program::Transfer { from: payer.clone(), to: vault_ai.clone() },
                            ),
                            delta,
                        )?;
                    }
                }
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
            if let RentSource::Buffer(buf_ai) = rent_source {
                require_keys_neq!(to, buf_ai.key(), VaultError::SelfTransfer);
            }
            let pairs = &remaining[1..];
            require!(pairs.chunks_exact(2).remainder().is_empty(), VaultError::MissingAccount);
            for pair in pairs.chunks_exact(2) {
                let acc_ai = &pair[0];
                let token_program = &pair[1];
                require!(is_token_program(token_program.key), VaultError::InvalidTokenProgram);
                require_keys_eq!(*acc_ai.owner, token_program.key(), VaultError::InvalidTokenProgram);
                let (_, owner, amount) = token_account_fields(acc_ai)?;
                require_keys_eq!(owner, vault_key, VaultError::NotVaultTokenAccount);
                require!(amount == 0, VaultError::TokenAccountNotEmpty);
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
            // The address stays occupied by a `Tombstone` holding exactly its
            // rent-exempt minimum (DESIGN.md section 2, "Close"); `create_vault`
            // refuses it, so no unexpired pre-close signature can ever verify
            // against a recreated vault. Everything else goes to `to`, which the
            // tombstone records as `heir`: a token account the owner did not
            // pass in here is recoverable later with `sweep_closed`, to `to` only.
            let vault_ai = vault.to_account_info();
            let keep = Rent::get()?.minimum_balance(Tombstone::SPACE);
            let payout = vault_ai.lamports().checked_sub(keep).ok_or(VaultError::InsufficientFunds)?;
            vault_ai.sub_lamports(payout)?;
            to_ai.add_lamports(payout)?;
            vault_ai.resize(Tombstone::SPACE)?;
            let tombstone = Tombstone { version: Tombstone::VERSION, vault_id, closed_slot: slot, heir: to };
            write_account(&vault_ai, &tombstone)?;
            // Anchor writes `vault` back at exit; with this version byte its
            // serializer writes nothing (see `AccountSerialize for Vault`).
            vault.version = Tombstone::VERSION;
        }
    }
    Ok(())
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
    ///
    /// The account is created here rather than by Anchor's `init` so that a
    /// closed vault's `Tombstone` at the address is reported as `VaultClosed`
    /// before any system program call; a live vault at the address still fails
    /// in the system program (`AccountAlreadyInUse`).
    pub fn create_vault(ctx: Context<CreateVault>, vault_id: [u8; 32], lms_pubkey: [u8; 56]) -> Result<()> {
        let pk = parse_vault_key(&lms_pubkey)?;
        require!(vault_id == vault_id_for(&lms_pubkey), VaultError::VaultIdMismatch);
        let vault_ai = ctx.accounts.vault.to_account_info();
        require!(!Tombstone::is_at(&vault_ai), VaultError::VaultClosed);
        let bump = ctx.bumps.vault;
        create_pda_account(
            &ctx.accounts.payer.to_account_info(),
            &vault_ai,
            &ctx.accounts.system_program.to_account_info(),
            Vault::space(pk.lms_type, 0),
            &[VAULT_SEED, &vault_id, &[bump]],
        )?;
        let vault = Vault {
            version: Vault::VERSION,
            bump,
            vault_id,
            lms_pubkey,
            spent: 0,
            generation: 0,
            created_slot: Clock::get()?.slot,
            used: vec![0u8; Vault::bitmap_len(pk.lms_type)],
            used_keys: Vec::new(),
        };
        write_account(&vault_ai, &vault)
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
    ///   The vault itself becomes a `Tombstone` naming `to` as heir (its address is
    ///   never reusable); a token account not passed in is swept to `to` later by `sweep_closed`.
    ///
    /// On a closed vault (a `Tombstone` at the address) every instruction that
    /// reads the vault fails with `VaultClosed`.
    pub fn execute<'info>(ctx: Context<'_, '_, 'info, 'info, Execute<'info>>) -> Result<()> {
        let buf = &ctx.accounts.sig_buffer;
        // 1. buffer complete and bound to this vault (binding also checked by has_one).
        require!(buf.filled == buf.sig_len, VaultError::SignatureIncomplete);
        let buf_ai = buf.to_account_info();
        verify_and_act(&mut ctx.accounts.vault, &buf.action, &buf.sig, RentSource::Buffer(&buf_ai), ctx.remaining_accounts)
        // 7. the buffer is closed to `payer` by the `close = payer` constraint.
    }

    /// `execute` without a staging buffer: the action and the whole LMS
    /// signature arrive in the instruction data, so one transaction does it
    /// all. Needs a transaction format that carries 2.4–2.7 KB of data (v1,
    /// SIMD-0385/0296). Same checks, same remaining accounts as `execute`;
    /// `payer` signs and, on `Rotate`, pays the 16-byte rent delta itself.
    pub fn execute_direct<'info>(
        ctx: Context<'_, '_, 'info, 'info, ExecuteDirect<'info>>,
        action: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<()> {
        require!(!action.is_empty() && action.len() <= MAX_ACTION_LEN, VaultError::ActionTooLarge);
        let payer = ctx.accounts.payer.to_account_info();
        let system_program = ctx.accounts.system_program.to_account_info();
        verify_and_act(
            &mut ctx.accounts.vault,
            &action,
            &signature,
            RentSource::Payer { payer: &payer, system_program: &system_program },
            ctx.remaining_accounts,
        )
    }

    /// Recovers a token balance a closed vault still owns. `Close` cannot
    /// enumerate the vault's token accounts, so one that was not passed to it
    /// stays owned by the PDA; this moves its whole balance to the heir's
    /// associated token account (created here if missing, rent paid by `payer`)
    /// and closes it, its rent to the heir. The heir is the `to` the `Close`
    /// was signed for, read from the `Tombstone`: anyone may call this, and
    /// funds can only ever go there. Token and Token-2022, any mint.
    pub fn sweep_closed(ctx: Context<SweepClosed>) -> Result<()> {
        let tomb = &ctx.accounts.tombstone;
        let heir = &ctx.accounts.heir;
        let token_program = &ctx.accounts.token_program;
        let mint_ai = &ctx.accounts.mint;
        let acc_ai = &ctx.accounts.vault_token_account;
        let heir_ata = &ctx.accounts.heir_token_account;

        require_keys_eq!(heir.key(), tomb.heir, VaultError::WrongHeir);
        require!(is_token_program(token_program.key), VaultError::InvalidTokenProgram);
        require_keys_eq!(*mint_ai.owner, token_program.key(), VaultError::InvalidTokenProgram);
        require_keys_eq!(*acc_ai.owner, token_program.key(), VaultError::InvalidTokenProgram);
        let (mint, owner, amount) = token_account_fields(acc_ai)?;
        require_keys_eq!(owner, tomb.key(), VaultError::NotVaultTokenAccount);
        require_keys_eq!(mint, mint_ai.key(), VaultError::WrongMint);
        let expected = get_associated_token_address_with_program_id(&tomb.heir, &mint, token_program.key);
        require_keys_eq!(heir_ata.key(), expected, VaultError::NotHeirTokenAccount);

        // The heir's ATA, if it does not exist yet. The ATA program checks the
        // address again and leaves an existing account alone.
        associated_token::create_idempotent(CpiContext::new(
            ctx.accounts.associated_token_program.to_account_info(),
            CreateAta {
                payer: ctx.accounts.payer.to_account_info(),
                associated_token: heir_ata.to_account_info(),
                authority: heir.to_account_info(),
                mint: mint_ai.to_account_info(),
                system_program: ctx.accounts.system_program.to_account_info(),
                token_program: token_program.to_account_info(),
            },
        ))?;

        let signer_seeds: &[&[u8]] = &[VAULT_SEED, &tomb.vault_id, &[ctx.bumps.tombstone]];
        if amount > 0 {
            let decimals = mint_decimals(mint_ai)?;
            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    token_program.to_account_info(),
                    TransferChecked {
                        from: acc_ai.to_account_info(),
                        mint: mint_ai.to_account_info(),
                        to: heir_ata.to_account_info(),
                        authority: tomb.to_account_info(),
                    },
                    &[signer_seeds],
                ),
                amount,
                decimals,
            )?;
        }
        token_interface::close_account(CpiContext::new_with_signer(
            token_program.to_account_info(),
            CloseAccount {
                account: acc_ai.to_account_info(),
                destination: heir.to_account_info(),
                authority: tomb.to_account_info(),
            },
            &[signer_seeds],
        ))
    }
}

#[derive(Accounts)]
#[instruction(vault_id: [u8; 32], lms_pubkey: [u8; 56])]
pub struct CreateVault<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// The vault PDA, created and written by the handler rather than by `init`
    /// so a `Tombstone` at the address is refused with `VaultClosed` before any
    /// system program call (see `create_vault`).
    /// CHECK: seeds verified here; the handler checks and initialises the data.
    #[account(mut, seeds = [VAULT_SEED, vault_id.as_ref()], bump)]
    pub vault: UncheckedAccount<'info>,
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

#[derive(Accounts)]
pub struct ExecuteDirect<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Pays the transaction and, on `Rotate`, the vault's 16-byte rent delta.
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// Accounts of `sweep_closed`. The token accounts are deliberately unchecked
/// here and validated in the handler (owner program, owner, mint, ATA address),
/// which keeps Token-2022 extension parsing out of the binary; the token and
/// ATA programs re-validate everything in the CPIs.
#[derive(Accounts)]
pub struct SweepClosed<'info> {
    /// Pays for the heir's associated token account when it has to be created.
    #[account(mut)]
    pub payer: Signer<'info>,
    /// The closed vault: a `Tombstone` at the vault PDA (a live vault fails `VaultNotClosed`).
    #[account(seeds = [VAULT_SEED, tombstone.vault_id.as_ref()], bump)]
    pub tombstone: Account<'info, Tombstone>,
    /// CHECK: must equal `tombstone.heir`; receives the token account's rent.
    #[account(mut)]
    pub heir: UncheckedAccount<'info>,
    /// CHECK: the heir's associated token account for `mint` under `token_program`; created if missing.
    #[account(mut)]
    pub heir_token_account: UncheckedAccount<'info>,
    /// CHECK: a token account owned by the closed vault's PDA, for `mint`; emptied and closed.
    #[account(mut)]
    pub vault_token_account: UncheckedAccount<'info>,
    /// CHECK: the mint, owned by `token_program`.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: Token or Token-2022.
    pub token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_is_domain_program_vault_generation_le_action() {
        let vault = Pubkey::new_unique();
        let action = [0x03u8; 49];
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
        let action = Action::Close { to: Pubkey::new_unique(), issued_slot: 0, expiry_slot: 1 }.encode();
        let base = signed_message(&vault, 0, &action);
        assert_ne!(base, signed_message(&vault, 1, &action), "generation must bind");
        assert_ne!(base, signed_message(&Pubkey::new_unique(), 0, &action), "vault must bind");
        let other = Action::Close { to: Pubkey::new_unique(), issued_slot: 0, expiry_slot: 1 }.encode();
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

    // ---- shared verify / act path (what `execute` and `execute_direct` both run) ----

    use lamport_lms::{LmotsType, LmsPrivateKey};

    fn error_code(e: anchor_lang::error::Error) -> u32 {
        match e {
            anchor_lang::error::Error::AnchorError(a) => a.error_code_number,
            anchor_lang::error::Error::ProgramError(p) => match p.program_error {
                anchor_lang::solana_program::program_error::ProgramError::Custom(c) => c,
                _ => u32::MAX,
            },
        }
    }

    fn code<T: core::fmt::Debug>(r: Result<T>) -> u32 {
        error_code(r.expect_err("expected an error"))
    }

    const fn vault_err(e: VaultError) -> u32 {
        e as u32 + anchor_lang::error::ERROR_CODE_OFFSET
    }

    fn h5_key(seed_byte: u8) -> LmsPrivateKey {
        LmsPrivateKey::new(LmsType::Sha256M32H5, LmotsType::Sha256N32W4, [seed_byte; 16], [seed_byte; 32])
    }

    fn vault_for(key: &LmsPrivateKey) -> Vault {
        let pk = key.public_key().to_bytes();
        Vault {
            version: Vault::VERSION,
            bump: 0,
            vault_id: vault_id_for(&pk),
            lms_pubkey: pk,
            spent: 0,
            generation: 0,
            created_slot: 0,
            used: vec![0u8; Vault::bitmap_len(key.lms_type)],
            used_keys: Vec::new(),
        }
    }

    fn transfer_action(expiry_slot: u64) -> Vec<u8> {
        Action::TransferSol { to: Pubkey::new_unique(), lamports: 1, issued_slot: 0, expiry_slot }.encode()
    }

    #[test]
    fn verify_accepts_a_signature_over_the_bound_message_and_reports_q() {
        let key = h5_key(1);
        let vault = vault_for(&key);
        let vault_key = Pubkey::new_unique();
        let action = transfer_action(10);
        let tree = key.tree();
        for q in [0u32, 7, 31] {
            let sig = key.sign_with_tree(&tree, q, &signed_message(&vault_key, 0, &action));
            let v = verify_action_signature(&vault, &vault_key, &action, &sig).unwrap();
            assert_eq!(v.q, q);
            assert!(!v.last_free);
            assert_eq!(v.pk.lms_type, LmsType::Sha256M32H5);
        }
    }

    #[test]
    fn verify_binds_vault_generation_and_action() {
        let key = h5_key(2);
        let mut vault = vault_for(&key);
        let vault_key = Pubkey::new_unique();
        let action = transfer_action(10);
        let sig = key.sign(3, &signed_message(&vault_key, 0, &action));
        // Another vault, a later generation, or a different action: the message differs.
        assert_eq!(code(verify_action_signature(&vault, &Pubkey::new_unique(), &action, &sig)), vault_err(VaultError::InvalidSignature));
        vault.generation = 1;
        assert_eq!(code(verify_action_signature(&vault, &vault_key, &action, &sig)), vault_err(VaultError::InvalidSignature));
        vault.generation = 0;
        assert_eq!(code(verify_action_signature(&vault, &vault_key, &transfer_action(11), &sig)), vault_err(VaultError::InvalidSignature));
        // One flipped byte anywhere in the signature body.
        let mut bad = sig.clone();
        bad[100] ^= 1;
        assert_eq!(code(verify_action_signature(&vault, &vault_key, &action, &bad)), vault_err(VaultError::InvalidSignature));
        // Still fine untouched.
        assert_eq!(verify_action_signature(&vault, &vault_key, &action, &sig).unwrap().q, 3);
    }

    #[test]
    fn verify_refuses_spent_leaf_malformed_and_foreign_signatures() {
        let key = h5_key(3);
        let mut vault = vault_for(&key);
        let vault_key = Pubkey::new_unique();
        let action = transfer_action(10);
        let sig = key.sign(5, &signed_message(&vault_key, 0, &action));
        vault.spend_leaf(5).unwrap();
        assert_eq!(code(verify_action_signature(&vault, &vault_key, &action, &sig)), vault_err(VaultError::LeafAlreadyUsed));
        let mut fresh = vault_for(&key);
        assert_eq!(code(verify_action_signature(&fresh, &vault_key, &action, &sig[..sig.len() - 1])), vault_err(VaultError::SignatureMalformed));
        assert_eq!(code(verify_action_signature(&fresh, &vault_key, &action, &[])), vault_err(VaultError::SignatureMalformed));
        // q beyond the tree.
        let mut far = sig.clone();
        far[..4].copy_from_slice(&32u32.to_be_bytes());
        assert_eq!(code(verify_action_signature(&fresh, &vault_key, &action, &far)), vault_err(VaultError::LeafOutOfRange));
        // An H10 signature for an H5 vault.
        let h10 = LmsPrivateKey::new(LmsType::Sha256M32H10, LmotsType::Sha256N32W4, [9; 16], [9; 32]);
        let sig10 = h10.sign(0, &signed_message(&vault_key, 0, &action));
        assert_eq!(code(verify_action_signature(&fresh, &vault_key, &action, &sig10)), vault_err(VaultError::SignatureTypeMismatch));
        // A valid signature from another key of the same parameter set.
        let other = h5_key(4).sign(0, &signed_message(&vault_key, 0, &action));
        assert_eq!(code(verify_action_signature(&fresh, &vault_key, &action, &other)), vault_err(VaultError::InvalidSignature));
        // Verification never mutates the vault.
        assert_eq!(fresh.spent, 0);
        fresh.spent = 0;
    }

    #[test]
    fn verify_flags_the_last_free_leaf() {
        let key = h5_key(5);
        let mut vault = vault_for(&key);
        let vault_key = Pubkey::new_unique();
        let action = transfer_action(10);
        for q in 0..31 {
            vault.spend_leaf(q).unwrap();
        }
        let sig = key.sign(31, &signed_message(&vault_key, 0, &action));
        let v = verify_action_signature(&vault, &vault_key, &action, &sig).unwrap();
        assert_eq!(v.q, 31);
        assert!(v.last_free);
    }

    #[test]
    fn check_action_expiry_exhaustion_and_decoding() {
        let transfer = transfer_action(100);
        assert!(matches!(check_action(&transfer, 100, false).unwrap(), Action::TransferSol { .. }));
        assert_eq!(code(check_action(&transfer, 101, false)), vault_err(VaultError::ActionExpired));
        assert_eq!(code(check_action(&transfer, 50, true)), vault_err(VaultError::LastLeafReservedForRotate));
        let token = Action::TransferToken { mint: Pubkey::new_unique(), to: Pubkey::new_unique(), amount: 1, issued_slot: 0, expiry_slot: 100 }.encode();
        assert_eq!(code(check_action(&token, 50, true)), vault_err(VaultError::LastLeafReservedForRotate));
        let rotate = Action::Rotate { new_lms_pubkey: [1; 56], issued_slot: 0, expiry_slot: 100 }.encode();
        assert!(matches!(check_action(&rotate, 100, true).unwrap(), Action::Rotate { .. }));
        // The exit is always open: Close may spend the last leaf too (a full key history makes Rotate fail).
        let close = Action::Close { to: Pubkey::new_unique(), issued_slot: 0, expiry_slot: 100 }.encode();
        assert!(matches!(check_action(&close, 100, true).unwrap(), Action::Close { .. }));
        assert_eq!(code(check_action(&close, 101, true)), vault_err(VaultError::ActionExpired));
        assert_eq!(code(check_action(&rotate, 101, true)), vault_err(VaultError::ActionExpired));
        assert_eq!(code(check_action(&[9, 9], 0, false)), vault_err(VaultError::ActionDecode));
        let mut trailing = transfer.clone();
        trailing.push(0);
        assert_eq!(code(check_action(&trailing, 0, false)), vault_err(VaultError::ActionDecode));
    }

    fn windowed(issued_slot: u64, expiry_slot: u64) -> Vec<u8> {
        Action::Close { to: Pubkey::new_unique(), issued_slot, expiry_slot }.encode()
    }

    #[test]
    fn validity_window_rules() {
        assert_eq!(MAX_VALIDITY_SLOTS, 216_000);
        let now = 1_000_000u64;
        // issued now, expires now: fine; issued earlier, expires later within a day: fine.
        assert!(check_action(&windowed(now, now), now, false).is_ok());
        assert!(check_action(&windowed(now - 10, now + 10), now, false).is_ok());
        // Exactly one day is the longest window.
        assert!(check_action(&windowed(now, now + MAX_VALIDITY_SLOTS), now, false).is_ok());
        assert!(check_action(&windowed(now - MAX_VALIDITY_SLOTS, now), now, false).is_ok());
        assert_eq!(code(check_action(&windowed(now, now + MAX_VALIDITY_SLOTS + 1), now, false)), vault_err(VaultError::InvalidValidityWindow));
        // Issued in the future, even by one slot, even with a fine window.
        assert_eq!(code(check_action(&windowed(now + 1, now + 2), now, false)), vault_err(VaultError::IssuedInFuture));
        // Expired: checked before the window shape.
        assert_eq!(code(check_action(&windowed(now - 5, now - 1), now, false)), vault_err(VaultError::ActionExpired));
        // An inverted window can never pass the two clock checks: whichever side the clock is on,
        // it is either expired or not yet issued.
        assert_eq!(code(check_action(&windowed(now, now - 1), now, false)), vault_err(VaultError::ActionExpired));
        assert_eq!(code(check_validity_window(now, now - 1, now - 1)), vault_err(VaultError::IssuedInFuture));
        // A far-future expiry on an old signature is impossible by construction: the window is capped.
        assert_eq!(code(check_action(&windowed(0, u64::MAX), now, false)), vault_err(VaultError::InvalidValidityWindow));
        assert_eq!(code(check_validity_window(0, u64::MAX, 0)), vault_err(VaultError::InvalidValidityWindow));
    }
}
