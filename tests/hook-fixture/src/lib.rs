//! Test fixture for `tests/svm`: one small program that plays two parts, depending on the address
//! LiteSVM loads it at. It is never deployed anywhere.
//!
//! # A transfer hook
//!
//! Token-2022 calls a mint's hook program on every transfer with the `Execute` instruction of the
//! SPL transfer-hook interface. The accounts are the source token account, the mint, the
//! destination token account and the source's authority, then the hook's *validation account*
//! (the address `["extra-account-metas", mint]` of the hook program, which lists the further
//! accounts the hook wants) and those accounts in the order listed.
//!
//! This hook wants one: its *counter*, at `["counter", mint]` of this program. It refuses to run
//! without it, so a transfer of such a mint only goes through when whoever called Token-2022 was
//! given the hook's accounts and handed them on. That is what the vault tests are about.
//!
//! It also refuses, with [`SAW_A_SIGNER`], if any account reaches it as a signer: a vault must
//! never lend a hook anybody's signature, and every transfer this hook lets through is a transfer
//! in which it checked that.
//!
//! The counter is [`COUNTER_LEN`] bytes. A test writes byte 0 to say what the hook should do; the
//! hook writes the rest when it lets a transfer through:
//!
//! ```text
//! 0        mode: 0 allow
//!                1 refuse with error REFUSED
//!                2 burn compute until the budget is gone
//!                3 steal: move TAKE_LAMPORTS from the account after the counter to the counter,
//!                  with the System Program (the account after that). It works only if that
//!                  account arrived as a writable signer.
//!                4 call back: invoke the program that is the account after the counter, with no
//!                  data and no accounts. A test names the vault program there.
//! 1        how many accounts the hook was called with
//! 2        what the hook saw of the four token accounts: bit 0 source writable, bit 1 mint
//!          writable, bit 2 destination writable, bit 3 authority writable, bit 4 authority signer
//! 3        how many of all its accounts were signers (0 in modes 0 to 2: with a signer the hook refuses)
//! 4        the account after the counter, if there was one: bit 7 present, bit 0 signer, bit 1 writable
//! 8..16    transfers let through so far (u64, little-endian)
//! 16..24   amount of the last one
//! 24..56   authority of the last one
//! ```
//!
//! There is no instruction that creates anything: the tests write the validation account and the
//! counter straight into the test chain.
//!
//! # A stand-in for the token program
//!
//! Loaded at Token-2022's own address, the program records what a caller hands the token program.
//! On `TransferChecked` it writes, into the first account (the source token account, which the
//! test made big enough), how many accounts came with the instruction and, for each, whether it
//! arrived as a signer and writable; it moves no tokens. Every other instruction succeeds and does
//! nothing. That shows the vault's call exactly as the token program gets it, whatever a given
//! release of Token-2022 would go on to do with it.
//!
//! ```text
//! RECORD_AT        number of accounts
//! RECORD_AT + 1..  one byte per account: bit 7 present, bit 0 signer, bit 1 writable
//! ```

use solana_account_info::AccountInfo;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::{ProgramError, ProgramResult};
use solana_pubkey::Pubkey;

solana_program_entrypoint::entrypoint!(process);

/// Discriminator of `Execute`: `sha256("spl-transfer-hook-interface:execute")[..8]`.
pub const EXECUTE: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];
pub const VALIDATION_SEED: &[u8] = b"extra-account-metas";
pub const COUNTER_SEED: &[u8] = b"counter";
pub const COUNTER_LEN: usize = 64;

pub const MODE_ALLOW: u8 = 0;
pub const MODE_REFUSE: u8 = 1;
pub const MODE_BURN_COMPUTE: u8 = 2;
pub const MODE_STEAL: u8 = 3;
pub const MODE_CALL_BACK: u8 = 4;

/// The custom error of a hook told to refuse.
pub const REFUSED: u32 = 0x4E4F;
/// The custom error when an account arrived as a signer.
pub const SAW_A_SIGNER: u32 = 0x5347;
/// What a hook told to steal tries to take.
pub const TAKE_LAMPORTS: u64 = 1_000_000_000;

pub const TOKEN_2022: Pubkey = Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
/// Tag of Token's and Token-2022's `TransferChecked`.
pub const TRANSFER_CHECKED: u8 = 12;
/// Where the stand-in writes its record in the source token account: after the 165-byte account
/// and the account-type byte.
pub const RECORD_AT: usize = 166;
pub const RECORD_MAX_ACCOUNTS: usize = 32;

fn flags(account: &AccountInfo) -> u8 {
    0x80 | (account.is_signer as u8) | (account.is_writable as u8) << 1
}

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if *program_id == TOKEN_2022 {
        return stand_in(accounts, data);
    }
    hook(program_id, accounts, data)
}

fn stand_in(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.first() != Some(&TRANSFER_CHECKED) {
        return Ok(());
    }
    let source = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    if accounts.len() > RECORD_MAX_ACCOUNTS {
        return Err(ProgramError::InvalidArgument);
    }
    let mut record = source.try_borrow_mut_data()?;
    if record.len() < RECORD_AT + 1 + RECORD_MAX_ACCOUNTS {
        return Err(ProgramError::AccountDataTooSmall);
    }
    record[RECORD_AT] = accounts.len() as u8;
    for (i, account) in accounts.iter().enumerate() {
        record[RECORD_AT + 1 + i] = flags(account);
    }
    Ok(())
}

fn hook(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 16 || data[..8] != EXECUTE {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let [source, mint, destination, authority, validation, counter, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let (validation_key, _) = Pubkey::find_program_address(&[VALIDATION_SEED, mint.key.as_ref()], program_id);
    if *validation.key != validation_key || validation.owner != program_id {
        return Err(ProgramError::InvalidSeeds);
    }
    let (counter_key, _) = Pubkey::find_program_address(&[COUNTER_SEED, mint.key.as_ref()], program_id);
    if *counter.key != counter_key || counter.owner != program_id || !counter.is_writable {
        return Err(ProgramError::InvalidArgument);
    }
    if counter.data_len() != COUNTER_LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    let mode = counter.try_borrow_data()?[0];
    let signers = accounts.iter().filter(|a| a.is_signer).count() as u8;

    match mode {
        MODE_ALLOW => {}
        MODE_REFUSE => return Err(ProgramError::Custom(REFUSED)),
        MODE_BURN_COMPUTE => {
            let mut n = 0u64;
            loop {
                n = core::hint::black_box(n.wrapping_add(1));
            }
        }
        MODE_STEAL => {
            let [victim, system_program] = accounts.get(6..8).ok_or(ProgramError::NotEnoughAccountKeys)? else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            // the System Program's Transfer: tag 2 (u32), then the lamports
            let mut transfer = vec![2, 0, 0, 0];
            transfer.extend_from_slice(&TAKE_LAMPORTS.to_le_bytes());
            let take = Instruction {
                program_id: *system_program.key,
                accounts: vec![AccountMeta::new(*victim.key, true), AccountMeta::new(*counter.key, false)],
                data: transfer,
            };
            solana_cpi::invoke(&take, &[victim.clone(), counter.clone()])?;
        }
        MODE_CALL_BACK => {
            let target = accounts.get(6).ok_or(ProgramError::NotEnoughAccountKeys)?;
            solana_cpi::invoke(&Instruction { program_id: *target.key, accounts: vec![], data: vec![] }, &[])?;
        }
        _ => return Err(ProgramError::InvalidAccountData),
    }
    if mode != MODE_STEAL && signers != 0 {
        return Err(ProgramError::Custom(SAW_A_SIGNER));
    }

    let mut state = counter.try_borrow_mut_data()?;
    state[1] = accounts.len() as u8;
    state[2] = (source.is_writable as u8)
        | (mint.is_writable as u8) << 1
        | (destination.is_writable as u8) << 2
        | (authority.is_writable as u8) << 3
        | (authority.is_signer as u8) << 4;
    state[3] = signers;
    state[4] = accounts.get(6).map_or(0, flags);
    let count = u64::from_le_bytes(state[8..16].try_into().unwrap());
    state[8..16].copy_from_slice(&count.wrapping_add(1).to_le_bytes());
    state[16..24].copy_from_slice(&amount.to_le_bytes());
    state[24..56].copy_from_slice(authority.key.as_ref());
    Ok(())
}
