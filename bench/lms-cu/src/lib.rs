//! Verifies one LMS signature per instruction so the runtime's compute-unit
//! report measures exactly one `LmsPublicKey::parse` + `lms_verify`, the same
//! work the vault's `execute` does.
//!
//! Account 0 holds `u16le pk_len || pk || u16le msg_len || msg || u16le sig_len || sig`,
//! as the vault's signature buffer holds a staged signature. `bench/run.mjs`
//! writes one such account per signature from `vectors.bin`.

use lamport_lms::{lms_verify, parse_lms_signature, LmsPublicKey};
use solana_account_info::AccountInfo;
use solana_program_error::{ProgramError, ProgramResult};
use solana_pubkey::Pubkey;

solana_program_entrypoint::entrypoint!(process);

fn take<'a>(b: &mut &'a [u8]) -> Result<&'a [u8], ProgramError> {
    if b.len() < 2 {
        return Err(ProgramError::InvalidAccountData);
    }
    let n = u16::from_le_bytes([b[0], b[1]]) as usize;
    if b.len() < 2 + n {
        return Err(ProgramError::InvalidAccountData);
    }
    let field = &b[2..2 + n];
    *b = &b[2 + n..];
    Ok(field)
}

pub fn process(_program_id: &Pubkey, accounts: &[AccountInfo], data_in: &[u8]) -> ProgramResult {
    let account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let data = account.try_borrow_data()?;
    let mut b: &[u8] = &data;
    let pk = take(&mut b)?;
    let msg = take(&mut b)?;
    let sig = take(&mut b)?;
    let pk = LmsPublicKey::parse(pk).map_err(|_| ProgramError::InvalidAccountData)?;
    // Instruction data [1]: parse only (to separate parsing cost from hashing cost).
    if data_in.first() == Some(&1) {
        return parse_lms_signature(sig, &pk).map(|_| ()).map_err(|_| ProgramError::InvalidInstructionData);
    }
    lms_verify(&pk, msg, sig).map(|_| ()).map_err(|e| {
        solana_msg::msg!("lms_verify: {}", e.name());
        ProgramError::InvalidInstructionData
    })
}
