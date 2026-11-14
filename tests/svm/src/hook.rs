//! A Token-2022 mint with a transfer hook, for the tests: the fixture program in
//! `tests/hook-fixture`, the two accounts it reads, and the accounts a transfer of such a mint
//! has to be given. The same program, loaded at Token-2022's address, stands in for the token
//! program and records what a caller hands it. Build the fixture first:
//!
//! ```sh
//! cargo build-sbf --manifest-path tests/hook-fixture/Cargo.toml
//! ```
//!
//! The hook's account list is encoded here by hand, like the vault's own formats in this crate.
use litesvm::LiteSVM;
use solana_account::Account;
use solana_address::Address;
use solana_instruction::AccountMeta;

use crate::Pubkey;

pub const HOOK_SO: &str = "../hook-fixture/target/deploy/hook_fixture.so";
/// Where the tests load the fixture. Any address would do: the program reads its own id.
pub const HOOK_PROGRAM_ID: Pubkey = Address::from_str_const("C4ogtPDx1SGxg1iZQqgMkhM3ecjr84rouhsWRcGpB1sS");
pub const TOKEN_2022: Pubkey = Address::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ASSOCIATED_TOKEN: Pubkey = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// `sha256("spl-transfer-hook-interface:execute")[..8]`: the `Execute` instruction's discriminator,
/// and the type of the entry in the validation account that lists its extra accounts.
pub const EXECUTE: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];

/// What the fixture does, byte 0 of its counter (`tests/hook-fixture/src/lib.rs`).
pub const ALLOW: u8 = 0;
pub const REFUSE: u8 = 1;
pub const BURN_COMPUTE: u8 = 2;
/// Try to move [`TAKE_LAMPORTS`] out of the account listed after the counter, with the System
/// Program listed after that. It works only if that account reaches the hook as a writable signer.
pub const STEAL: u8 = 3;
pub const TAKE_LAMPORTS: u64 = 1_000_000_000;
/// Invoke the program listed after the counter, with no data and no accounts.
pub const CALL_BACK: u8 = 4;
pub const COUNTER_LEN: usize = 64;

/// The fixture's error when told to refuse.
pub const ERR_REFUSED: u32 = 0x4E4F;
/// The fixture's error when any account reached it as a signer.
pub const ERR_SAW_A_SIGNER: u32 = 0x5347;
/// `AccountResolutionError::IncorrectAccount` (spl-tlv-account-resolution), from Token-2022: an
/// account the hook's list names is not among the accounts it was given.
pub const ERR_LISTED_ACCOUNT_MISSING: u32 = 2_724_315_840;

/// The hook's validation account for `mint`: `["extra-account-metas", mint]` of the hook program.
pub fn validation_address(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"extra-account-metas", mint.as_ref()], &HOOK_PROGRAM_ID).0
}

/// The fixture's counter for `mint`: `["counter", mint]` of the hook program.
pub fn counter_address(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"counter", mint.as_ref()], &HOOK_PROGRAM_ID).0
}

/// One entry of a hook's list (`ExtraAccountMeta`, 35 bytes): how to find the account, and
/// whether the hook wants it as a signer and writable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listed {
    /// The fixture's counter, as a program-derived address of the hook: the literal seed
    /// `"counter"`, then the key of account 1 of `Execute` (the mint). Writable.
    Counter,
    /// A fixed address.
    Fixed { key: Pubkey, signer: bool, writable: bool },
}

impl Listed {
    fn encode(&self) -> [u8; 35] {
        let mut e = [0u8; 35];
        match self {
            Listed::Counter => {
                e[0] = 1; // a PDA of the hook program; the 32 bytes are packed seeds
                let seeds = &mut e[1..33];
                seeds[0] = 1; // Seed::Literal
                seeds[1] = 7;
                seeds[2..9].copy_from_slice(b"counter");
                seeds[9] = 3; // Seed::AccountKey
                seeds[10] = 1; // index 1: the mint
                e[34] = 1;
            }
            Listed::Fixed { key, signer, writable } => {
                e[1..33].copy_from_slice(key.as_ref());
                e[33] = *signer as u8;
                e[34] = *writable as u8;
            }
        }
        e
    }
}

/// The data of a validation account: one type-length-value entry, type [`EXECUTE`], whose value is
/// a count and that many 35-byte entries.
pub fn validation_data(list: &[Listed]) -> Vec<u8> {
    let mut d = EXECUTE.to_vec();
    d.extend_from_slice(&(4 + 35 * list.len() as u32).to_le_bytes());
    d.extend_from_slice(&(list.len() as u32).to_le_bytes());
    for entry in list {
        d.extend_from_slice(&entry.encode());
    }
    d
}

/// Loads the fixture program.
pub fn load(svm: &mut LiteSVM) {
    svm.add_program_from_file(HOOK_PROGRAM_ID, HOOK_SO).expect("build the fixture first: cargo build-sbf --manifest-path tests/hook-fixture/Cargo.toml");
}

fn put(svm: &mut LiteSVM, address: Pubkey, data: Vec<u8>) {
    let lamports = svm.minimum_balance_for_rent_exemption(data.len());
    svm.set_account(address, Account { lamports, data, owner: HOOK_PROGRAM_ID, executable: false, rent_epoch: 0 }).unwrap();
}

/// Writes the hook's two accounts for `mint`: the validation account with `list`, and the counter
/// in `mode` with nothing counted yet.
pub fn install(svm: &mut LiteSVM, mint: &Pubkey, mode: u8, list: &[Listed]) {
    put(svm, validation_address(mint), validation_data(list));
    let mut counter = vec![0u8; COUNTER_LEN];
    counter[0] = mode;
    put(svm, counter_address(mint), counter);
}

/// Tells the hook of `mint` what to do from now on; what it has counted stays.
pub fn set_mode(svm: &mut LiteSVM, mint: &Pubkey, mode: u8) {
    let mut counter = svm.get_account(&counter_address(mint)).expect("install the hook first").data;
    counter[0] = mode;
    put(svm, counter_address(mint), counter);
}

/// What the hook wrote the last time it let a transfer through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// Transfers let through so far.
    pub calls: u64,
    /// Amount of the last one.
    pub amount: u64,
    /// The authority of the last one, as the hook was told.
    pub authority: Pubkey,
    /// How many accounts the hook was called with.
    pub accounts: u8,
    /// How many of them were signers. Unless told to steal, the fixture refuses a transfer in
    /// which any was.
    pub signers: u8,
    /// Whether the source's authority came as a signer, or writable.
    pub authority_signer: bool,
    pub authority_writable: bool,
    /// Whether the source account, the mint or the destination account came writable.
    pub token_accounts_writable: bool,
    /// The account after the counter, if the hook's list had one: `(signer, writable)`.
    pub after_counter: Option<(bool, bool)>,
}

pub fn seen(svm: &LiteSVM, mint: &Pubkey) -> Seen {
    let d = svm.get_account(&counter_address(mint)).expect("install the hook first").data;
    Seen {
        calls: u64::from_le_bytes(d[8..16].try_into().unwrap()),
        amount: u64::from_le_bytes(d[16..24].try_into().unwrap()),
        authority: Pubkey::new_from_array(d[24..56].try_into().unwrap()),
        accounts: d[1],
        signers: d[3],
        authority_signer: d[2] & 0b1_0000 != 0,
        authority_writable: d[2] & 0b1000 != 0,
        token_accounts_writable: d[2] & 0b111 != 0,
        after_counter: (d[4] & 0x80 != 0).then_some((d[4] & 1 != 0, d[4] & 2 != 0)),
    }
}

/// The accounts a transfer of `mint` needs after the vault instruction's own: the counter
/// (writable), the validation account and the hook program.
pub fn accounts(mint: &Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(counter_address(mint), false),
        AccountMeta::new_readonly(validation_address(mint), false),
        AccountMeta::new_readonly(HOOK_PROGRAM_ID, false),
    ]
}

// ---- the stand-in for the token program ----

/// Where the stand-in writes its record in the source token account, and how many accounts it has
/// room for (`tests/hook-fixture/src/lib.rs`).
pub const RECORD_AT: usize = 166;
pub const RECORD_MAX_ACCOUNTS: usize = 32;

/// Puts the fixture at Token-2022's address. From here on a `TransferChecked` sent there moves
/// nothing and is recorded in its source account; mints and token accounts have to be written
/// with [`put_mint`] and [`put_token_account`], since no token program is left to make them.
pub fn stand_in_for_token_2022(svm: &mut LiteSVM) {
    svm.add_program_from_file(TOKEN_2022, HOOK_SO).expect("build the fixture first: cargo build-sbf --manifest-path tests/hook-fixture/Cargo.toml");
}

fn put_token(svm: &mut LiteSVM, address: Pubkey, data: Vec<u8>) {
    let lamports = svm.minimum_balance_for_rent_exemption(data.len());
    svm.set_account(address, Account { lamports, data, owner: TOKEN_2022, executable: false, rent_epoch: 0 }).unwrap();
}

/// A mint as Token-2022 lays one out without extensions: 82 bytes, `decimals` at 44, initialised at 45.
pub fn put_mint(svm: &mut LiteSVM, address: Pubkey, decimals: u8) {
    let mut d = vec![0u8; 82];
    d[44] = decimals;
    d[45] = 1;
    put_token(svm, address, d);
}

/// A token account as Token-2022 lays one out (mint, owner, amount, initialised at 108, account
/// type 2 at 165), with room behind it for the stand-in's record.
pub fn put_token_account(svm: &mut LiteSVM, address: Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) {
    let mut d = vec![0u8; RECORD_AT + 1 + RECORD_MAX_ACCOUNTS];
    d[..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d[165] = 2;
    put_token(svm, address, d);
}

/// What the stand-in was handed with the last `TransferChecked` that named `source` first:
/// `(signer, writable)` for every account, in order. Empty if none has arrived.
pub fn recorded(svm: &LiteSVM, source: &Pubkey) -> Vec<(bool, bool)> {
    let d = svm.get_account(source).expect("the source token account").data;
    let n = d[RECORD_AT] as usize;
    d[RECORD_AT + 1..RECORD_AT + 1 + n].iter().map(|f| (f & 1 != 0, f & 2 != 0)).collect()
}
