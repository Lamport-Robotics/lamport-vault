//! A Token-2022 mint with a transfer hook, through every instruction of the vault that moves
//! tokens: `execute_direct` and the staged `execute` (`TransferToken`, `TransferTokenFrom`), and
//! `sweep_closed` after a `Close`. The mint, the token accounts and the transfers are the real
//! Token-2022 program's; the hook is the fixture in `tests/hook-fixture`, which wants one account
//! of its own, counts the transfers it lets through, and refuses any transfer in which an account
//! reaches it as a signer (or, told to, tries to take the SOL of an account it was handed).
//!
//! What is pinned here:
//! - with the hook's accounts given, the token moves and the hook has run;
//! - a hook that refuses, or burns the compute budget, fails the vault instruction and nothing
//!   moves: no token, no leaf, no lamport beyond the fee;
//! - missing or wrong hook accounts fail the same way;
//! - nobody's signature reaches a hook through the vault: not the vault's, not the fee payer's,
//!   not any other signer of the transaction, whatever the hook's list asks for. The vault's call
//!   to the token program is read directly for this, with the fixture standing in for it;
//! - a mint without a hook, and a plain SPL Token mint, move as before, with or without accounts
//!   that nobody needs.
//!
//! Runs against the default build and against the `succession` build alike.
use lamport_lms::LmsPrivateKey;
use lamport_vault_svm_tests::hook::{self, Listed};
use lamport_vault_svm_tests::*;
use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_system_interface::{instruction as system_instruction, program as system_program};
use solana_sysvar::clock::Clock;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use spl_associated_token_account_interface::instruction::create_associated_token_account_idempotent;
use spl_token_2022_interface as t22;
use t22::extension::ExtensionType;
use t22::state::{Account as TokenAccount, Mint};

const SO: &str = "../../target/deploy/lamport_vault.so";
const T22: Pubkey = hook::TOKEN_2022;
const DECIMALS: u8 = 6;
/// One signature, no priority fee.
const FEE: u64 = 5_000;

/// Anchor instruction discriminator, `sha256("global:<name>")[..8]`.
fn disc(name: &str) -> Vec<u8> {
    Sha256::digest(format!("global:{name}").as_bytes())[..8].to_vec()
}

fn vec_u8(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn kind(e: TransactionError) -> InstructionError {
    match e {
        TransactionError::InstructionError(_, kind) => kind,
        other => panic!("not an instruction error: {other:?}"),
    }
}

fn custom(e: TransactionError) -> u32 {
    match kind(e) {
        InstructionError::Custom(code) => code,
        other => panic!("not a program error: {other:?}"),
    }
}

/// A signature staged in a buffer, ready for `execute`.
struct Staged {
    buffer: Pubkey,
}

/// One H5 vault on LiteSVM with the hook fixture loaded.
struct World {
    svm: LiteSVM,
    payer: Keypair,
    key: LmsPrivateKey,
    vault: Pubkey,
    /// The next leaf a signed action will use. A leaf is spent only if the action executes.
    next_leaf: u32,
    /// Compute units of the last transaction sent.
    units: u64,
}

impl World {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program_from_file(PROGRAM_ID, SO).expect("anchor build first: target/deploy/lamport_vault.so");
        hook::load(&mut svm);
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        let key = h5_key(1);
        let pk = key.public_key().to_bytes();
        let vault_id = vault_id_for(&pk);
        let (vault, _) = vault_address(&vault_id);
        let mut w = World { svm, payer, key, vault, next_leaf: 0, units: 0 };
        let create = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![AccountMeta::new(w.me(), true), AccountMeta::new(vault, false), AccountMeta::new_readonly(system_program::ID, false)],
            data: create_vault_data(&vault_id, &pk),
        };
        w.send(&[create], &[]).expect("create_vault");
        let fund = system_instruction::transfer(&w.me(), &vault, 5_000_000_000);
        w.send(&[fund], &[]).expect("fund");
        w
    }

    /// The fee payer.
    fn me(&self) -> Pubkey {
        self.payer.pubkey()
    }

    /// Signs with the payer and `extra`, sends, and moves to a fresh blockhash so the same
    /// instructions can be sent again.
    fn send(&mut self, ixs: &[Instruction], extra: &[&Keypair]) -> Result<(), TransactionError> {
        let bh = self.svm.latest_blockhash();
        let msg = Message::new_with_blockhash(ixs, Some(&self.me()), &bh);
        let mut signers: Vec<&Keypair> = vec![&self.payer];
        signers.extend_from_slice(extra);
        let tx = Transaction::new(&signers, msg, bh);
        let r = match self.svm.send_transaction(tx) {
            Ok(meta) => {
                self.units = meta.compute_units_consumed;
                Ok(())
            }
            Err(failed) => {
                self.units = failed.meta.compute_units_consumed;
                Err(failed.err)
            }
        };
        self.svm.expire_blockhash();
        r
    }

    fn rent(&self, len: usize) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(len)
    }

    fn balance(&self, k: &Pubkey) -> u64 {
        self.svm.get_balance(k).unwrap_or(0)
    }

    fn exists(&self, k: &Pubkey) -> bool {
        self.svm.get_account(k).is_some_and(|a| a.lamports > 0)
    }

    /// Balance of a token account.
    fn amount(&self, account: &Pubkey) -> u64 {
        u64::from_le_bytes(self.svm.get_account(account).expect("the token account").data[64..72].try_into().unwrap())
    }

    fn spent(&self) -> u32 {
        decode_vault(&self.svm.get_account(&self.vault).unwrap().data).spent
    }

    fn is_tombstone(&self) -> bool {
        self.svm.get_account(&self.vault).unwrap().data[..8] == TOMBSTONE_DISC
    }

    fn window(&self) -> (u64, u64) {
        let s = self.svm.get_sysvar::<Clock>().slot;
        (s, s + 300)
    }

    // ---- mints and token accounts, made by the token programs themselves ----

    /// A mint under `program` with `extensions`, each initialised by `init` before the mint
    /// itself. The payer is the mint authority.
    fn mint(&mut self, program: &Pubkey, extensions: &[ExtensionType], init: impl Fn(&Pubkey) -> Vec<Instruction>) -> Pubkey {
        let mint = Keypair::new();
        let payer = self.me();
        let space = ExtensionType::try_calculate_account_len::<Mint>(extensions).unwrap();
        let mut ixs = vec![system_instruction::create_account(&payer, &mint.pubkey(), self.rent(space), space as u64, program)];
        ixs.extend(init(&mint.pubkey()));
        ixs.push(t22::instruction::initialize_mint2(program, &mint.pubkey(), &payer, None, DECIMALS).unwrap());
        self.send(&ixs, &[&mint]).expect("create the mint");
        mint.pubkey()
    }

    /// A Token-2022 mint whose transfer hook is the fixture, with the hook's accounts written:
    /// what it should do (`mode`) and the accounts it lists.
    fn hook_mint(&mut self, mode: u8, list: &[Listed]) -> Pubkey {
        let payer = self.me();
        let mint = self.mint(&T22, &[ExtensionType::TransferHook], |mint| {
            vec![t22::extension::transfer_hook::instruction::initialize(&T22, mint, Some(payer), Some(hook::HOOK_PROGRAM_ID)).unwrap()]
        });
        hook::install(&mut self.svm, &mint, mode, list);
        mint
    }

    /// `owner`'s associated token account for `mint` under `program`, created if missing.
    fn ata(&mut self, program: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
        let ix = create_associated_token_account_idempotent(&self.me(), owner, mint, program);
        self.send(&[ix], &[]).expect("create the associated token account");
        ata_of(program, owner, mint)
    }

    /// A token account of `owner` for a hook mint at an address of its own (not the associated one).
    fn hook_token_account(&mut self, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
        let account = Keypair::new();
        let space = ExtensionType::try_calculate_account_len::<TokenAccount>(&[ExtensionType::TransferHookAccount]).unwrap();
        let ixs = [
            system_instruction::create_account(&self.me(), &account.pubkey(), self.rent(space), space as u64, &T22),
            t22::instruction::initialize_account3(&T22, &account.pubkey(), mint, owner).unwrap(),
        ];
        self.send(&ixs, &[&account]).expect("create the token account");
        account.pubkey()
    }

    fn mint_to(&mut self, program: &Pubkey, mint: &Pubkey, account: &Pubkey, amount: u64) {
        let ix = t22::instruction::mint_to(program, mint, account, &self.me(), &[], amount).unwrap();
        self.send(&[ix], &[]).expect("mint_to");
    }

    /// The vault's associated token account for `mint`, holding `amount`, and somebody else's
    /// to send to.
    fn funded(&mut self, program: &Pubkey, mint: &Pubkey, amount: u64) -> (Pubkey, Pubkey) {
        let vault = self.vault;
        let from = self.ata(program, &vault, mint);
        self.mint_to(program, mint, &from, amount);
        let to = self.ata(program, &Keypair::new().pubkey(), mint);
        (from, to)
    }

    // ---- the vault's instructions ----

    fn sign(&self, q: u32, action: &[u8]) -> Vec<u8> {
        self.key.sign(q, &signed_message(&self.vault, 0, action))
    }

    /// `execute_direct` of `action`, signed with the next free leaf, by the payer and `extra`.
    fn direct_signed_by(&mut self, action: &[u8], remaining: Vec<AccountMeta>, extra: &[&Keypair]) -> Result<(), TransactionError> {
        let sig = self.sign(self.next_leaf, action);
        let mut accounts = vec![AccountMeta::new(self.vault, false), AccountMeta::new(self.me(), true), AccountMeta::new_readonly(system_program::ID, false)];
        accounts.extend(remaining);
        let ix = Instruction { program_id: PROGRAM_ID, accounts, data: execute_direct_data(action, &sig) };
        let r = self.send(&[ComputeBudgetInstruction::set_compute_unit_limit(400_000), ix], extra);
        if r.is_ok() {
            self.next_leaf += 1;
        }
        r
    }

    fn direct(&mut self, action: &[u8], remaining: Vec<AccountMeta>) -> Result<(), TransactionError> {
        self.direct_signed_by(action, remaining, &[])
    }

    /// Opens a signature buffer for `action` and fills it: everything of the staged path but the
    /// `execute` itself.
    fn stage(&mut self, action: &[u8]) -> Staged {
        let sig = self.sign(self.next_leaf, action);
        let nonce = 7_000 + self.next_leaf as u64;
        let payer = self.me();
        let (buffer, _) = Pubkey::find_program_address(&[b"sig", self.vault.as_ref(), payer.as_ref(), &nonce.to_le_bytes()], &PROGRAM_ID);
        let mut data = disc("open_sig_buffer");
        data.extend_from_slice(&nonce.to_le_bytes());
        vec_u8(&mut data, action);
        data.extend_from_slice(&(sig.len() as u16).to_le_bytes());
        vec_u8(&mut data, &[]);
        let open = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![AccountMeta::new(payer, true), AccountMeta::new_readonly(self.vault, false), AccountMeta::new(buffer, false), AccountMeta::new_readonly(system_program::ID, false)],
            data,
        };
        self.send(&[open], &[]).expect("open_sig_buffer");
        for (i, chunk) in sig.chunks(900).enumerate() {
            let mut data = disc("write_sig");
            data.extend_from_slice(&((i * 900) as u16).to_le_bytes());
            vec_u8(&mut data, chunk);
            let write = Instruction { program_id: PROGRAM_ID, accounts: vec![AccountMeta::new_readonly(payer, true), AccountMeta::new(buffer, false)], data };
            self.send(&[write], &[]).expect("write_sig");
        }
        Staged { buffer }
    }

    /// `execute` of a staged signature.
    fn execute(&mut self, staged: &Staged, remaining: Vec<AccountMeta>) -> Result<(), TransactionError> {
        let mut accounts = vec![AccountMeta::new(self.vault, false), AccountMeta::new(staged.buffer, false), AccountMeta::new(self.me(), false)];
        accounts.extend(remaining);
        let ix = Instruction { program_id: PROGRAM_ID, accounts, data: disc("execute") };
        let r = self.send(&[ComputeBudgetInstruction::set_compute_unit_limit(400_000), ix], &[]);
        if r.is_ok() {
            self.next_leaf += 1;
        }
        r
    }

    /// A signed `Close` to `heir`. The vault's token accounts are left for `sweep_closed`.
    fn close(&mut self, heir: &Pubkey) {
        let (issued, expiry) = self.window();
        let action = action::close(heir, issued, expiry);
        self.direct(&action, vec![AccountMeta::new(*heir, false)]).expect("Close");
        assert!(self.is_tombstone());
    }

    /// `sweep_closed` of one of the closed vault's token accounts, with `extra` accounts after its own.
    fn sweep(&mut self, program: &Pubkey, heir: &Pubkey, account: &Pubkey, mint: &Pubkey, extra: Vec<AccountMeta>) -> Result<(), TransactionError> {
        let mut accounts = vec![
            AccountMeta::new(self.me(), true),
            AccountMeta::new_readonly(self.vault, false),
            AccountMeta::new(*heir, false),
            AccountMeta::new(ata_of(program, heir, mint), false),
            AccountMeta::new(*account, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*program, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(hook::ASSOCIATED_TOKEN, false),
        ];
        accounts.extend(extra);
        let ix = Instruction { program_id: PROGRAM_ID, accounts, data: disc("sweep_closed") };
        self.send(&[ComputeBudgetInstruction::set_compute_unit_limit(400_000), ix], &[])
    }
}

/// The associated token account of `owner` for `mint` under `program`.
fn ata_of(program: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[owner.as_ref(), program.as_ref(), mint.as_ref()], &hook::ASSOCIATED_TOKEN).0
}

/// The four accounts a token transfer names, as `execute` and `execute_direct` take them.
fn four(program: &Pubkey, from: &Pubkey, to: &Pubkey, mint: &Pubkey) -> Vec<AccountMeta> {
    vec![AccountMeta::new(*from, false), AccountMeta::new(*to, false), AccountMeta::new_readonly(*mint, false), AccountMeta::new_readonly(*program, false)]
}

/// The four, then the hook's accounts.
fn with_hook(program: &Pubkey, from: &Pubkey, to: &Pubkey, mint: &Pubkey) -> Vec<AccountMeta> {
    let mut metas = four(program, from, to, mint);
    metas.extend(hook::accounts(mint));
    metas
}

/// What a transfer that went through the hook must look like from inside it: the vault as the
/// authority, read-only and unsigned like the three token accounts, and no signer anywhere.
fn hook_ran_once_for(w: &World, mint: &Pubkey, amount: u64) -> hook::Seen {
    let seen = hook::seen(&w.svm, mint);
    assert_eq!(seen.calls, 1, "the hook ran once");
    assert_eq!(seen.amount, amount);
    assert_eq!(seen.authority, w.vault, "the hook was told the vault is the authority");
    assert!(!seen.authority_signer && !seen.authority_writable, "the vault reaches the hook read-only and unsigned");
    assert!(!seen.token_accounts_writable, "so do the token accounts and the mint");
    assert_eq!(seen.signers, 0, "no account reaches the hook as a signer");
    seen
}

// ---- the token leaves, and the hook has run ----

#[test]
fn a_hook_mint_leaves_by_execute_direct_and_the_hook_runs() {
    let mut w = World::new();
    let mint = w.hook_mint(hook::ALLOW, &[Listed::Counter]);
    let (from, to) = w.funded(&T22, &mint, 1_000_000);
    let (issued, expiry) = w.window();
    let action = action::transfer_token(&mint, &to, 250_000, issued, expiry);
    w.direct(&action, with_hook(&T22, &from, &to, &mint)).expect("TransferToken of a hook mint");
    assert_eq!((w.amount(&from), w.amount(&to)), (750_000, 250_000));
    assert_eq!(w.spent(), 1);
    let seen = hook_ran_once_for(&w, &mint, 250_000);
    assert_eq!(seen.accounts, 6, "source, mint, destination, authority, validation account, counter");
    println!("execute_direct, TransferToken, hook mint: {} compute units", w.units);
}

#[test]
fn a_hook_mint_leaves_by_transfer_token_from() {
    let mut w = World::new();
    let mint = w.hook_mint(hook::ALLOW, &[Listed::Counter]);
    let vault = w.vault;
    // not the vault's associated account: the action names its source
    let from = w.hook_token_account(&vault, &mint);
    w.mint_to(&T22, &mint, &from, 500);
    let to = w.ata(&T22, &Keypair::new().pubkey(), &mint);
    let (issued, expiry) = w.window();
    let action = action::transfer_token_from(&from, &mint, &to, 500, issued, expiry);
    w.direct(&action, with_hook(&T22, &from, &to, &mint)).expect("TransferTokenFrom of a hook mint");
    assert_eq!((w.amount(&from), w.amount(&to)), (0, 500));
    hook_ran_once_for(&w, &mint, 500);
}

#[test]
fn a_hook_mint_leaves_by_the_staged_execute() {
    let mut w = World::new();
    let mint = w.hook_mint(hook::ALLOW, &[Listed::Counter]);
    let (from, to) = w.funded(&T22, &mint, 1_000);
    let (issued, expiry) = w.window();
    let action = action::transfer_token(&mint, &to, 400, issued, expiry);
    let staged = w.stage(&action);
    // without the hook's accounts the buffer stays, and so does everything else
    assert!(w.execute(&staged, four(&T22, &from, &to, &mint)).is_err());
    assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (1_000, 0, 0));
    assert!(w.exists(&staged.buffer), "the buffer is still there to execute");
    w.execute(&staged, with_hook(&T22, &from, &to, &mint)).expect("execute of a hook mint");
    assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (600, 400, 1));
    assert!(!w.exists(&staged.buffer), "the buffer is closed");
    hook_ran_once_for(&w, &mint, 400);
    println!("execute (staged), TransferToken, hook mint: {} compute units", w.units);
}

#[test]
fn a_hook_mint_left_in_a_closed_vault_is_swept_to_the_heir() {
    let mut w = World::new();
    let mint = w.hook_mint(hook::ALLOW, &[Listed::Counter]);
    let (account, _) = w.funded(&T22, &mint, 1_000);
    let heir = Keypair::new().pubkey();
    w.close(&heir);
    w.sweep(&T22, &heir, &account, &mint, hook::accounts(&mint)).expect("sweep_closed of a hook mint");
    assert_eq!(w.amount(&ata_of(&T22, &heir, &mint)), 1_000);
    assert!(!w.exists(&account), "the vault's token account is closed");
    // the tombstone sits at the vault's address and signs as the vault did
    let seen = hook_ran_once_for(&w, &mint, 1_000);
    assert_eq!(seen.accounts, 6);
    println!("sweep_closed, hook mint, heir's account created: {} compute units", w.units);
}

#[test]
fn the_order_of_the_hooks_accounts_does_not_matter_and_strangers_are_not_handed_to_the_hook() {
    let mut w = World::new();
    let mint = w.hook_mint(hook::ALLOW, &[Listed::Counter]);
    let (from, to) = w.funded(&T22, &mint, 1_000);
    let (issued, expiry) = w.window();
    let action = action::transfer_token(&mint, &to, 10, issued, expiry);
    let mut metas = four(&T22, &from, &to, &mint);
    let mut extra = hook::accounts(&mint);
    extra.reverse();
    extra.insert(1, AccountMeta::new(Keypair::new().pubkey(), false));
    extra.push(AccountMeta::new_readonly(system_program::ID, false));
    metas.extend(extra);
    w.direct(&action, metas).expect("the hook's accounts in another order, among strangers");
    assert_eq!(w.amount(&to), 10);
    // the token program picked the hook's accounts out by address; the two strangers went no further
    assert_eq!(hook_ran_once_for(&w, &mint, 10).accounts, 6);
}

// ---- a hook that refuses ----

#[test]
fn a_hook_that_refuses_fails_execute_direct_and_nothing_moves() {
    let mut w = World::new();
    let mint = w.hook_mint(hook::REFUSE, &[Listed::Counter]);
    let (from, to) = w.funded(&T22, &mint, 1_000);
    let (issued, expiry) = w.window();
    let action = action::transfer_token(&mint, &to, 300, issued, expiry);
    let payer_before = w.balance(&w.me());
    let vault_before = w.balance(&w.vault);
    let e = w.direct(&action, with_hook(&T22, &from, &to, &mint)).unwrap_err();
    assert_eq!(custom(e), hook::ERR_REFUSED, "the hook's own error comes back");
    assert_eq!((w.amount(&from), w.amount(&to)), (1_000, 0), "no token moved");
    assert_eq!(w.spent(), 0, "no leaf was spent");
    assert_eq!(w.balance(&w.vault), vault_before);
    assert_eq!(w.balance(&w.me()), payer_before - FEE, "the payer lost the fee and nothing else");
    assert_eq!(hook::seen(&w.svm, &mint).calls, 0);
    // the same action, signed with the same leaf, goes through once the hook allows it
    hook::set_mode(&mut w.svm, &mint, hook::ALLOW);
    w.direct(&action, with_hook(&T22, &from, &to, &mint)).expect("the hook allows it now");
    assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (700, 300, 1));
}

#[test]
fn a_hook_that_refuses_fails_the_staged_execute_and_the_buffer_stays() {
    let mut w = World::new();
    let mint = w.hook_mint(hook::REFUSE, &[Listed::Counter]);
    let (from, to) = w.funded(&T22, &mint, 1_000);
    let (issued, expiry) = w.window();
    let action = action::transfer_token(&mint, &to, 300, issued, expiry);
    let staged = w.stage(&action);
    let buffer_lamports = w.balance(&staged.buffer);
    let e = w.execute(&staged, with_hook(&T22, &from, &to, &mint)).unwrap_err();
    assert_eq!(custom(e), hook::ERR_REFUSED);
    assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (1_000, 0, 0));
    assert_eq!(w.balance(&staged.buffer), buffer_lamports, "the buffer keeps its rent");
    hook::set_mode(&mut w.svm, &mint, hook::ALLOW);
    w.execute(&staged, with_hook(&T22, &from, &to, &mint)).expect("the hook allows it now");
    assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (700, 300, 1));
}

#[test]
fn a_hook_that_refuses_fails_the_sweep_and_the_token_waits() {
    let mut w = World::new();
    let mint = w.hook_mint(hook::ALLOW, &[Listed::Counter]);
    let (account, _) = w.funded(&T22, &mint, 1_000);
    let heir = Keypair::new().pubkey();
    w.close(&heir);
    hook::set_mode(&mut w.svm, &mint, hook::REFUSE);
    let payer_before = w.balance(&w.me());
    let e = w.sweep(&T22, &heir, &account, &mint, hook::accounts(&mint)).unwrap_err();
    assert_eq!(custom(e), hook::ERR_REFUSED);
    assert_eq!(w.amount(&account), 1_000, "the closed vault still holds the token");
    assert!(!w.exists(&ata_of(&T22, &heir, &mint)), "the heir's account was not even created");
    assert_eq!(w.balance(&w.me()), payer_before - FEE);
    hook::set_mode(&mut w.svm, &mint, hook::ALLOW);
    w.sweep(&T22, &heir, &account, &mint, hook::accounts(&mint)).expect("the hook allows it now");
    assert_eq!(w.amount(&ata_of(&T22, &heir, &mint)), 1_000);
}

#[test]
fn a_hook_that_burns_the_compute_budget_fails_the_same_way() {
    let mut w = World::new();
    let mint = w.hook_mint(hook::BURN_COMPUTE, &[Listed::Counter]);
    let (from, to) = w.funded(&T22, &mint, 1_000);
    let (issued, expiry) = w.window();
    let action = action::transfer_token(&mint, &to, 300, issued, expiry);
    let payer_before = w.balance(&w.me());
    let e = w.direct(&action, with_hook(&T22, &from, &to, &mint)).unwrap_err();
    assert!(matches!(kind(e), InstructionError::ProgramFailedToComplete | InstructionError::ComputationalBudgetExceeded));
    assert_eq!(w.units, 400_000, "the whole budget went");
    assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (1_000, 0, 0));
    assert_eq!(w.balance(&w.me()), payer_before - FEE);
}

// ---- missing or wrong hook accounts ----

// `NotEnoughAccountKeys` is the name the fixture's own refusal comes back under; the crate has since
// folded it into `MissingAccount` for new code.
#[test]
#[allow(deprecated)]
fn missing_or_wrong_hook_accounts_fail_the_transfer_and_nothing_moves() {
    let mut w = World::new();
    let mint = w.hook_mint(hook::ALLOW, &[Listed::Counter]);
    let other_mint = w.hook_mint(hook::ALLOW, &[Listed::Counter]);
    let (from, to) = w.funded(&T22, &mint, 1_000);
    let (issued, expiry) = w.window();
    let action = action::transfer_token(&mint, &to, 300, issued, expiry);

    let counter = AccountMeta::new(hook::counter_address(&mint), false);
    let validation = AccountMeta::new_readonly(hook::validation_address(&mint), false);
    let program = AccountMeta::new_readonly(hook::HOOK_PROGRAM_ID, false);
    let stranger = AccountMeta::new(Keypair::new().pubkey(), false);
    let cases: Vec<(&str, Vec<AccountMeta>, InstructionError)> = vec![
        // Token-2022 cannot call a program it was not given
        ("no hook accounts at all", vec![], InstructionError::MissingAccount),
        ("the counter and the validation account, without the hook program", vec![counter.clone(), validation.clone()], InstructionError::MissingAccount),
        // without its validation account the hook is called with the four token accounts only, and refuses
        ("the hook program alone", vec![program.clone()], InstructionError::NotEnoughAccountKeys),
        ("the hook program and the counter, without the validation account", vec![program.clone(), counter.clone()], InstructionError::NotEnoughAccountKeys),
        ("another mint's hook accounts", hook::accounts(&other_mint), InstructionError::NotEnoughAccountKeys),
        // Token-2022 reads the list and does not find what it names
        ("the hook program and the validation account, without the counter", vec![program.clone(), validation.clone()], InstructionError::Custom(hook::ERR_LISTED_ACCOUNT_MISSING)),
        ("a stranger where the counter should be", vec![stranger, validation.clone(), program.clone()], InstructionError::Custom(hook::ERR_LISTED_ACCOUNT_MISSING)),
        // the list wants the counter writable; the transaction did not make it so, and the vault adds nothing
        ("the counter read-only", vec![AccountMeta::new_readonly(counter.pubkey, false), validation.clone(), program.clone()], InstructionError::PrivilegeEscalation),
    ];
    for (name, extra, expected) in cases {
        let mut metas = four(&T22, &from, &to, &mint);
        metas.extend(extra);
        let payer_before = w.balance(&w.me());
        let e = w.direct(&action, metas).expect_err(name);
        assert_eq!(kind(e), expected, "{name}");
        assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (1_000, 0, 0), "{name}: nothing moved, no leaf spent");
        assert_eq!(w.balance(&w.me()), payer_before - FEE, "{name}: the payer lost the fee and nothing else");
        assert_eq!(hook::seen(&w.svm, &mint).calls, 0, "{name}");
    }
    // and with the right ones, the same signed action goes through
    w.direct(&action, with_hook(&T22, &from, &to, &mint)).expect("the right accounts");
    assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (700, 300, 1));
}

#[test]
#[allow(deprecated)]
fn a_sweep_without_the_hooks_accounts_fails_and_the_token_waits() {
    let mut w = World::new();
    let mint = w.hook_mint(hook::ALLOW, &[Listed::Counter]);
    let (account, _) = w.funded(&T22, &mint, 1_000);
    let heir = Keypair::new().pubkey();
    w.close(&heir);
    let program = AccountMeta::new_readonly(hook::HOOK_PROGRAM_ID, false);
    for (name, extra, expected) in [
        ("no hook accounts", vec![], InstructionError::MissingAccount),
        ("the hook program alone", vec![program], InstructionError::NotEnoughAccountKeys),
    ] {
        let e = w.sweep(&T22, &heir, &account, &mint, extra).expect_err(name);
        assert_eq!(kind(e), expected, "{name}");
        assert_eq!(w.amount(&account), 1_000, "{name}");
        assert!(!w.exists(&ata_of(&T22, &heir, &mint)), "{name}: nothing was created");
    }
    w.sweep(&T22, &heir, &account, &mint, hook::accounts(&mint)).expect("the right accounts");
    assert_eq!(w.amount(&ata_of(&T22, &heir, &mint)), 1_000);
}

// ---- nobody's signature reaches a hook through the vault ----
//
// Whoever pays for a transaction signs all of it, so the fee payer is a signer in every
// instruction that names it. A mint's owner can write any key into the hook's list, the payer's
// included, and ask for it as a writable signer; a hook handed that could move the payer's SOL.
// The vault passes every remaining account on unsigned, so the token program has no signature to
// give a hook but the vault's own, and that one it keeps.
//
// Two layers enforce this, and the tests take them apart. The Token-2022 that LiteSVM 0.17.0 runs
// (11.0.0) demotes every account of a hook's list to a non-signer by itself; the 8.0.1 source the
// vault is built against passed the flag on. The vault's rule must not depend on which one is
// deployed, so `the_vault_hands_the_token_program_no_signature_but_its_own` reads the vault's call
// directly, with the fixture standing in for the token program. The others run the real one.

/// The four accounts of a transfer as the token program has always been sent them: source and
/// destination writable, the mint read-only, the authority read-only and signed.
const FOUR: [(bool, bool); 4] = [(false, true), (false, false), (false, true), (true, false)];

#[test]
fn the_vault_hands_the_token_program_no_signature_but_its_own() {
    let mut w = World::new();
    hook::stand_in_for_token_2022(&mut w.svm);
    let vault = w.vault;
    let payer = w.me();
    let second = Keypair::new();
    let mint = Keypair::new().pubkey();
    hook::put_mint(&mut w.svm, mint, DECIMALS);
    let from = Keypair::new().pubkey();
    hook::put_token_account(&mut w.svm, from, &mint, &vault, 1_000);
    let to = Keypair::new().pubkey();
    hook::put_token_account(&mut w.svm, to, &mint, &Keypair::new().pubkey(), 0);
    let (issued, expiry) = w.window();
    let action = action::transfer_token(&mint, &to, 100, issued, expiry);

    // nothing after the four: the call is the one anchor-spl made before
    w.direct(&action, four(&T22, &from, &to, &mint)).expect("the four accounts alone");
    assert_eq!(hook::recorded(&w.svm, &from), FOUR);

    // After the four: a read-only stranger, a writable one, the fee payer marked as a writable
    // signer, and a second key that signed the transaction. Each arrives writable or not as the
    // transaction made it, and none of them signed.
    let extra = vec![
        AccountMeta::new_readonly(Keypair::new().pubkey(), false),
        AccountMeta::new(Keypair::new().pubkey(), false),
        AccountMeta::new(payer, true),
        AccountMeta::new_readonly(second.pubkey(), true),
    ];
    let unsigned = [(false, false), (false, true), (false, true), (false, false)];
    let expected: Vec<(bool, bool)> = FOUR.into_iter().chain(unsigned).collect();
    let mut metas = four(&T22, &from, &to, &mint);
    metas.extend(extra.clone());
    w.direct_signed_by(&action, metas.clone(), &[&second]).expect("execute_direct");
    assert_eq!(hook::recorded(&w.svm, &from), expected, "execute_direct");

    // the staged path
    hook::put_token_account(&mut w.svm, from, &mint, &vault, 1_000);
    let staged = w.stage(&action);
    let mut accounts = vec![AccountMeta::new(vault, false), AccountMeta::new(staged.buffer, false), AccountMeta::new(payer, false)];
    accounts.extend(metas);
    let ix = Instruction { program_id: PROGRAM_ID, accounts, data: disc("execute") };
    w.send(&[ComputeBudgetInstruction::set_compute_unit_limit(400_000), ix], &[&second]).expect("execute");
    w.next_leaf += 1;
    assert_eq!(hook::recorded(&w.svm, &from), expected, "execute");

    // TransferTokenFrom is the same call
    hook::put_token_account(&mut w.svm, from, &mint, &vault, 1_000);
    let action = action::transfer_token_from(&from, &mint, &to, 100, issued, expiry);
    let mut metas = four(&T22, &from, &to, &mint);
    metas.extend(extra.clone());
    w.direct_signed_by(&action, metas, &[&second]).expect("TransferTokenFrom");
    assert_eq!(hook::recorded(&w.svm, &from), expected, "TransferTokenFrom");

    // and sweep_closed, where the caller is anyone at all
    let heir = Keypair::new().pubkey();
    w.close(&heir);
    hook::put_token_account(&mut w.svm, from, &mint, &vault, 1_000);
    hook::put_token_account(&mut w.svm, ata_of(&T22, &heir, &mint), &mint, &heir, 0);
    let mut sweep = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new(heir, false),
            AccountMeta::new(ata_of(&T22, &heir, &mint), false),
            AccountMeta::new(from, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(T22, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(hook::ASSOCIATED_TOKEN, false),
        ],
        data: disc("sweep_closed"),
    };
    w.send(&[sweep.clone()], &[]).expect("sweep_closed, its own accounts alone");
    assert_eq!(hook::recorded(&w.svm, &from), FOUR, "sweep_closed, bare");
    hook::put_token_account(&mut w.svm, from, &mint, &vault, 1_000);
    sweep.accounts.extend(extra);
    w.send(&[sweep], &[&second]).expect("sweep_closed");
    assert_eq!(hook::recorded(&w.svm, &from), expected, "sweep_closed");
}

#[test]
fn the_fixture_notices_a_signer_and_its_thief_steals_when_handed_one() {
    // The control for the tests below: the fixture does what they rely on. Called directly, with
    // somebody's signature on the transaction, the hook refuses because it saw a signer; told to
    // steal, it takes that somebody's SOL.
    let mut w = World::new();
    let victim = Keypair::new();
    w.svm.airdrop(&victim.pubkey(), 5_000_000_000).unwrap();
    let mint = w.hook_mint(hook::ALLOW, &[Listed::Counter]);
    let mut data = hook::EXECUTE.to_vec();
    data.extend_from_slice(&1u64.to_le_bytes());
    let any = AccountMeta::new_readonly(Keypair::new().pubkey(), false);
    let ix = Instruction {
        program_id: hook::HOOK_PROGRAM_ID,
        accounts: vec![
            any.clone(),
            AccountMeta::new_readonly(mint, false),
            any.clone(),
            any,
            AccountMeta::new_readonly(hook::validation_address(&mint), false),
            AccountMeta::new(hook::counter_address(&mint), false),
            AccountMeta::new(victim.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    };
    let e = w.send(&[ix.clone()], &[&victim]).unwrap_err();
    assert_eq!(custom(e), hook::ERR_SAW_A_SIGNER);
    assert_eq!(hook::seen(&w.svm, &mint).calls, 0);
    hook::set_mode(&mut w.svm, &mint, hook::STEAL);
    w.send(&[ix], &[&victim]).expect("the thief, given a signature");
    assert_eq!(w.balance(&victim.pubkey()), 5_000_000_000 - hook::TAKE_LAMPORTS);
}

#[test]
fn the_token_program_run_here_gives_a_hook_no_signer_either() {
    // No vault: an ordinary transfer by the payer. A bystander signs the transaction, the hook's
    // list asks for the bystander as a writable signer, and the bystander is passed as one.
    // Token-2022 11.0.0 hands it over writable but unsigned. An older release would have handed
    // over the signature, which is why the vault's own rule is tested without the token program.
    let mut w = World::new();
    let bystander = Keypair::new();
    let mint = w.hook_mint(hook::ALLOW, &[Listed::Counter, Listed::Fixed { key: bystander.pubkey(), signer: true, writable: true }]);
    let payer = w.me();
    let from = w.ata(&T22, &payer, &mint);
    w.mint_to(&T22, &mint, &from, 100);
    let to = w.ata(&T22, &Keypair::new().pubkey(), &mint);
    let mut ix = t22::instruction::transfer_checked(&T22, &from, &mint, &to, &payer, &[], 10, DECIMALS).unwrap();
    ix.accounts.extend(hook::accounts(&mint));
    ix.accounts.push(AccountMeta::new(bystander.pubkey(), true));
    w.send(&[ix], &[&bystander]).expect("an ordinary transfer");
    let seen = hook::seen(&w.svm, &mint);
    assert_eq!((seen.calls, seen.signers), (1, 0));
    assert_eq!(seen.after_counter, Some((false, true)), "the bystander: unsigned, writable");
}

/// A hook mint whose hook steals from `victim`: the list names the counter, the victim as a
/// writable signer, and the System Program.
fn thief_mint(w: &mut World, victim: &Pubkey) -> Pubkey {
    w.hook_mint(
        hook::STEAL,
        &[Listed::Counter, Listed::Fixed { key: *victim, signer: true, writable: true }, Listed::Fixed { key: system_program::ID, signer: false, writable: false }],
    )
}

/// What a client that follows the hook's list to the letter would append: the hook's accounts,
/// the victim as a writable signer, the System Program.
fn thief_accounts(mint: &Pubkey, victim: &Pubkey) -> Vec<AccountMeta> {
    let mut metas = hook::accounts(mint);
    metas.push(AccountMeta::new(*victim, true));
    metas.push(AccountMeta::new_readonly(system_program::ID, false));
    metas
}

#[test]
fn a_hook_whose_list_names_the_fee_payer_as_a_signer_cannot_take_its_sol() {
    let mut w = World::new();
    let payer = w.me();
    let mint = thief_mint(&mut w, &payer);
    let (from, to) = w.funded(&T22, &mint, 1_000);
    let counter_lamports = w.balance(&hook::counter_address(&mint));
    let (issued, expiry) = w.window();
    let action = action::transfer_token(&mint, &to, 300, issued, expiry);

    // the payer is the transaction's fee payer and the instruction's `payer`, and here once more
    // among the remaining accounts, marked as a writable signer
    let mut metas = four(&T22, &from, &to, &mint);
    metas.extend(thief_accounts(&mint, &payer));
    let before = w.balance(&payer);
    let e = w.direct(&action, metas.clone()).unwrap_err();
    assert_eq!(kind(e), InstructionError::PrivilegeEscalation, "the hook asked the System Program for a signature it does not have");
    assert_eq!(w.balance(&payer), before - FEE, "the payer lost the fee and nothing else");
    assert_eq!(w.balance(&hook::counter_address(&mint)), counter_lamports, "the hook got nothing");
    assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (1_000, 0, 0), "no token moved, no leaf spent");

    // the staged path, where the payer does not even sign the instruction for the vault's sake
    let staged = w.stage(&action);
    let before = w.balance(&payer);
    let e = w.execute(&staged, metas).unwrap_err();
    assert_eq!(kind(e), InstructionError::PrivilegeEscalation);
    assert_eq!(w.balance(&payer), before - FEE);
    assert_eq!(w.balance(&hook::counter_address(&mint)), counter_lamports);
    assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (1_000, 0, 0));

    // left out of the accounts, the payer is simply missing from what the list names
    let mut metas = four(&T22, &from, &to, &mint);
    metas.extend(hook::accounts(&mint));
    metas.push(AccountMeta::new_readonly(system_program::ID, false));
    let e = w.direct(&action, metas).unwrap_err();
    assert_eq!(custom(e), hook::ERR_LISTED_ACCOUNT_MISSING);
    assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (1_000, 0, 0));
}

#[test]
fn whoever_sweeps_a_strangers_hook_mint_keeps_their_sol() {
    // `sweep_closed` is for anyone to call, on a token the caller may know nothing about.
    let mut w = World::new();
    let payer = w.me();
    let mint = thief_mint(&mut w, &payer);
    let (account, _) = w.funded(&T22, &mint, 1_000);
    let counter_lamports = w.balance(&hook::counter_address(&mint));
    let heir = Keypair::new().pubkey();
    w.close(&heir);
    let before = w.balance(&payer);
    let e = w.sweep(&T22, &heir, &account, &mint, thief_accounts(&mint, &payer)).unwrap_err();
    assert_eq!(kind(e), InstructionError::PrivilegeEscalation);
    assert_eq!(w.balance(&payer), before - FEE, "the caller lost the fee and nothing else");
    assert_eq!(w.balance(&hook::counter_address(&mint)), counter_lamports);
    assert_eq!(w.amount(&account), 1_000);
    assert!(!w.exists(&ata_of(&T22, &heir, &mint)));
}

#[test]
fn a_second_signer_of_the_transaction_is_no_better_off_as_prey() {
    // not the fee payer this time: another key that signed the same transaction
    let mut w = World::new();
    let cosigner = Keypair::new();
    w.svm.airdrop(&cosigner.pubkey(), 5_000_000_000).unwrap();
    let mint = thief_mint(&mut w, &cosigner.pubkey());
    let (from, to) = w.funded(&T22, &mint, 1_000);
    let (issued, expiry) = w.window();
    let action = action::transfer_token(&mint, &to, 300, issued, expiry);
    let mut metas = four(&T22, &from, &to, &mint);
    metas.extend(thief_accounts(&mint, &cosigner.pubkey()));
    let e = w.direct_signed_by(&action, metas, &[&cosigner]).unwrap_err();
    assert_eq!(kind(e), InstructionError::PrivilegeEscalation);
    assert_eq!(w.balance(&cosigner.pubkey()), 5_000_000_000);
    assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (1_000, 0, 0));
}

#[test]
fn a_transaction_signer_among_the_remaining_accounts_reaches_the_hook_unsigned() {
    // The hook's list names two keys that signed the transaction: the fee payer, asked for as a
    // writable signer, and a second signer, asked for as neither. Both are passed as signers among
    // the remaining accounts. This hook steals nothing; it only looks. The fixture refuses any
    // transfer in which an account reaches it as a signer, so the transfer going through is the
    // hook itself saying that none did.
    //
    // (That the transfer goes through at all when the list asks for a signature is Token-2022
    // 11.0.0 demoting the entry; a release that passed the flag on would fail here with
    // PrivilegeEscalation, having been given no signature to pass. Either way no signature arrives.)
    let mut w = World::new();
    let payer = w.me();
    let second = Keypair::new();
    let mint = w.hook_mint(
        hook::ALLOW,
        &[Listed::Counter, Listed::Fixed { key: payer, signer: true, writable: true }, Listed::Fixed { key: second.pubkey(), signer: false, writable: false }],
    );
    let (from, to) = w.funded(&T22, &mint, 1_000);
    let (issued, expiry) = w.window();
    let action = action::transfer_token(&mint, &to, 300, issued, expiry);
    let mut metas = with_hook(&T22, &from, &to, &mint);
    metas.push(AccountMeta::new(payer, true));
    metas.push(AccountMeta::new_readonly(second.pubkey(), true));
    let before = w.balance(&payer);
    w.direct_signed_by(&action, metas, &[&second]).expect("the transfer goes through: no signer reached the hook");
    assert_eq!((w.amount(&from), w.amount(&to)), (700, 300));
    assert_eq!(w.balance(&payer), before - 2 * FEE, "two signatures' fee and nothing else");
    let seen = hook_ran_once_for(&w, &mint, 300);
    assert_eq!(seen.accounts, 8, "the six, then the two listed keys");
    assert_eq!(seen.after_counter, Some((false, true)), "the fee payer: there, writable as listed, unsigned");
}

#[test]
fn the_vaults_own_signature_stops_at_the_token_program() {
    // The hook's list names the vault itself, as a writable signer. The token program was given
    // the vault's signature for the authority; it hands the hook the authority unsigned and
    // read-only, and the same account again from the list no differently.
    let mut w = World::new();
    let vault = w.vault;
    let mint = w.hook_mint(hook::ALLOW, &[Listed::Counter, Listed::Fixed { key: vault, signer: true, writable: true }]);
    let (from, to) = w.funded(&T22, &mint, 1_000);
    let (issued, expiry) = w.window();
    let action = action::transfer_token(&mint, &to, 300, issued, expiry);
    let mut metas = with_hook(&T22, &from, &to, &mint);
    metas.push(AccountMeta::new(vault, false));
    w.direct(&action, metas).expect("the transfer goes through: the hook saw no signer");
    assert_eq!((w.amount(&from), w.amount(&to)), (700, 300));
    let seen = hook_ran_once_for(&w, &mint, 300);
    assert_eq!(seen.accounts, 7);
    assert_eq!(seen.after_counter, Some((false, false)), "the vault, from the list: unsigned and read-only");
}

#[test]
fn a_hook_cannot_call_back_into_the_vault() {
    // The hook's list names the vault program, and the hook invokes it. The runtime refuses to
    // enter a program that is already further up the call stack, so a hook cannot reach the vault
    // while the vault's own instruction is still running, whatever it would ask of it.
    let mut w = World::new();
    let mint = w.hook_mint(hook::CALL_BACK, &[Listed::Counter, Listed::Fixed { key: PROGRAM_ID, signer: false, writable: false }]);
    let (from, to) = w.funded(&T22, &mint, 1_000);
    let (issued, expiry) = w.window();
    let action = action::transfer_token(&mint, &to, 300, issued, expiry);
    let mut metas = with_hook(&T22, &from, &to, &mint);
    metas.push(AccountMeta::new_readonly(PROGRAM_ID, false));
    let e = w.direct(&action, metas.clone()).unwrap_err();
    assert_eq!(kind(e), InstructionError::ReentrancyNotAllowed);
    assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (1_000, 0, 0));
    // the same hook, calling a program that is not on the stack (the Memo program, which takes an
    // empty memo), is let through: the refusal above was the runtime's
    let memo = Pubkey::from_str_const("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
    let mint = w.hook_mint(hook::CALL_BACK, &[Listed::Counter, Listed::Fixed { key: memo, signer: false, writable: false }]);
    let (from, to) = w.funded(&T22, &mint, 1_000);
    let action = action::transfer_token(&mint, &to, 300, issued, expiry);
    let mut metas = with_hook(&T22, &from, &to, &mint);
    metas.push(AccountMeta::new_readonly(memo, false));
    w.direct(&action, metas).expect("a call to a program that is not on the stack");
    assert_eq!((w.amount(&from), w.amount(&to), w.spent()), (700, 300, 1));
}

// ---- mints without a hook ----

/// Accounts nobody needs: a stranger (writable), a hook's accounts for a mint that has no hook,
/// the system program, and the fee payer marked as a signer.
fn junk(w: &World, mint: &Pubkey) -> Vec<AccountMeta> {
    let mut metas = vec![AccountMeta::new(Keypair::new().pubkey(), false)];
    metas.extend(hook::accounts(mint));
    metas.push(AccountMeta::new_readonly(system_program::ID, false));
    metas.push(AccountMeta::new(w.me(), true));
    metas
}

#[test]
fn mints_without_a_hook_move_as_before_with_or_without_accounts_nobody_needs() {
    let mut w = World::new();
    let payer = w.me();
    let spl = w.mint(&TOKEN_PROGRAM_ID, &[], |_| vec![]);
    let plain = w.mint(&T22, &[], |_| vec![]);
    // the extension is there, but no program is set: nothing to call
    let hookless = w.mint(&T22, &[ExtensionType::TransferHook], |mint| {
        vec![t22::extension::transfer_hook::instruction::initialize(&T22, mint, Some(payer), None).unwrap()]
    });
    let heir = Keypair::new().pubkey();
    let mut accounts = vec![];
    for (name, program, mint) in [("SPL Token", TOKEN_PROGRAM_ID, spl), ("Token-2022", T22, plain), ("Token-2022, hook extension with no program", T22, hookless)] {
        let (from, to) = w.funded(&program, &mint, 1_000);
        let (issued, expiry) = w.window();
        // the four accounts and nothing else, as every client has sent them so far
        let action = action::transfer_token(&mint, &to, 100, issued, expiry);
        w.direct(&action, four(&program, &from, &to, &mint)).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let bare = w.units;
        // the same with accounts behind them that nobody needs
        let action = action::transfer_token(&mint, &to, 100, issued, expiry + 1);
        let mut metas = four(&program, &from, &to, &mint);
        metas.extend(junk(&w, &mint));
        w.direct(&action, metas).unwrap_or_else(|e| panic!("{name}, with junk: {e:?}"));
        println!("execute_direct, TransferToken, {name}: {bare} compute units, {} with five unneeded accounts", w.units);
        // and staged
        let action = action::transfer_token(&mint, &to, 100, issued, expiry + 2);
        let staged = w.stage(&action);
        let mut metas = four(&program, &from, &to, &mint);
        metas.extend(junk(&w, &mint));
        w.execute(&staged, metas).unwrap_or_else(|e| panic!("{name}, staged, with junk: {e:?}"));
        assert_eq!((w.amount(&from), w.amount(&to)), (700, 300), "{name}");
        accounts.push((name, program, mint, from));
    }
    assert_eq!(w.spent(), 9);

    // after a Close, the sweep: bare for one, with junk for the others
    w.close(&heir);
    for (i, (name, program, mint, account)) in accounts.into_iter().enumerate() {
        let extra = if i == 0 { vec![] } else { junk(&w, &mint) };
        w.sweep(&program, &heir, &account, &mint, extra.clone()).unwrap_or_else(|e| panic!("{name}: sweep: {e:?}"));
        assert_eq!(w.amount(&ata_of(&program, &heir, &mint)), 700, "{name}");
        assert!(!w.exists(&account), "{name}");
        // SPL Token goes again with junk: a second account of the closed vault
        if i == 0 {
            let vault = w.vault;
            let second = Keypair::new();
            let ixs = [
                system_instruction::create_account(&payer, &second.pubkey(), w.rent(165), 165, &program),
                t22::instruction::initialize_account3(&program, &second.pubkey(), &mint, &vault).unwrap(),
            ];
            w.send(&ixs, &[&second]).expect("a second SPL Token account for the closed vault");
            w.mint_to(&program, &mint, &second.pubkey(), 50);
            w.sweep(&program, &heir, &second.pubkey(), &mint, junk(&w, &mint)).unwrap_or_else(|e| panic!("{name}: sweep with junk: {e:?}"));
            assert_eq!(w.amount(&ata_of(&program, &heir, &mint)), 750, "{name}");
        }
    }
}
