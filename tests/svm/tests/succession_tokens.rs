//! Token-2022 extensions through a release: one test per extension that can matter when a vault
//! is released (`execute_succession`) and its token accounts are swept to the claim address
//! (`sweep_closed`). The mints and accounts are made by the real Token-2022 and associated-token
//! programs, with the instructions their own interface crates build.
//!
//! Two outcomes are acceptable, and each test pins which one an extension gives:
//! - the tokens arrive at the claim address's associated token account, or
//! - the sweep fails cleanly: the token program's own error comes back, nothing has moved, the
//!   release of everything else is unaffected, and the test shows what (if anything) unblocks it.
#![cfg(feature = "succession")]

use lamport_vault_svm_tests::succession::*;
use lamport_vault_svm_tests::*;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_system_interface::instruction as system_instruction;
use solana_transaction_error::TransactionError;
use spl_associated_token_account_interface::instruction::create_associated_token_account_idempotent;
use spl_token_2022_interface as t22;
use t22::error::TokenError;
use t22::extension::ExtensionType;
use t22::state::{Account as TokenAccount, AccountState, Mint};

const T22: Pubkey = TOKEN_2022_PROGRAM_ID;
const DECIMALS: u8 = 6;

struct World {
    b: Bench,
    /// The plan's claim address: a keypair here, so tests that need the heir to act can sign.
    heir: Keypair,
}

impl World {
    fn new() -> Self {
        let mut b = Bench::new();
        let heir = Keypair::new();
        b.svm.airdrop(&heir.pubkey(), 1_000_000_000).unwrap();
        World { b, heir }
    }

    fn payer(&self) -> Pubkey {
        self.b.payer.pubkey()
    }

    fn claim(&self) -> Pubkey {
        self.heir.pubkey()
    }

    /// A Token-2022 mint with `extensions`, each initialised by `init` before the mint itself.
    /// The payer is the mint authority and, when `freeze` is set, the freeze authority.
    fn mint(&mut self, extensions: &[ExtensionType], init: Vec<Instruction>, freeze: bool) -> Pubkey {
        let mint = Keypair::new();
        let payer = self.payer();
        let space = ExtensionType::try_calculate_account_len::<Mint>(extensions).unwrap();
        let mut ixs = vec![system_instruction::create_account(&payer, &mint.pubkey(), self.b.rent(space), space as u64, &T22)];
        ixs.extend(init);
        ixs.push(t22::instruction::initialize_mint2(&T22, &mint.pubkey(), &payer, freeze.then_some(&payer), DECIMALS).unwrap());
        self.b.send(&ixs, &[&mint]).expect("create the mint");
        mint.pubkey()
    }

    /// `owner`'s associated token account for `mint`, created if missing.
    fn ata(&mut self, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
        let ix = create_associated_token_account_idempotent(&self.payer(), owner, mint, &T22);
        self.b.send(&[ix], &[]).expect("create the associated token account");
        ata(owner, mint, &T22)
    }

    fn mint_to(&mut self, mint: &Pubkey, account: &Pubkey, amount: u64) {
        let ix = t22::instruction::mint_to(&T22, mint, account, &self.payer(), &[], amount).unwrap();
        self.b.send(&[ix], &[]).expect("mint_to");
    }

    /// The vault's associated token account for `mint`, holding `amount` minted straight into it.
    fn vault_tokens(&mut self, mint: &Pubkey, amount: u64) -> Pubkey {
        let vault = self.b.vault;
        let account = self.ata(&vault, mint);
        if amount > 0 {
            self.mint_to(mint, &account, amount);
        }
        account
    }

    /// Arms a plan to the claim address, lets the window and the waiting period pass, and releases
    /// the vault, closing the token accounts in `pairs` on the way.
    fn release_with(&mut self, pairs: &[(Pubkey, Pubkey)]) -> Result<(), TransactionError> {
        if !self.b.plan().is_armed() {
            let plan = Plan { claim: self.claim(), window_secs: MIN_WINDOW_SECS, wait_secs: MIN_WAIT_SECS, checkin_key: Pubkey::default(), contact_key: Pubkey::default() };
            self.b.set_plan(&plan).expect("arm");
            self.b.advance(90 * DAY + 1);
            self.b.start().expect("start");
            self.b.advance(30 * DAY);
        }
        let claim = self.claim();
        self.b.execute(&claim, pairs)
    }

    fn release(&mut self) {
        self.release_with(&[]).expect("release");
        assert!(self.b.is_tombstone());
    }

    /// `sweep_closed` of one of the closed vault's token accounts, with `extra` accounts for a hook.
    fn sweep_with(&mut self, account: &Pubkey, mint: &Pubkey, extra: Vec<AccountMeta>) -> Result<(), TransactionError> {
        let mut ix = sweep_closed_ix(&self.payer(), &self.b.vault, &self.claim(), account, mint, &T22);
        ix.accounts.extend(extra);
        self.b.send(&[ix], &[])
    }

    fn sweep(&mut self, account: &Pubkey, mint: &Pubkey) -> Result<(), TransactionError> {
        self.sweep_with(account, mint, vec![])
    }

    fn amount(&self, account: &Pubkey) -> u64 {
        token_amount(&self.b.data(account))
    }

    /// What the claim address holds of `mint`.
    fn arrived(&self, mint: &Pubkey) -> u64 {
        let account = ata(&self.claim(), mint, &T22);
        if self.b.account(&account).is_some() {
            self.amount(&account)
        } else {
            0
        }
    }
}

fn token_error(r: Result<(), TransactionError>) -> u32 {
    custom(r.expect_err("the sweep must fail"))
}

/// The sweep failed and left everything where it was.
fn nothing_moved(w: &World, account: &Pubkey, mint: &Pubkey, held: u64) {
    assert_eq!(w.amount(account), held, "the vault's token account still holds its balance");
    assert_eq!(w.arrived(mint), 0, "nothing reached the claim address");
    assert!(w.b.is_tombstone(), "the vault stays released");
}

// ---- extensions that do not stand in the way ----

#[test]
fn mint_extensions_that_do_not_touch_transfers_let_the_tokens_through() {
    let payer_of = |w: &World| w.payer();
    type Init = fn(&Pubkey, &Pubkey) -> Instruction;
    let cases: Vec<(&str, ExtensionType, Init)> = vec![
        ("mint close authority", ExtensionType::MintCloseAuthority, |mint, payer| t22::instruction::initialize_mint_close_authority(&T22, mint, Some(payer)).unwrap()),
        ("permanent delegate", ExtensionType::PermanentDelegate, |mint, payer| t22::instruction::initialize_permanent_delegate(&T22, mint, payer).unwrap()),
        ("interest bearing", ExtensionType::InterestBearingConfig, |mint, payer| t22::extension::interest_bearing_mint::instruction::initialize(&T22, mint, Some(*payer), 500).unwrap()),
        ("scaled ui amount", ExtensionType::ScaledUiAmount, |mint, payer| t22::extension::scaled_ui_amount::instruction::initialize(&T22, mint, Some(*payer), 2.5).unwrap()),
    ];
    for (name, extension, init) in cases {
        let mut w = World::new();
        let payer = payer_of(&w);
        // the mint's address has to be known to its own initialisers
        let mint_key = Keypair::new();
        let space = ExtensionType::try_calculate_account_len::<Mint>(&[extension]).unwrap();
        let ixs = vec![
            system_instruction::create_account(&payer, &mint_key.pubkey(), w.b.rent(space), space as u64, &T22),
            init(&mint_key.pubkey(), &payer),
            t22::instruction::initialize_mint2(&T22, &mint_key.pubkey(), &payer, None, DECIMALS).unwrap(),
        ];
        w.b.send(&ixs, &[&mint_key]).unwrap_or_else(|e| panic!("{name}: create the mint: {e:?}"));
        let mint = mint_key.pubkey();
        let account = w.vault_tokens(&mint, 1_000);
        w.release();
        w.sweep(&account, &mint).unwrap_or_else(|e| panic!("{name}: sweep: {e:?}"));
        assert_eq!(w.arrived(&mint), 1_000, "{name}");
        assert!(w.b.account(&account).is_none(), "{name}: the vault's account is closed");
    }
}

#[test]
fn an_empty_account_of_any_of_these_mints_is_closed_in_the_release() {
    let mut w = World::new();
    let mint = w.mint(&[], vec![], false);
    let account = w.vault_tokens(&mint, 0);
    let rent = w.b.balance(&account);
    let claim_before = w.b.balance(&w.claim());
    let vault_lamports = w.b.balance(&w.b.vault);
    w.release_with(&[(account, T22)]).expect("release, closing the empty account");
    assert!(w.b.account(&account).is_none());
    assert_eq!(w.b.balance(&w.claim()), claim_before + vault_lamports - w.b.rent(TOMBSTONE_SPACE) + rent);
}

// ---- transfer fee ----

/// A mint that withholds 1% of every transfer, and a vault account that has *received* a
/// transfer, so that it carries withheld fees of its own.
fn fee_world() -> (World, Pubkey, Pubkey) {
    let mut w = World::new();
    let payer = w.payer();
    let mint_key = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[ExtensionType::TransferFeeConfig]).unwrap();
    let ixs = vec![
        system_instruction::create_account(&payer, &mint_key.pubkey(), w.b.rent(space), space as u64, &T22),
        t22::extension::transfer_fee::instruction::initialize_transfer_fee_config(&T22, &mint_key.pubkey(), Some(&payer), Some(&payer), 100, u64::MAX).unwrap(),
        t22::instruction::initialize_mint2(&T22, &mint_key.pubkey(), &payer, None, DECIMALS).unwrap(),
    ];
    w.b.send(&ixs, &[&mint_key]).expect("a mint with a transfer fee");
    let mint = mint_key.pubkey();
    // someone pays the vault 500 000: 5 000 is withheld in the vault's account, 495 000 is its balance
    let from = w.ata(&payer, &mint);
    w.mint_to(&mint, &from, 1_000_000);
    let vault = w.b.vault;
    let account = w.ata(&vault, &mint);
    let pay = t22::extension::transfer_fee::instruction::transfer_checked_with_fee(&T22, &from, &mint, &account, &payer, &[], 500_000, DECIMALS, 5_000).unwrap();
    w.b.send(&[pay], &[]).expect("a transfer into the vault");
    assert_eq!(w.amount(&account), 495_000);
    (w, mint, account)
}

#[test]
fn transfer_fee_an_account_with_withheld_fees_is_swept_once_they_are_harvested() {
    let (mut w, mint, account) = fee_world();
    w.release();

    // the sweep moves the balance, then closes the account; Token-2022 refuses to close an account
    // that still holds withheld fees, so the whole sweep fails and nothing moves
    assert_eq!(token_error(w.sweep(&account, &mint)), TokenError::AccountHasWithheldTransferFees as u32);
    nothing_moved(&w, &account, &mint, 495_000);

    // anyone can harvest the withheld fees to the mint; no signature of the vault's is needed
    let harvest = t22::extension::transfer_fee::instruction::harvest_withheld_tokens_to_mint(&T22, &mint, &[&account]).unwrap();
    w.b.send(&[harvest], &[]).expect("harvest");
    w.sweep(&account, &mint).expect("sweep after the harvest");
    // the transfer to the claim address pays the fee too: 1% of 495 000
    assert_eq!(w.arrived(&mint), 495_000 - 4_950);
    assert!(w.b.account(&account).is_none());
}

#[test]
fn transfer_fee_harvest_and_sweep_fit_one_transaction() {
    let (mut w, mint, account) = fee_world();
    w.release();
    let harvest = t22::extension::transfer_fee::instruction::harvest_withheld_tokens_to_mint(&T22, &mint, &[&account]).unwrap();
    let sweep = sweep_closed_ix(&w.payer(), &w.b.vault, &w.claim(), &account, &mint, &T22);
    w.b.send(&[harvest, sweep], &[]).expect("harvest, then sweep");
    assert_eq!(w.arrived(&mint), 490_050);
}

#[test]
fn transfer_fee_an_emptied_account_with_withheld_fees_cannot_ride_along_in_the_release() {
    // The vault's owner moved the tokens out before going quiet, so the account is empty, but the
    // fees withheld in it are still there. Passing it to the release to be closed fails the
    // release; leaving it out releases the vault, and it is swept later like any other account.
    let (mut w, mint, account) = fee_world();
    let to = w.ata(&w.payer(), &mint);
    let (issued, expiry) = w.b.window();
    let out = action::transfer_token(&mint, &to, 495_000, issued, expiry);
    let metas = vec![AccountMeta::new(account, false), AccountMeta::new(to, false), AccountMeta::new_readonly(mint, false), AccountMeta::new_readonly(T22, false)];
    w.b.signed(&out, metas).expect("the owner empties the account");
    assert_eq!(w.amount(&account), 0);

    assert_eq!(custom(w.release_with(&[(account, T22)]).unwrap_err()), TokenError::AccountHasWithheldTransferFees as u32);
    assert!(!w.b.is_tombstone(), "the release did not happen");
    w.release_with(&[]).expect("the release without that account");
    assert!(w.b.is_tombstone());
    // afterwards: harvest, then the sweep closes it (there is nothing to move)
    let harvest = t22::extension::transfer_fee::instruction::harvest_withheld_tokens_to_mint(&T22, &mint, &[&account]).unwrap();
    w.b.send(&[harvest], &[]).unwrap();
    w.sweep(&account, &mint).expect("sweep closes the empty account");
    assert!(w.b.account(&account).is_none());
}

// ---- tokens that cannot move ----

#[test]
fn non_transferable_tokens_stay_where_they_are() {
    let mut w = World::new();
    let payer = w.payer();
    let mint_key = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[ExtensionType::NonTransferable]).unwrap();
    let ixs = vec![
        system_instruction::create_account(&payer, &mint_key.pubkey(), w.b.rent(space), space as u64, &T22),
        t22::instruction::initialize_non_transferable_mint(&T22, &mint_key.pubkey()).unwrap(),
        t22::instruction::initialize_mint2(&T22, &mint_key.pubkey(), &payer, None, DECIMALS).unwrap(),
    ];
    w.b.send(&ixs, &[&mint_key]).expect("a non-transferable mint");
    let mint = mint_key.pubkey();
    let account = w.vault_tokens(&mint, 100);
    let sol_before = w.b.balance(&w.claim());
    w.release();
    assert!(w.b.balance(&w.claim()) > sol_before, "the SOL was released all the same");

    assert_eq!(token_error(w.sweep(&account, &mint)), TokenError::NonTransferable as u32);
    nothing_moved(&w, &account, &mint, 100);
    // there is no way round it: the token is bound to the vault's address for good
    assert_eq!(token_error(w.sweep(&account, &mint)), TokenError::NonTransferable as u32);
}

#[test]
fn a_mint_whose_accounts_start_frozen_needs_the_issuer_to_thaw_the_heirs_account() {
    let mut w = World::new();
    let payer = w.payer();
    let mint_key = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[ExtensionType::DefaultAccountState]).unwrap();
    let ixs = vec![
        system_instruction::create_account(&payer, &mint_key.pubkey(), w.b.rent(space), space as u64, &T22),
        t22::extension::default_account_state::instruction::initialize_default_account_state(&T22, &mint_key.pubkey(), &AccountState::Frozen).unwrap(),
        t22::instruction::initialize_mint2(&T22, &mint_key.pubkey(), &payer, Some(&payer), DECIMALS).unwrap(),
    ];
    w.b.send(&ixs, &[&mint_key]).expect("a mint whose accounts start frozen");
    let mint = mint_key.pubkey();
    // the issuer thawed the vault's account once, so that it could hold the token at all
    let vault = w.b.vault;
    let account = w.ata(&vault, &mint);
    w.b.send(&[t22::instruction::thaw_account(&T22, &account, &mint, &payer, &[]).unwrap()], &[]).expect("thaw the vault's account");
    w.mint_to(&mint, &account, 100);
    w.release();

    // the sweep creates the heir's account, which starts frozen, and the transfer into it is refused
    assert_eq!(token_error(w.sweep(&account, &mint)), TokenError::AccountFrozen as u32);
    nothing_moved(&w, &account, &mint, 100);

    // once the issuer has thawed the heir's account the sweep goes through
    let claim = w.claim();
    let heirs = w.ata(&claim, &mint);
    w.b.send(&[t22::instruction::thaw_account(&T22, &heirs, &mint, &payer, &[]).unwrap()], &[]).expect("thaw the heir's account");
    w.sweep(&account, &mint).expect("sweep");
    assert_eq!(w.arrived(&mint), 100);
}

#[test]
fn a_frozen_vault_account_waits_for_the_issuer() {
    let mut w = World::new();
    let payer = w.payer();
    let mint = w.mint(&[], vec![], true);
    let account = w.vault_tokens(&mint, 100);
    w.b.send(&[t22::instruction::freeze_account(&T22, &account, &mint, &payer, &[]).unwrap()], &[]).expect("freeze");
    w.release();
    assert_eq!(token_error(w.sweep(&account, &mint)), TokenError::AccountFrozen as u32);
    nothing_moved(&w, &account, &mint, 100);
    w.b.send(&[t22::instruction::thaw_account(&T22, &account, &mint, &payer, &[]).unwrap()], &[]).expect("thaw");
    w.sweep(&account, &mint).expect("sweep");
    assert_eq!(w.arrived(&mint), 100);
}

#[test]
fn a_paused_mint_waits_until_it_is_resumed() {
    let mut w = World::new();
    let payer = w.payer();
    let mint_key = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[ExtensionType::Pausable]).unwrap();
    let ixs = vec![
        system_instruction::create_account(&payer, &mint_key.pubkey(), w.b.rent(space), space as u64, &T22),
        t22::extension::pausable::instruction::initialize(&T22, &mint_key.pubkey(), &payer).unwrap(),
        t22::instruction::initialize_mint2(&T22, &mint_key.pubkey(), &payer, None, DECIMALS).unwrap(),
    ];
    w.b.send(&ixs, &[&mint_key]).expect("a pausable mint");
    let mint = mint_key.pubkey();
    let account = w.vault_tokens(&mint, 100);
    w.b.send(&[t22::extension::pausable::instruction::pause(&T22, &mint, &payer, &[]).unwrap()], &[]).expect("pause");
    w.release();
    assert_eq!(token_error(w.sweep(&account, &mint)), TokenError::MintPaused as u32);
    nothing_moved(&w, &account, &mint, 100);
    w.b.send(&[t22::extension::pausable::instruction::resume(&T22, &mint, &payer, &[]).unwrap()], &[]).expect("resume");
    w.sweep(&account, &mint).expect("sweep");
    assert_eq!(w.arrived(&mint), 100);
}

#[test]
fn a_transfer_hook_whose_program_is_not_given_fails_cleanly() {
    let mut w = World::new();
    let payer = w.payer();
    let hook_program = Keypair::new().pubkey(); // a hook program that does not exist
    let mint_key = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[ExtensionType::TransferHook]).unwrap();
    let ixs = vec![
        system_instruction::create_account(&payer, &mint_key.pubkey(), w.b.rent(space), space as u64, &T22),
        t22::extension::transfer_hook::instruction::initialize(&T22, &mint_key.pubkey(), Some(payer), Some(hook_program)).unwrap(),
        t22::instruction::initialize_mint2(&T22, &mint_key.pubkey(), &payer, None, DECIMALS).unwrap(),
    ];
    w.b.send(&ixs, &[&mint_key]).expect("a mint with a transfer hook");
    let mint = mint_key.pubkey();
    let account = w.vault_tokens(&mint, 100);
    w.release();
    // without the hook's accounts the token program cannot run the hook, and refuses the transfer
    assert!(w.sweep(&account, &mint).is_err());
    nothing_moved(&w, &account, &mint, 100);
    // sweep_closed hands every extra account on to the token program, so a real hook's accounts
    // can be supplied; here the hook program itself does not exist, and the transfer still fails
    assert!(w.sweep_with(&account, &mint, vec![AccountMeta::new_readonly(hook_program, false)]).is_err());
    nothing_moved(&w, &account, &mint, 100);
}

// ---- what the heir set on their own account ----

#[test]
fn an_heir_who_requires_memos_on_incoming_transfers_has_to_switch_that_off() {
    let mut w = World::new();
    let mint = w.mint(&[], vec![], false);
    let account = w.vault_tokens(&mint, 100);
    let claim = w.claim();
    let heirs = w.ata(&claim, &mint);
    let payer = w.payer();
    let heir = w.heir.insecure_clone();
    // the heir's account gets the memo extension and turns it on
    let grow = t22::instruction::reallocate(&T22, &heirs, &payer, &claim, &[], &[ExtensionType::MemoTransfer]).unwrap();
    let require = t22::extension::memo_transfer::instruction::enable_required_transfer_memos(&T22, &heirs, &claim, &[]).unwrap();
    w.b.send(&[grow, require], &[&heir]).expect("require memos");
    w.release();

    assert_eq!(token_error(w.sweep(&account, &mint)), TokenError::NoMemo as u32);
    nothing_moved(&w, &account, &mint, 100);
    let relax = t22::extension::memo_transfer::instruction::disable_required_transfer_memos(&T22, &heirs, &claim, &[]).unwrap();
    w.b.send(&[relax], &[&heir]).expect("stop requiring memos");
    w.sweep(&account, &mint).expect("sweep");
    assert_eq!(w.arrived(&mint), 100);
}

#[test]
fn an_heirs_cpi_guard_does_not_stop_tokens_arriving() {
    let mut w = World::new();
    let mint = w.mint(&[], vec![], false);
    let account = w.vault_tokens(&mint, 100);
    let claim = w.claim();
    let heirs = w.ata(&claim, &mint);
    let payer = w.payer();
    let heir = w.heir.insecure_clone();
    let grow = t22::instruction::reallocate(&T22, &heirs, &payer, &claim, &[], &[ExtensionType::CpiGuard]).unwrap();
    let guard = t22::extension::cpi_guard::instruction::enable_cpi_guard(&T22, &heirs, &claim, &[]).unwrap();
    w.b.send(&[grow, guard], &[&heir]).expect("enable the CPI guard");
    w.release();
    w.sweep(&account, &mint).expect("sweep");
    assert_eq!(w.arrived(&mint), 100);
}

#[test]
fn the_accounts_the_token_program_makes_are_the_ones_the_vault_reads() {
    // The vault reads token accounts by offset rather than through the token program's own types.
    // Check that against an account Token-2022 made itself, extensions and all.
    let (w, mint, account) = fee_world();
    let data = w.b.data(&account);
    assert!(data.len() > 165, "an account with extensions is longer than the base layout");
    assert_eq!(data[165], 2, "account type byte: Account");
    assert_eq!(&data[..32], mint.as_ref());
    assert_eq!(&data[32..64], w.b.vault.as_ref());
    assert_eq!(token_amount(&data), 495_000);
    // the base layouts the vault assumes: 165 bytes for an account, 82 for a mint
    assert_eq!(ExtensionType::try_calculate_account_len::<TokenAccount>(&[]).unwrap(), 165);
    assert_eq!(ExtensionType::try_calculate_account_len::<Mint>(&[]).unwrap(), 82);
    let mint_data = w.b.data(&mint);
    assert_eq!(mint_data[165], 1, "account type byte: Mint");
    assert_eq!((mint_data[44], mint_data[45]), (DECIMALS, 1));
}
