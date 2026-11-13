//! Wire formats of the succession feature, rebuilt by hand like the rest of this crate, and a test
//! bench: one vault on LiteSVM with a clock the test moves.
use lamport_lms::LmsPrivateKey;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_clock::Clock;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_system_interface::{instruction as system_instruction, program as system_program};
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

use crate::*;

pub const SO: &str = "../../target/deploy/lamport_vault.so";
pub const TOKEN_2022_PROGRAM_ID: Pubkey = Address::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ATA_PROGRAM_ID: Pubkey = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// One day of the succession clock, in seconds (`DAY_SECS` of a build without `short-clocks`).
pub const DAY: i64 = 86_400;
pub const MIN_WINDOW_SECS: u64 = 90 * 86_400;
pub const MIN_WAIT_SECS: u64 = 30 * 86_400;
pub const MAX_DURATION_SECS: u64 = 36_500 * 86_400;
pub const CHECKIN_CAP_SECS: i64 = 730 * DAY;
pub const CONTACT_EXTENSION_SECS: i64 = 90 * DAY;
/// Size of the succession block, and its offset in a vault account.
pub const BLOCK_LEN: usize = 200;
pub const BLOCK_OFFSET: usize = 114;

/// `SuccessionError`, declaration order from 6100; and the `VaultError` codes the release shares
/// with `Close`.
pub mod err {
    pub const NOT_ARMED: u32 = 6100;
    pub const WRONG_CHECKIN_KEY: u32 = 6101;
    pub const CHECKIN_PAST_CAP: u32 = 6102;
    pub const WRONG_CONTACT_KEY: u32 = 6103;
    pub const CONTACT_ALREADY_USED: u32 = 6104;
    pub const WAIT_ALREADY_OPEN: u32 = 6105;
    pub const BEFORE_DEADLINE: u32 = 6106;
    pub const NO_WAIT_OPEN: u32 = 6107;
    pub const WAIT_NOT_OVER: u32 = 6108;
    pub const WINDOW_OUT_OF_RANGE: u32 = 6109;
    pub const WAIT_OUT_OF_RANGE: u32 = 6110;
    pub const CLEAR_CARRIES_PLAN: u32 = 6111;
    pub const CLAIM_ACCOUNT_MISSING: u32 = 6112;
    pub const CLAIM_IS_THE_VAULT: u32 = 6113;
    pub const CLAIM_NOT_USABLE: u32 = 6114;
    pub const WRONG_CLAIM: u32 = 6115;
    pub const OVERFLOW: u32 = 6116;

    pub const LAST_LEAF_RESERVED: u32 = 6015;
    pub const MISSING_ACCOUNT: u32 = 6018;
    pub const INVALID_TOKEN_PROGRAM: u32 = 6021;
    pub const TOKEN_ACCOUNT_NOT_EMPTY: u32 = 6022;
    pub const VAULT_CLOSED: u32 = 6032;
    pub const VAULT_NOT_CLOSED: u32 = 6033;
    pub const WRONG_HEIR: u32 = 6034;
    pub const NOT_VAULT_TOKEN_ACCOUNT: u32 = 6036;
    pub const ANCHOR_ACCOUNT_NOT_SIGNER: u32 = 3010;
}

/// Anchor instruction discriminator, `sha256("global:<name>")[..8]`.
pub fn ix_disc(name: &str) -> [u8; 8] {
    let mut h = sha2::Sha256::new();
    sha2::Digest::update(&mut h, b"global:");
    sha2::Digest::update(&mut h, name.as_bytes());
    let out: [u8; 32] = sha2::Digest::finalize(h).into();
    out[..8].try_into().unwrap()
}

/// The succession block of a vault, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessionState {
    pub claim: Pubkey,
    pub window_secs: u64,
    pub wait_secs: u64,
    pub last_signed_ts: i64,
    pub last_checkin_ts: i64,
    pub checkin_key: Pubkey,
    pub contact_key: Pubkey,
    pub contact_used: bool,
    pub extended_until_ts: i64,
    pub wait_open: bool,
    pub wait_started_ts: i64,
    pub reserved: Vec<u8>,
}

impl SuccessionState {
    pub fn is_armed(&self) -> bool {
        self.claim != Pubkey::default()
    }
}

pub fn decode(b: &[u8]) -> SuccessionState {
    assert_eq!(b.len(), BLOCK_LEN);
    let key = |o: usize| Pubkey::new_from_array(b[o..o + 32].try_into().unwrap());
    let u = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let i = |o: usize| i64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    assert!(b[128] <= 1 && b[137] <= 1, "a bool is 0 or 1");
    SuccessionState {
        claim: key(0),
        window_secs: u(32),
        wait_secs: u(40),
        last_signed_ts: i(48),
        last_checkin_ts: i(56),
        checkin_key: key(64),
        contact_key: key(96),
        contact_used: b[128] == 1,
        extended_until_ts: i(129),
        wait_open: b[137] == 1,
        wait_started_ts: i(138),
        reserved: b[146..].to_vec(),
    }
}

/// A plan, as `SetSuccession` carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub claim: Pubkey,
    pub window_secs: u64,
    pub wait_secs: u64,
    pub checkin_key: Pubkey,
    pub contact_key: Pubkey,
}

impl Plan {
    /// The encoding that clears a plan: every field zero.
    pub fn clear() -> Self {
        Plan { claim: Pubkey::default(), window_secs: 0, wait_secs: 0, checkin_key: Pubkey::default(), contact_key: Pubkey::default() }
    }
}

/// Borsh `Action::SetSuccession`, variant 5, 129 bytes.
pub fn set_succession_action(p: &Plan, issued: u64, expiry: u64) -> Vec<u8> {
    let mut v = vec![5u8];
    v.extend_from_slice(p.claim.as_ref());
    v.extend_from_slice(&p.window_secs.to_le_bytes());
    v.extend_from_slice(&p.wait_secs.to_le_bytes());
    v.extend_from_slice(p.checkin_key.as_ref());
    v.extend_from_slice(p.contact_key.as_ref());
    v.extend_from_slice(&issued.to_le_bytes());
    v.extend_from_slice(&expiry.to_le_bytes());
    assert_eq!(v.len(), 129);
    v
}

pub fn checkin_ix(vault: &Pubkey, checkin_key: &Pubkey) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![AccountMeta::new(*vault, false), AccountMeta::new_readonly(*checkin_key, true)],
        data: ix_disc("checkin").to_vec(),
    }
}

pub fn contact_extend_ix(vault: &Pubkey, contact_key: &Pubkey) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![AccountMeta::new(*vault, false), AccountMeta::new_readonly(*contact_key, true)],
        data: ix_disc("contact_extend").to_vec(),
    }
}

pub fn start_succession_ix(vault: &Pubkey) -> Instruction {
    Instruction { program_id: PROGRAM_ID, accounts: vec![AccountMeta::new(*vault, false)], data: ix_disc("start_succession").to_vec() }
}

/// `execute_succession`: the vault, the claim account, then `[token account, token program]` pairs.
pub fn execute_succession_ix(vault: &Pubkey, claim: &Pubkey, pairs: &[(Pubkey, Pubkey)]) -> Instruction {
    let mut accounts = vec![AccountMeta::new(*vault, false), AccountMeta::new(*claim, false)];
    for (account, program) in pairs {
        accounts.push(AccountMeta::new(*account, false));
        accounts.push(AccountMeta::new_readonly(*program, false));
    }
    Instruction { program_id: PROGRAM_ID, accounts, data: ix_disc("execute_succession").to_vec() }
}

pub fn sweep_closed_sol_ix(tombstone: &Pubkey, heir: &Pubkey) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![AccountMeta::new(*tombstone, false), AccountMeta::new(*heir, false)],
        data: ix_disc("sweep_closed_sol").to_vec(),
    }
}

/// The associated token account of `owner` for `mint` under `token_program`.
pub fn ata(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[owner.as_ref(), token_program.as_ref(), mint.as_ref()], &ATA_PROGRAM_ID).0
}

pub fn sweep_closed_ix(payer: &Pubkey, tombstone: &Pubkey, heir: &Pubkey, vault_token_account: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*tombstone, false),
            AccountMeta::new(*heir, false),
            AccountMeta::new(ata(heir, mint, token_program), false),
            AccountMeta::new(*vault_token_account, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*token_program, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(ATA_PROGRAM_ID, false),
        ],
        data: ix_disc("sweep_closed").to_vec(),
    }
}

/// SPL Mint, 82 bytes: no authorities, `decimals` at 44, `is_initialized` at 45.
pub fn mint_data(decimals: u8, supply: u64) -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[36..44].copy_from_slice(&supply.to_le_bytes());
    d[44] = decimals;
    d[45] = 1;
    d
}

/// SPL token Account, 165 bytes: mint, owner, amount, state Initialized at 108.
pub fn token_account_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d
}

pub fn token_amount(data: &[u8]) -> u64 {
    u64::from_le_bytes(data[64..72].try_into().unwrap())
}

/// The custom program error a transaction failed with.
pub fn custom(e: TransactionError) -> u32 {
    match e {
        TransactionError::InstructionError(_, InstructionError::Custom(c)) => c,
        other => panic!("not a program error: {other:?}"),
    }
}

pub const FEE: u64 = 5_000;
pub const T0: i64 = 1_800_000_000;

/// One H5 vault of the Heir-enabled program on LiteSVM, funded, with the clock at [`T0`].
pub struct Bench {
    pub svm: LiteSVM,
    pub payer: Keypair,
    pub key: LmsPrivateKey,
    pub vault: Pubkey,
    pub generation: u32,
    /// The next leaf `signed` will use.
    pub next_leaf: u32,
}

impl Bench {
    pub fn new() -> Self {
        Self::with_key(1)
    }

    pub fn with_key(seed_byte: u8) -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program_from_file(PROGRAM_ID, SO).expect("build first: anchor build -- --features succession");
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
        let key = h5_key(seed_byte);
        let pk = key.public_key().to_bytes();
        let vault_id = vault_id_for(&pk);
        let (vault, _) = vault_address(&vault_id);
        let mut b = Bench { svm, payer, key, vault, generation: 0, next_leaf: 0 };
        b.set_time(T0);
        let create = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(b.payer.pubkey(), true),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: create_vault_data(&vault_id, &pk),
        };
        b.send(&[create], &[]).expect("create_vault");
        let fund = system_instruction::transfer(&b.payer.pubkey(), &vault, 5_000_000_000);
        b.send(&[fund], &[]).expect("fund");
        b
    }

    pub fn now(&self) -> i64 {
        self.svm.get_sysvar::<Clock>().unix_timestamp
    }

    pub fn slot(&self) -> u64 {
        self.svm.get_sysvar::<Clock>().slot
    }

    pub fn set_time(&mut self, unix_timestamp: i64) {
        let mut clock = self.svm.get_sysvar::<Clock>();
        clock.unix_timestamp = unix_timestamp;
        self.svm.set_sysvar::<Clock>(&clock);
    }

    pub fn advance(&mut self, secs: i64) {
        let t = self.now() + secs;
        self.set_time(t);
    }

    pub fn rent(&self, len: usize) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(len)
    }

    pub fn balance(&self, k: &Pubkey) -> u64 {
        self.svm.get_balance(k).unwrap_or(0)
    }

    pub fn account(&self, k: &Pubkey) -> Option<Account> {
        self.svm.get_account(k).filter(|a| a.lamports > 0)
    }

    pub fn data(&self, k: &Pubkey) -> Vec<u8> {
        self.svm.get_account(k).map(|a| a.data).unwrap_or_default()
    }

    /// Writes an account, rent-exempt for its size.
    pub fn put(&mut self, k: &Pubkey, owner: &Pubkey, data: Vec<u8>) {
        let lamports = self.rent(data.len());
        self.svm.set_account(*k, Account { lamports, data, owner: *owner, executable: false, rent_epoch: 0 }).unwrap();
    }

    pub fn vault_state(&self) -> VaultState {
        decode_vault(&self.data(&self.vault))
    }

    /// The vault's succession block.
    pub fn plan(&self) -> SuccessionState {
        self.vault_state().succession
    }

    pub fn is_tombstone(&self) -> bool {
        self.data(&self.vault).get(..8) == Some(&TOMBSTONE_DISC[..])
    }

    /// Signs with the payer and `extra`, sends, and moves to a fresh blockhash so the same
    /// instructions can be sent again.
    pub fn send(&mut self, ixs: &[Instruction], extra: &[&Keypair]) -> Result<(), TransactionError> {
        let bh = self.svm.latest_blockhash();
        let msg = Message::new_with_blockhash(ixs, Some(&self.payer.pubkey()), &bh);
        let mut signers: Vec<&Keypair> = vec![&self.payer];
        signers.extend_from_slice(extra);
        let tx = Transaction::new(&signers, msg, bh);
        let r = self.svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err);
        self.svm.expire_blockhash();
        r
    }

    /// A validity window that holds now.
    pub fn window(&self) -> (u64, u64) {
        let s = self.slot();
        (s, s + 300)
    }

    /// Signs `action` with leaf `q` and sends it through `execute_direct`.
    pub fn signed_with_leaf(&mut self, q: u32, action: &[u8], remaining: Vec<AccountMeta>) -> Result<(), TransactionError> {
        let sig = self.key.sign(q, &signed_message(&self.vault, self.generation, action));
        let mut accounts = vec![
            AccountMeta::new(self.vault, false),
            AccountMeta::new(self.payer.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ];
        accounts.extend(remaining);
        let ix = Instruction { program_id: PROGRAM_ID, accounts, data: execute_direct_data(action, &sig) };
        self.send(&[ComputeBudgetInstruction::set_compute_unit_limit(400_000), ix], &[])
    }

    /// Signs `action` with the next free leaf. The leaf is spent only if the action executes.
    pub fn signed(&mut self, action: &[u8], remaining: Vec<AccountMeta>) -> Result<(), TransactionError> {
        let r = self.signed_with_leaf(self.next_leaf, action, remaining);
        if r.is_ok() {
            self.next_leaf += 1;
        }
        r
    }

    /// `SetSuccession` for `plan`, with the claim account passed unless the plan is a clear.
    pub fn set_plan(&mut self, plan: &Plan) -> Result<(), TransactionError> {
        let (issued, expiry) = self.window();
        let action = set_succession_action(plan, issued, expiry);
        let remaining = if plan.claim == Pubkey::default() { vec![] } else { vec![AccountMeta::new_readonly(plan.claim, false)] };
        self.signed(&action, remaining)
    }

    /// A small signed transfer: any signed action will do as a sign of life.
    pub fn sign_of_life(&mut self) -> Result<(), TransactionError> {
        let to = Keypair::new().pubkey();
        let (issued, expiry) = self.window();
        let action = action::transfer_sol(&to, 1_000_000, issued, expiry);
        self.signed(&action, vec![AccountMeta::new(to, false)])
    }

    pub fn checkin(&mut self, key: &Keypair) -> Result<(), TransactionError> {
        let ix = checkin_ix(&self.vault, &key.pubkey());
        self.send(&[ix], &[key])
    }

    pub fn contact_extend(&mut self, key: &Keypair) -> Result<(), TransactionError> {
        let ix = contact_extend_ix(&self.vault, &key.pubkey());
        self.send(&[ix], &[key])
    }

    pub fn start(&mut self) -> Result<(), TransactionError> {
        let ix = start_succession_ix(&self.vault);
        self.send(&[ix], &[])
    }

    pub fn execute(&mut self, claim: &Pubkey, pairs: &[(Pubkey, Pubkey)]) -> Result<(), TransactionError> {
        let ix = execute_succession_ix(&self.vault, claim, pairs);
        self.send(&[ix], &[])
    }

    /// A mint under `token_program`, written directly.
    pub fn mint(&mut self, token_program: &Pubkey, decimals: u8) -> Pubkey {
        let mint = Keypair::new().pubkey();
        self.put(&mint, token_program, mint_data(decimals, 1_000_000_000_000));
        mint
    }

    /// A token account for `mint` owned by `owner`, holding `amount`, at `address`.
    pub fn token_account_at(&mut self, address: &Pubkey, token_program: &Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) {
        self.put(address, token_program, token_account_data(mint, owner, amount));
    }

    /// A token account for `mint` owned by `owner` at a fresh address.
    pub fn token_account(&mut self, token_program: &Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) -> Pubkey {
        let k = Keypair::new().pubkey();
        self.token_account_at(&k, token_program, mint, owner, amount);
        k
    }
}

impl Default for Bench {
    fn default() -> Self {
        Self::new()
    }
}
