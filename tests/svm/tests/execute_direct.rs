//! `execute_direct` for every action, on chain in LiteSVM. The H5/W4 signature is 2348 bytes:
//! more than a wire transaction carries, which is why the validator suite cannot run this.
use lamport_lms::LmsPrivateKey;
use lamport_vault_svm_tests::*;
use litesvm::LiteSVM;
use solana_account::Account;
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

const SO: &str = "../../target/deploy/lamport_vault.so";
const FEE: u64 = 5_000; // one signature

struct Env {
    svm: LiteSVM,
    payer: Keypair,
    key: LmsPrivateKey,
    vault: Pubkey,
    generation: u32,
}

impl Env {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program_from_file(PROGRAM_ID, SO).expect("anchor build first: target/deploy/lamport_vault.so");
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        let key = h5_key(1);
        let pk = key.public_key().to_bytes();
        let vault_id = vault_id_for(&pk);
        let (vault, _) = vault_address(&vault_id);
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: create_vault_data(&vault_id, &pk),
        };
        let mut env = Env { svm, payer, key, vault, generation: 0 };
        env.send(&[ix], &[]).expect("create_vault");
        // fund it well above rent
        let fund = system_instruction::transfer(&env.payer.pubkey(), &env.vault, 5_000_000_000);
        env.send(&[fund], &[]).expect("fund");
        env
    }

    fn slot(&self) -> u64 {
        self.svm.get_sysvar::<Clock>().slot
    }

    fn send(&mut self, ixs: &[Instruction], extra: &[&Keypair]) -> Result<(), TransactionError> {
        let bh = self.svm.latest_blockhash();
        let msg = Message::new_with_blockhash(ixs, Some(&self.payer.pubkey()), &bh);
        let mut signers: Vec<&Keypair> = vec![&self.payer];
        signers.extend_from_slice(extra);
        let tx = Transaction::new(&signers, msg, bh);
        self.svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
    }

    fn vault_state(&self) -> VaultState {
        decode_vault(&self.svm.get_account(&self.vault).unwrap().data)
    }

    fn balance(&self, k: &Pubkey) -> u64 {
        self.svm.get_balance(k).unwrap_or(0)
    }

    /// Signs `action` with leaf `q` under the current generation.
    fn sign(&self, q: u32, action: &[u8]) -> Vec<u8> {
        self.key.sign(q, &signed_message(&self.vault, self.generation, action))
    }

    fn direct_ix(&self, action: &[u8], sig: &[u8], remaining: Vec<AccountMeta>) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(self.vault, false),
            AccountMeta::new(self.payer.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ];
        accounts.extend(remaining);
        Instruction { program_id: PROGRAM_ID, accounts, data: execute_direct_data(action, sig) }
    }

    fn execute_direct(&mut self, action: &[u8], sig: &[u8], remaining: Vec<AccountMeta>) -> Result<(), TransactionError> {
        let ixs = [ComputeBudgetInstruction::set_compute_unit_limit(400_000), self.direct_ix(action, sig, remaining)];
        self.send(&ixs, &[])
    }

    fn window(&self) -> (u64, u64) {
        let s = self.slot();
        (s, s + 300)
    }
}

fn custom(e: TransactionError) -> u32 {
    match e {
        TransactionError::InstructionError(_, InstructionError::Custom(c)) => c,
        other => panic!("not a program error: {other:?}"),
    }
}

/// A plain Token mint and two token accounts owned by `vault_owner` / `other_owner`, the first holding `amount`.
fn token_fixture(env: &mut Env, vault_owner: &Pubkey, other_owner: &Pubkey, amount: u64) -> (Pubkey, Pubkey, Pubkey) {
    let mint = Keypair::new();
    let src = Keypair::new();
    let dst = Keypair::new();
    let payer = env.payer.pubkey();
    let mint_rent = env.svm.minimum_balance_for_rent_exemption(82);
    let acc_rent = env.svm.minimum_balance_for_rent_exemption(165);
    let token_ix = |keys: Vec<AccountMeta>, data: Vec<u8>| Instruction { program_id: TOKEN_PROGRAM_ID, accounts: keys, data };
    // InitializeMint2 (tag 20): decimals, mint authority, no freeze authority
    let mut init_mint = vec![20u8, 6];
    init_mint.extend_from_slice(payer.as_ref());
    init_mint.push(0);
    // InitializeAccount3 (tag 18): owner
    let init_acc = |owner: &Pubkey| { let mut d = vec![18u8]; d.extend_from_slice(owner.as_ref()); d };
    // MintTo (tag 7): amount
    let mut mint_to = vec![7u8];
    mint_to.extend_from_slice(&amount.to_le_bytes());
    let ixs = vec![
        system_instruction::create_account(&payer, &mint.pubkey(), mint_rent, 82, &TOKEN_PROGRAM_ID),
        token_ix(vec![AccountMeta::new(mint.pubkey(), false)], init_mint),
        system_instruction::create_account(&payer, &src.pubkey(), acc_rent, 165, &TOKEN_PROGRAM_ID),
        token_ix(vec![AccountMeta::new(src.pubkey(), false), AccountMeta::new_readonly(mint.pubkey(), false)], init_acc(vault_owner)),
        system_instruction::create_account(&payer, &dst.pubkey(), acc_rent, 165, &TOKEN_PROGRAM_ID),
        token_ix(vec![AccountMeta::new(dst.pubkey(), false), AccountMeta::new_readonly(mint.pubkey(), false)], init_acc(other_owner)),
        token_ix(vec![AccountMeta::new(mint.pubkey(), false), AccountMeta::new(src.pubkey(), false), AccountMeta::new_readonly(payer, true)], mint_to),
    ];
    env.send(&ixs, &[&mint, &src, &dst]).expect("token fixture");
    (mint.pubkey(), src.pubkey(), dst.pubkey())
}

fn token_amount(acc: &Account) -> u64 {
    u64::from_le_bytes(acc.data[64..72].try_into().unwrap())
}

#[test]
fn transfer_sol_pays_the_recipient_and_only_the_fee_from_the_payer() {
    let mut env = Env::new();
    let to = Pubkey::new_unique();
    let (issued, expiry) = env.window();
    let action = action::transfer_sol(&to, 1_000_000, issued, expiry);
    let sig = env.sign(3, &action);
    assert_eq!(sig.len(), 2348);
    let payer_before = env.balance(&env.payer.pubkey());
    let vault_before = env.balance(&env.vault);
    env.execute_direct(&action, &sig, vec![AccountMeta::new(to, false)]).unwrap();
    assert_eq!(env.balance(&to), 1_000_000);
    assert_eq!(env.balance(&env.vault), vault_before - 1_000_000);
    assert_eq!(env.balance(&env.payer.pubkey()), payer_before - FEE);
    let v = env.vault_state();
    assert_eq!(v.spent, 1);
    assert!(v.is_used(3));
    assert_eq!(v.generation, 0);
}

#[test]
fn transfer_token_moves_the_balance() {
    let mut env = Env::new();
    let other = Pubkey::new_unique();
    let vault = env.vault;
    let (mint, src, dst) = token_fixture(&mut env, &vault, &other, 1_000_000);
    let (issued, expiry) = env.window();
    let action = action::transfer_token(&mint, &dst, 250_000, issued, expiry);
    let sig = env.sign(0, &action);
    let remaining = vec![
        AccountMeta::new(src, false),
        AccountMeta::new(dst, false),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
    ];
    env.execute_direct(&action, &sig, remaining.clone()).unwrap();
    assert_eq!(token_amount(&env.svm.get_account(&dst).unwrap()), 250_000);
    assert_eq!(token_amount(&env.svm.get_account(&src).unwrap()), 750_000);
    // the destination is bound to the signed action
    let action2 = action::transfer_token(&mint, &dst, 1, issued, expiry);
    let sig2 = env.sign(1, &action2);
    let (_, _, elsewhere) = token_fixture(&mut env, &vault, &other, 0);
    let wrong = vec![remaining[0].clone(), AccountMeta::new(elsewhere, false), remaining[2].clone(), remaining[3].clone()];
    let e = env.execute_direct(&action2, &sig2, wrong).unwrap_err();
    assert_eq!(custom(e), ERR_WRONG_DESTINATION);
    // the leaf was burnt before the destination check: nothing moved, q=1 is spent
    assert_eq!(token_amount(&env.svm.get_account(&dst).unwrap()), 250_000);
}

#[test]
fn rotate_with_the_payer_covering_the_rent_delta() {
    let mut env = Env::new();
    let new_key = h5_key(2);
    let new_pk = new_key.public_key().to_bytes();
    let old_pk = env.key.public_key().to_bytes();
    let (issued, expiry) = env.window();
    let action = action::rotate(&new_pk, issued, expiry);
    let sig = env.sign(31, &action); // the last leaf may Rotate
    let len_before = env.svm.get_account(&env.vault).unwrap().data.len();
    let delta = env.svm.minimum_balance_for_rent_exemption(len_before + 16) - env.svm.minimum_balance_for_rent_exemption(len_before);
    assert!(delta > 0);
    let payer_before = env.balance(&env.payer.pubkey());
    let vault_before = env.balance(&env.vault);
    env.execute_direct(&action, &sig, vec![]).unwrap();
    assert_eq!(env.balance(&env.payer.pubkey()), payer_before - FEE - delta);
    assert_eq!(env.balance(&env.vault), vault_before + delta);
    let acc = env.svm.get_account(&env.vault).unwrap();
    assert_eq!(acc.data.len(), len_before + 16);
    let v = decode_vault(&acc.data);
    assert_eq!(v.generation, 1);
    assert_eq!(v.spent, 0);
    assert!(v.used.iter().all(|b| *b == 0));
    assert_eq!(v.lms_pubkey, new_pk);
    assert_eq!(v.used_keys, vec![key_hash(&old_pk)]);
    // the new key signs under generation 1; the old key's signatures are dead
    env.key = new_key;
    env.generation = 1;
    let to = Pubkey::new_unique();
    let a2 = action::transfer_sol(&to, 1_000_000, issued, expiry);
    let s2 = env.sign(0, &a2);
    env.execute_direct(&a2, &s2, vec![AccountMeta::new(to, false)]).unwrap();
    assert_eq!(env.balance(&to), 1_000_000);
    let stale = h5_key(1).sign(5, &signed_message(&env.vault, 0, &a2));
    let e = env.execute_direct(&a2, &stale, vec![AccountMeta::new(to, false)]).unwrap_err();
    assert_eq!(custom(e), ERR_INVALID_SIGNATURE);
}

#[test]
fn close_leaves_a_tombstone_and_sends_the_rest() {
    let mut env = Env::new();
    let heir = Pubkey::new_unique();
    let (issued, expiry) = env.window();
    let action = action::close(&heir, issued, expiry);
    let sig = env.sign(7, &action);
    let vault_before = env.balance(&env.vault);
    let keep = env.svm.minimum_balance_for_rent_exemption(TOMBSTONE_SPACE);
    env.execute_direct(&action, &sig, vec![AccountMeta::new(heir, false)]).unwrap();
    assert_eq!(env.balance(&heir), vault_before - keep);
    let acc = env.svm.get_account(&env.vault).unwrap();
    assert_eq!(acc.lamports, keep);
    assert_eq!(acc.data.len(), TOMBSTONE_SPACE);
    assert_eq!(&acc.data[..8], &TOMBSTONE_DISC);
    assert_eq!(acc.data[8], 0xFE);
    assert_eq!(&acc.data[49..81], heir.as_ref());
    // a closed vault refuses everything
    let a2 = action::transfer_sol(&heir, 1_000_000, issued, expiry);
    let s2 = env.sign(8, &a2);
    let e = env.execute_direct(&a2, &s2, vec![AccountMeta::new(heir, false)]).unwrap_err();
    assert_eq!(custom(e), ERR_VAULT_CLOSED);
}

#[test]
fn a_leaf_spends_once_and_only_the_vaults_key_counts() {
    let mut env = Env::new();
    let to = Pubkey::new_unique();
    let (issued, expiry) = env.window();
    let action = action::transfer_sol(&to, 1_000_000, issued, expiry);
    let sig = env.sign(4, &action);
    let meta = vec![AccountMeta::new(to, false)];
    env.execute_direct(&action, &sig, meta.clone()).unwrap();
    // the same transaction bytes are refused by the blockhash dedup, so a fresh action with the same leaf
    let again = action::transfer_sol(&to, 1_000_001, issued, expiry);
    let sig_again = env.sign(4, &again);
    let e = env.execute_direct(&again, &sig_again, meta.clone()).unwrap_err();
    assert_eq!(custom(e), ERR_LEAF_ALREADY_USED);
    assert_eq!(env.balance(&to), 1_000_000);
    // another key of the same parameter set: verifies against the wrong root
    let foreign = h5_key(9).sign(6, &signed_message(&env.vault, 0, &again));
    let e = env.execute_direct(&again, &foreign, meta.clone()).unwrap_err();
    assert_eq!(custom(e), ERR_INVALID_SIGNATURE);
    assert!(!env.vault_state().is_used(6));
    // a signature whose typecodes do not match the vault's key
    let mut wrong_type = sig_again.clone();
    wrong_type[4..8].copy_from_slice(&4u32.to_be_bytes()); // LM-OTS W8 where W4 is expected
    let e = env.execute_direct(&again, &wrong_type, meta).unwrap_err();
    assert_eq!(custom(e), ERR_SIGNATURE_TYPE_MISMATCH);
    assert_eq!(env.vault_state().spent, 1);
}
