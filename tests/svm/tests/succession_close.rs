//! `execute_succession` releases a vault by a copy of the `Close` path (the copy exists because
//! sharing the code would change the default build; docs/SUCCESSION.md). This holds the copy to
//! the original: from the same vault state, a release to the claim address and a signed
//! `Close { to: claim }` must leave every account the same, byte for byte and lamport for lamport,
//! and must refuse the same inputs with the same codes.
#![cfg(feature = "succession")]

use lamport_vault_svm_tests::succession::*;
use lamport_vault_svm_tests::*;
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;

/// Small deterministic generator (xorshift64*).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// An address fixed by the case, so both worlds hold the same accounts at the same places.
fn addr(case: u64, tag: u8) -> Pubkey {
    let mut b = [tag; 32];
    b[..8].copy_from_slice(&case.to_le_bytes());
    b[31] = 0x5A;
    Pubkey::new_from_array(b)
}

struct Case {
    claim: Pubkey,
    /// lamports the claim address holds beforehand (0: it does not exist yet)
    claim_funded: u64,
    extra_lamports: u64,
    /// token accounts owned by the vault: (address, program, mint, amount, passed in?)
    tokens: Vec<(Pubkey, Pubkey, Pubkey, u64, bool)>,
}

fn case(n: u64) -> Case {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15u64.wrapping_mul(n + 1) | 1);
    let claim = if rng.below(3) == 0 { Pubkey::find_program_address(&[b"plan", &n.to_le_bytes()], &ATA_PROGRAM_ID).0 } else { addr(n, 1) };
    let claim_funded = if rng.below(2) == 0 { 0 } else { 1_000_000 + rng.below(1_000_000_000) };
    let extra_lamports = rng.below(3_000_000_000);
    let mut tokens = vec![];
    for i in 0..rng.below(5) {
        let program = if rng.below(2) == 0 { TOKEN_PROGRAM_ID } else { TOKEN_2022_PROGRAM_ID };
        let amount = if rng.below(3) == 0 { 1 + rng.below(1_000_000) } else { 0 };
        // an account that holds tokens can only be left out: passing it is the refusal tested below
        let passed = amount == 0 && rng.below(4) != 0;
        tokens.push((addr(n, 10 + i as u8), program, addr(n, 30 + i as u8), amount, passed));
    }
    Case { claim, claim_funded, extra_lamports, tokens }
}

/// A vault in the state of `c`, armed to release to `c.claim`, with its waiting period over.
fn prepared(c: &Case) -> Bench {
    let mut b = Bench::new();
    let vault = b.vault;
    if c.claim_funded > 0 {
        b.svm.airdrop(&c.claim, c.claim_funded).unwrap();
    }
    if c.extra_lamports > 0 {
        b.svm.airdrop(&vault, c.extra_lamports).unwrap();
    }
    for (address, program, mint, amount, _) in &c.tokens {
        b.put(mint, program, mint_data(6, 1_000_000_000));
        b.token_account_at(address, program, mint, &vault, *amount);
    }
    let plan = Plan { claim: c.claim, window_secs: MIN_WINDOW_SECS, wait_secs: MIN_WAIT_SECS, checkin_key: Pubkey::default(), contact_key: Pubkey::default() };
    b.set_plan(&plan).expect("arm");
    b.advance(90 * DAY + 1);
    b.start().expect("start");
    b.advance(30 * DAY);
    b
}

fn pairs(c: &Case) -> Vec<(Pubkey, Pubkey)> {
    c.tokens.iter().filter(|t| t.4).map(|t| (t.0, t.1)).collect()
}

fn close_signed(b: &mut Bench, to: &Pubkey, pairs: &[(Pubkey, Pubkey)]) -> Result<(), TransactionError> {
    let (issued, expiry) = b.window();
    let mut remaining = vec![AccountMeta::new(*to, false)];
    for (account, program) in pairs {
        remaining.push(AccountMeta::new(*account, false));
        remaining.push(AccountMeta::new_readonly(*program, false));
    }
    b.signed(&action::close(to, issued, expiry), remaining)
}

/// Everything about an account that a release could change.
fn snapshot(b: &Bench, k: &Pubkey) -> Option<(u64, Vec<u8>, Pubkey)> {
    b.account(k).map(|a| (a.lamports, a.data, a.owner))
}

#[test]
fn a_release_and_a_signed_close_leave_identical_accounts() {
    for n in 0..120 {
        let c = case(n);
        let mut released = prepared(&c);
        let mut closed = prepared(&c);
        assert_eq!(released.vault, closed.vault);
        assert_eq!(snapshot(&released, &c.claim), snapshot(&closed, &c.claim), "case {n}: same start");
        let p = pairs(&c);

        released.execute(&c.claim, &p).unwrap_or_else(|e| panic!("case {n}: execute_succession: {e:?}"));
        close_signed(&mut closed, &c.claim, &p).unwrap_or_else(|e| panic!("case {n}: Close: {e:?}"));

        let vault = released.vault;
        assert!(released.is_tombstone() && closed.is_tombstone(), "case {n}");
        assert_eq!(snapshot(&released, &vault), snapshot(&closed, &vault), "case {n}: the tombstone");
        assert_eq!(snapshot(&released, &c.claim), snapshot(&closed, &c.claim), "case {n}: the claim address");
        for (address, _, mint, amount, passed) in &c.tokens {
            assert_eq!(snapshot(&released, address), snapshot(&closed, address), "case {n}: token account {address}");
            assert_eq!(snapshot(&released, mint), snapshot(&closed, mint), "case {n}: mint {mint}");
            assert_eq!(released.account(address).is_none(), *passed, "case {n}: closed exactly when passed");
            if !passed {
                assert_eq!(token_amount(&released.data(address)), *amount, "case {n}: left as it was");
            }
        }
    }
}

#[test]
fn a_release_and_a_signed_close_refuse_the_same_inputs_with_the_same_codes() {
    let c = Case {
        claim: addr(9_999, 1),
        claim_funded: 0,
        extra_lamports: 0,
        tokens: vec![
            (addr(9_999, 10), TOKEN_PROGRAM_ID, addr(9_999, 30), 0, false),
            (addr(9_999, 11), TOKEN_PROGRAM_ID, addr(9_999, 30), 5, false),
        ],
    };
    let stranger = Keypair::new().pubkey();
    let build = |c: &Case| {
        let mut b = prepared(c);
        // a token account that is not the vault's
        b.token_account_at(&addr(9_999, 12), &TOKEN_PROGRAM_ID, &addr(9_999, 30), &stranger, 0);
        b
    };
    let (empty, full, foreign) = (addr(9_999, 10), addr(9_999, 11), addr(9_999, 12));
    let inputs: Vec<(Vec<(Pubkey, Pubkey)>, u32, &str)> = vec![
        (vec![(full, TOKEN_PROGRAM_ID)], err::TOKEN_ACCOUNT_NOT_EMPTY, "an account that holds tokens"),
        (vec![(foreign, TOKEN_PROGRAM_ID)], err::NOT_VAULT_TOKEN_ACCOUNT, "an account that is not the vault's"),
        (vec![(empty, TOKEN_2022_PROGRAM_ID)], err::INVALID_TOKEN_PROGRAM, "the wrong token program for the account"),
        (vec![(empty, ATA_PROGRAM_ID)], err::INVALID_TOKEN_PROGRAM, "a program that is not a token program"),
        (vec![(empty, TOKEN_PROGRAM_ID), (full, TOKEN_PROGRAM_ID)], err::TOKEN_ACCOUNT_NOT_EMPTY, "a good pair, then a bad one"),
    ];
    for (p, expected, what) in inputs {
        let mut released = build(&c);
        let mut closed = build(&c);
        assert_eq!(custom(released.execute(&c.claim, &p).unwrap_err()), expected, "execute_succession: {what}");
        assert_eq!(custom(close_signed(&mut closed, &c.claim, &p).unwrap_err()), expected, "Close: {what}");
        assert!(!released.is_tombstone() && !closed.is_tombstone(), "{what}: nothing closed");
        assert_eq!(released.balance(&c.claim), 0, "{what}");
    }
}
