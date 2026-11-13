//! The succession clock on chain, in LiteSVM: `SetSuccession`, `checkin`, `contact_extend`,
//! `start_succession`, `execute_succession`, with a clock the tests move. Each instruction has its
//! refusals next to it.
#![cfg(feature = "succession")]

use lamport_vault_svm_tests::succession::*;
use lamport_vault_svm_tests::*;
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;

const SOL: u64 = 1_000_000_000;

struct World {
    b: Bench,
    claim: Pubkey,
    checkin: Keypair,
    contact: Keypair,
    stranger: Keypair,
}

fn world() -> World {
    World { b: Bench::new(), claim: Keypair::new().pubkey(), checkin: Keypair::new(), contact: Keypair::new(), stranger: Keypair::new() }
}

impl World {
    fn plan(&self, window_days: u64, wait_days: u64) -> Plan {
        Plan {
            claim: self.claim,
            window_secs: window_days * DAY as u64,
            wait_secs: wait_days * DAY as u64,
            checkin_key: self.checkin.pubkey(),
            contact_key: self.contact.pubkey(),
        }
    }
    /// Arms `window`/`wait` at the current time and returns that time.
    fn arm(&mut self, window_days: u64, wait_days: u64) -> i64 {
        let p = self.plan(window_days, wait_days);
        self.b.set_plan(&p).expect("SetSuccession");
        self.b.now()
    }
}

fn code(r: Result<(), TransactionError>) -> u32 {
    custom(r.expect_err("expected a refusal"))
}

// ---- the block and SetSuccession ----

#[test]
fn a_new_vault_is_version_3_with_an_empty_block() {
    let b = Bench::new();
    let v = b.vault_state();
    assert_eq!(v.version, 3);
    let data = b.data(&b.vault);
    assert_eq!(data.len(), 126 + BLOCK_LEN, "an H5 vault with no history, plus the block");
    assert!(data[BLOCK_OFFSET..BLOCK_OFFSET + BLOCK_LEN].iter().all(|x| *x == 0), "all zero until armed");
    assert!(!v.succession.is_armed());
    assert_eq!(b.balance(&b.vault), b.rent(data.len()) + 5 * SOL);
}

#[test]
fn set_succession_arms_the_plan_and_starts_the_clock() {
    let mut w = world();
    w.b.advance(1_000);
    let armed_at = w.arm(365, 60);
    let s = w.b.plan();
    assert_eq!(s.claim, w.claim);
    assert_eq!((s.window_secs, s.wait_secs), (365 * 86_400, 60 * 86_400));
    assert_eq!((s.checkin_key, s.contact_key), (w.checkin.pubkey(), w.contact.pubkey()));
    assert_eq!(s.last_signed_ts, armed_at);
    assert_eq!((s.last_checkin_ts, s.extended_until_ts, s.wait_started_ts), (0, 0, 0));
    assert!(!s.contact_used && !s.wait_open);
    assert!(s.reserved.iter().all(|x| *x == 0));
    assert_eq!(w.b.vault_state().spent, 1, "one leaf, like any signed action");
}

#[test]
fn a_plan_is_changed_at_once_and_cleared_with_one_encoding() {
    let mut w = world();
    w.arm(365, 60);
    // a new claim address, the shortest clock, no keys
    let other = Keypair::new().pubkey();
    w.b.advance(10 * DAY);
    let changed = Plan { claim: other, window_secs: MIN_WINDOW_SECS, wait_secs: MIN_WAIT_SECS, checkin_key: Pubkey::default(), contact_key: Pubkey::default() };
    w.b.set_plan(&changed).expect("change");
    let s = w.b.plan();
    assert_eq!((s.claim, s.window_secs, s.wait_secs), (other, MIN_WINDOW_SECS, MIN_WAIT_SECS));
    assert_eq!((s.checkin_key, s.contact_key), (Pubkey::default(), Pubkey::default()));
    assert_eq!(s.last_signed_ts, w.b.now());

    // a clear that still carries a window is refused; the canonical clear disarms
    let dirty = Plan { window_secs: MIN_WINDOW_SECS, ..Plan::clear() };
    assert_eq!(code(w.b.set_plan(&dirty)), err::CLEAR_CARRIES_PLAN);
    w.b.set_plan(&Plan::clear()).expect("clear");
    let s = w.b.plan();
    assert!(!s.is_armed());
    assert_eq!((s.window_secs, s.wait_secs), (0, 0));
    w.b.advance(10_000 * DAY);
    assert_eq!(code(w.b.start()), err::NOT_ARMED);
}

#[test]
fn window_and_wait_have_floors_and_a_ceiling() {
    let mut w = world();
    let base = w.plan(90, 30);
    let cases = [
        (Plan { window_secs: MIN_WINDOW_SECS - 1, ..base.clone() }, err::WINDOW_OUT_OF_RANGE),
        (Plan { window_secs: MAX_DURATION_SECS + 1, ..base.clone() }, err::WINDOW_OUT_OF_RANGE),
        (Plan { window_secs: u64::MAX, ..base.clone() }, err::WINDOW_OUT_OF_RANGE),
        (Plan { wait_secs: MIN_WAIT_SECS - 1, ..base.clone() }, err::WAIT_OUT_OF_RANGE),
        (Plan { wait_secs: 0, ..base.clone() }, err::WAIT_OUT_OF_RANGE),
        (Plan { wait_secs: MAX_DURATION_SECS + 1, ..base.clone() }, err::WAIT_OUT_OF_RANGE),
    ];
    for (plan, expected) in cases {
        assert_eq!(code(w.b.set_plan(&plan)), expected, "{plan:?}");
    }
    assert!(!w.b.plan().is_armed(), "nothing was armed");
    assert_eq!(w.b.vault_state().spent, 0, "and no leaf was spent: the transactions failed whole");
    w.b.set_plan(&base).expect("the floors themselves");
    w.b.set_plan(&Plan { window_secs: MAX_DURATION_SECS, wait_secs: MAX_DURATION_SECS, ..base }).expect("the ceiling itself");
}

#[test]
fn the_claim_account_must_be_shown_and_must_be_able_to_receive() {
    let mut w = world();
    let vault = w.b.vault;
    let (issued, expiry) = w.b.window();
    let plan = w.plan(365, 60);
    let action = set_succession_action(&plan, issued, expiry);

    // not passed, or another account passed in its place
    assert_eq!(code(w.b.signed(&action, vec![])), err::CLAIM_ACCOUNT_MISSING);
    let other = Keypair::new().pubkey();
    assert_eq!(code(w.b.signed(&action, vec![AccountMeta::new_readonly(other, false)])), err::CLAIM_ACCOUNT_MISSING);

    let mint = w.b.mint(&TOKEN_PROGRAM_ID, 6);
    let token_account = w.b.token_account(&TOKEN_PROGRAM_ID, &mint, &vault, 0);
    let mint22 = w.b.mint(&TOKEN_2022_PROGRAM_ID, 6);
    let clock_sysvar = solana_sysvar::clock::ID;
    // a tombstone of this program: another vault, closed
    let mut closed = Bench::with_key(7);
    let heir = Keypair::new().pubkey();
    let (i2, e2) = closed.window();
    closed.signed(&action::close(&heir, i2, e2), vec![AccountMeta::new(heir, false)]).expect("close the other vault");
    let tombstone = closed.vault;
    w.b.put(&tombstone, &PROGRAM_ID, closed.data(&closed.vault));

    let refused: [(Pubkey, u32, &str); 6] = [
        (vault, err::CLAIM_IS_THE_VAULT, "the vault itself"),
        (TOKEN_PROGRAM_ID, err::CLAIM_NOT_USABLE, "a program"),
        (token_account, err::CLAIM_NOT_USABLE, "a token account"),
        (mint22, err::CLAIM_NOT_USABLE, "a Token-2022 mint"),
        (clock_sysvar, err::CLAIM_NOT_USABLE, "a sysvar"),
        (tombstone, err::CLAIM_NOT_USABLE, "a closed vault of this program"),
    ];
    for (claim, expected, what) in refused {
        let p = Plan { claim, ..plan.clone() };
        assert_eq!(code(w.b.set_plan(&p)), expected, "{what}");
    }
    assert!(!w.b.plan().is_armed());

    // what is allowed: an address with nothing at it, a funded wallet, another program's account,
    // and another open vault of this program
    let empty = Keypair::new().pubkey();
    let wallet = Keypair::new().pubkey();
    w.b.svm.airdrop(&wallet, SOL).unwrap();
    let foreign = Keypair::new().pubkey();
    w.b.put(&foreign, &ATA_PROGRAM_ID, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    let backup = Bench::with_key(9);
    w.b.put(&backup.vault, &PROGRAM_ID, backup.data(&backup.vault));
    for (claim, what) in [(empty, "an empty address"), (wallet, "a wallet"), (foreign, "another program's account"), (backup.vault, "another open vault")] {
        let p = Plan { claim, ..plan.clone() };
        w.b.set_plan(&p).unwrap_or_else(|e| panic!("{what}: {e:?}"));
        assert_eq!(w.b.plan().claim, claim, "{what}");
    }
}

#[test]
fn two_vaults_cannot_name_each_other() {
    // If vault A released to vault B and B released back to A, each tombstone would name the other
    // and the funds would pass between them for ever. Whichever of the two plans is signed second
    // is refused.
    let mut w = world();
    let this_vault = w.b.vault;
    let plan = w.plan(90, 30);
    // another vault of this program, built in its own VM, whose plan already names this one
    let mut other = Bench::with_key(7);
    other.set_plan(&Plan { claim: this_vault, ..plan.clone() }).expect("the first of the two plans is an ordinary one");
    assert_eq!(other.plan().claim, this_vault);
    w.b.put(&other.vault, &PROGRAM_ID, other.data(&other.vault));

    let spent = w.b.vault_state().spent;
    assert_eq!(code(w.b.set_plan(&Plan { claim: other.vault, ..plan.clone() })), err::CLAIM_NOT_USABLE);
    assert!(!w.b.plan().is_armed());
    assert_eq!(w.b.vault_state().spent, spent, "and the refusal costs no leaf");

    // once the other vault names somebody else, it is an ordinary claim address again
    other.set_plan(&Plan { claim: Keypair::new().pubkey(), ..plan.clone() }).unwrap();
    w.b.put(&other.vault, &PROGRAM_ID, other.data(&other.vault));
    w.b.set_plan(&Plan { claim: other.vault, ..plan.clone() }).expect("a vault that names somebody else");
}

#[test]
fn the_ids_of_loaders_and_of_the_sysvar_owner_are_not_claim_addresses() {
    // No account exists at these addresses, so they look like unused wallets; nothing can ever be
    // credited to them.
    let mut w = world();
    let plan = w.plan(90, 30);
    for id in ["Sysvar1111111111111111111111111111111111111", "NativeLoader1111111111111111111111111111111", "LoaderV411111111111111111111111111111111111"] {
        let claim = Pubkey::from_str_const(id);
        assert_eq!(code(w.b.set_plan(&Plan { claim, ..plan.clone() })), err::CLAIM_NOT_USABLE, "{id}");
    }
    assert!(!w.b.plan().is_armed());
}

#[test]
fn the_last_free_leaf_cannot_set_a_plan() {
    let mut w = world();
    // mark 31 of the 32 leaves spent, as 31 signed actions would have
    let mut data = w.b.data(&w.b.vault);
    data[98..102].copy_from_slice(&31u32.to_le_bytes());
    let bitmap = BLOCK_OFFSET + BLOCK_LEN + 4;
    data[bitmap..bitmap + 4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0x7F]);
    let lamports = w.b.balance(&w.b.vault);
    w.b.svm.set_account(w.b.vault, solana_account::Account { lamports, data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 }).unwrap();
    assert_eq!(w.b.vault_state().spent, 31);
    let (issued, expiry) = w.b.window();
    let action = set_succession_action(&w.plan(365, 60), issued, expiry);
    let claim = w.claim;
    assert_eq!(code(w.b.signed_with_leaf(31, &action, vec![AccountMeta::new_readonly(claim, false)])), err::LAST_LEAF_RESERVED);
}

#[test]
fn every_signed_action_is_a_sign_of_life_and_the_plan_survives_rotate() {
    let mut w = world();
    let armed_at = w.arm(90, 30);
    let plan_before = w.b.plan();

    // a transfer, 50 days on
    w.b.set_time(armed_at + 50 * DAY);
    w.b.sign_of_life().expect("transfer");
    assert_eq!(w.b.plan().last_signed_ts, armed_at + 50 * DAY);

    // a rotation, 60 days on: the key changes, the bitmap clears, the block stays
    w.b.set_time(armed_at + 60 * DAY);
    let new_key = h5_key(2);
    let (issued, expiry) = w.b.window();
    let len_before = w.b.data(&w.b.vault).len();
    w.b.signed(&action::rotate(&new_key.public_key().to_bytes(), issued, expiry), vec![]).expect("rotate");
    w.b.key = new_key;
    w.b.generation = 1;
    w.b.next_leaf = 0;
    let v = w.b.vault_state();
    assert_eq!(w.b.data(&w.b.vault).len(), len_before + 16);
    assert_eq!((v.generation, v.spent, v.used_keys.len()), (1, 0, 1));
    let s = v.succession;
    assert_eq!(s.last_signed_ts, armed_at + 60 * DAY, "a rotation is a signed action too");
    assert_eq!(SuccessionState { last_signed_ts: plan_before.last_signed_ts, ..s }, plan_before, "nothing else in the block moved");

    // and the clock runs from the rotation
    w.b.set_time(armed_at + 150 * DAY);
    assert_eq!(code(w.b.start()), err::BEFORE_DEADLINE);
    w.b.set_time(armed_at + 150 * DAY + 1);
    w.b.start().expect("start after the window");
    // the new key cancels it
    w.b.sign_of_life().expect("transfer under the new key");
    assert!(!w.b.plan().wait_open);
}

// ---- checkin ----

#[test]
fn a_check_in_counts_as_activity_and_anyone_may_pay_for_it() {
    let mut w = world();
    let armed_at = w.arm(90, 30);
    w.b.set_time(armed_at + 80 * DAY);
    let (payer_before, key_before) = (w.b.balance(&w.b.payer.pubkey()), w.b.balance(&w.checkin.pubkey()));
    let checkin = w.checkin.insecure_clone();
    w.b.checkin(&checkin).expect("checkin");
    assert_eq!(w.b.balance(&checkin.pubkey()), key_before, "the check-in key holds and spends nothing");
    assert_eq!(w.b.balance(&w.b.payer.pubkey()), payer_before - 2 * FEE);
    let s = w.b.plan();
    assert_eq!((s.last_checkin_ts, s.last_signed_ts), (armed_at + 80 * DAY, armed_at));
    assert_eq!(w.b.vault_state().spent, 1, "a check-in spends no leaf");
    // the window now runs from the check-in
    w.b.set_time(armed_at + 170 * DAY);
    assert_eq!(code(w.b.start()), err::BEFORE_DEADLINE);
    w.b.set_time(armed_at + 170 * DAY + 1);
    w.b.start().expect("start");
}

#[test]
fn only_the_check_in_key_checks_in_and_it_must_sign() {
    let mut w = world();
    w.arm(90, 30);
    let (stranger, contact, checkin) = (w.stranger.insecure_clone(), w.contact.insecure_clone(), w.checkin.insecure_clone());
    assert_eq!(code(w.b.checkin(&stranger)), err::WRONG_CHECKIN_KEY);
    assert_eq!(code(w.b.checkin(&contact)), err::WRONG_CHECKIN_KEY);
    let payer = w.b.payer.insecure_clone();
    assert_eq!(code(w.b.checkin(&payer)), err::WRONG_CHECKIN_KEY);
    // the right key named but not signing
    let mut ix = checkin_ix(&w.b.vault, &checkin.pubkey());
    ix.accounts[1] = AccountMeta::new_readonly(checkin.pubkey(), false);
    assert_eq!(code(w.b.send(&[ix], &[])), err::ANCHOR_ACCOUNT_NOT_SIGNER);
    assert_eq!(w.b.plan().last_checkin_ts, 0);

    // with no plan, and with a plan that names no check-in key, nobody checks in
    let mut unarmed = world();
    let key = unarmed.checkin.insecure_clone();
    assert_eq!(code(unarmed.b.checkin(&key)), err::NOT_ARMED);
    let p = Plan { checkin_key: Pubkey::default(), ..unarmed.plan(90, 30) };
    unarmed.b.set_plan(&p).unwrap();
    assert_eq!(code(unarmed.b.checkin(&key)), err::WRONG_CHECKIN_KEY);
}

#[test]
fn check_ins_stop_counting_two_years_after_the_last_signed_action() {
    let mut w = world();
    let armed_at = w.arm(90, 30);
    let checkin = w.checkin.insecure_clone();
    let cap = armed_at + CHECKIN_CAP_SECS;
    w.b.set_time(cap);
    w.b.checkin(&checkin).expect("at the cap");
    w.b.set_time(cap + 1);
    let before = w.b.plan();
    assert_eq!(code(w.b.checkin(&checkin)), err::CHECKIN_PAST_CAP);
    assert_eq!(w.b.plan(), before, "a refused check-in changes nothing");

    // so a thief with the check-in key delays the release to cap + window + wait, and no further
    w.b.set_time(cap + 90 * DAY);
    assert_eq!(code(w.b.start()), err::BEFORE_DEADLINE);
    w.b.set_time(cap + 90 * DAY + 1);
    w.b.start().expect("start");
    assert_eq!(code(w.b.checkin(&checkin)), err::CHECKIN_PAST_CAP);
    assert!(w.b.plan().wait_open, "a check-in past the cap does not cancel the waiting period");
    w.b.set_time(cap + 120 * DAY + 1);
    let claim = w.claim;
    w.b.execute(&claim, &[]).expect("release");

    // a signed action opens two more years of check-ins
    let mut w = world();
    let armed_at = w.arm(90, 30);
    let checkin = w.checkin.insecure_clone();
    w.b.set_time(armed_at + CHECKIN_CAP_SECS + 5 * DAY);
    assert_eq!(code(w.b.checkin(&checkin)), err::CHECKIN_PAST_CAP);
    w.b.sign_of_life().unwrap();
    w.b.checkin(&checkin).expect("after a signed action");
}

#[test]
fn a_check_in_or_a_signed_action_cancels_an_open_waiting_period() {
    for by_checkin in [true, false] {
        let mut w = world();
        let armed_at = w.arm(90, 30);
        w.b.set_time(armed_at + 90 * DAY + 1);
        w.b.start().expect("start");
        assert!(w.b.plan().wait_open);
        w.b.advance(20 * DAY);
        if by_checkin {
            let k = w.checkin.insecure_clone();
            w.b.checkin(&k).expect("checkin");
        } else {
            w.b.sign_of_life().expect("signed action");
        }
        let s = w.b.plan();
        assert!(!s.wait_open);
        assert_eq!(s.wait_started_ts, 0);
        // the old waiting period is gone for good: nothing to finish, and a new one needs a new window
        w.b.advance(40 * DAY);
        let claim = w.claim;
        assert_eq!(code(w.b.execute(&claim, &[])), err::NO_WAIT_OPEN);
        assert_eq!(code(w.b.start()), err::BEFORE_DEADLINE);
    }
}

#[test]
fn whichever_lands_first_the_owner_wins_the_race_with_a_start() {
    // the owner's check-in lands first: the deadline has moved and the start fails
    let mut w = world();
    let armed_at = w.arm(90, 30);
    let k = w.checkin.insecure_clone();
    w.b.set_time(armed_at + 90 * DAY + 1);
    w.b.checkin(&k).unwrap();
    assert_eq!(code(w.b.start()), err::BEFORE_DEADLINE);
    assert!(!w.b.plan().wait_open);

    // the start lands first, in the same second: the check-in cancels it
    let mut w = world();
    let armed_at = w.arm(90, 30);
    let k = w.checkin.insecure_clone();
    w.b.set_time(armed_at + 90 * DAY + 1);
    w.b.start().unwrap();
    w.b.checkin(&k).unwrap();
    assert!(!w.b.plan().wait_open);
}

// ---- contact_extend ----

#[test]
fn the_contact_extends_once_and_only_the_contact() {
    let mut w = world();
    let armed_at = w.arm(90, 30);
    let (contact, checkin, stranger) = (w.contact.insecure_clone(), w.checkin.insecure_clone(), w.stranger.insecure_clone());
    assert_eq!(code(w.b.contact_extend(&stranger)), err::WRONG_CONTACT_KEY);
    assert_eq!(code(w.b.contact_extend(&checkin)), err::WRONG_CONTACT_KEY);
    let mut ix = contact_extend_ix(&w.b.vault, &contact.pubkey());
    ix.accounts[1] = AccountMeta::new_readonly(contact.pubkey(), false);
    assert_eq!(code(w.b.send(&[ix], &[])), err::ANCHOR_ACCOUNT_NOT_SIGNER);

    w.b.set_time(armed_at + 10 * DAY);
    w.b.contact_extend(&contact).expect("extend");
    let s = w.b.plan();
    assert!(s.contact_used);
    assert_eq!(s.extended_until_ts, armed_at + 180 * DAY, "90 days past the deadline that stood");
    assert_eq!(code(w.b.contact_extend(&contact)), err::CONTACT_ALREADY_USED);
    w.b.set_time(armed_at + 180 * DAY);
    assert_eq!(code(w.b.start()), err::BEFORE_DEADLINE);
    w.b.set_time(armed_at + 180 * DAY + 1);
    w.b.start().expect("start after the extension");

    // no plan, or a plan with no contact: nobody extends
    let mut unarmed = world();
    let c = unarmed.contact.insecure_clone();
    assert_eq!(code(unarmed.b.contact_extend(&c)), err::NOT_ARMED);
    let p = Plan { contact_key: Pubkey::default(), ..unarmed.plan(90, 30) };
    unarmed.b.set_plan(&p).unwrap();
    assert_eq!(code(unarmed.b.contact_extend(&c)), err::WRONG_CONTACT_KEY);
}

#[test]
fn an_extension_used_late_still_buys_ninety_days_and_cancels_the_wait() {
    let mut w = world();
    let armed_at = w.arm(90, 30);
    let contact = w.contact.insecure_clone();
    // nobody starts the waiting period until day 300; the contact extends on day 310
    w.b.set_time(armed_at + 300 * DAY);
    w.b.start().unwrap();
    w.b.set_time(armed_at + 310 * DAY);
    w.b.contact_extend(&contact).expect("extend");
    let s = w.b.plan();
    assert!(!s.wait_open);
    assert_eq!(s.extended_until_ts, armed_at + 400 * DAY, "90 days from now, not from a deadline long past");
    assert_eq!(code(w.b.start()), err::BEFORE_DEADLINE);
    w.b.set_time(armed_at + 400 * DAY + 1);
    w.b.start().expect("start once the extension is over");
}

#[test]
fn a_check_in_never_brings_the_deadline_forward() {
    // The contact extends on day 1 of a 90-day window: the deadline goes to day 180. A check-in on
    // day 2 must not pull it back to day 92. The check-in key can delay a release, nothing else.
    let mut w = world();
    let armed_at = w.arm(90, 30);
    let (contact, checkin) = (w.contact.insecure_clone(), w.checkin.insecure_clone());
    w.b.set_time(armed_at + DAY);
    w.b.contact_extend(&contact).unwrap();
    w.b.set_time(armed_at + 2 * DAY);
    w.b.checkin(&checkin).unwrap();
    assert_eq!(w.b.plan().extended_until_ts, armed_at + 180 * DAY, "the extension stands");
    // so nobody can open a waiting period on day 93, or on day 180; only after it
    for day in [93, 150, 180] {
        w.b.set_time(armed_at + day * DAY);
        assert_eq!(code(w.b.start()), err::BEFORE_DEADLINE, "day {day}");
    }
    w.b.set_time(armed_at + 180 * DAY + 1);
    w.b.start().expect("after the extended deadline");
}

#[test]
fn the_extension_ends_when_the_owner_signs_and_a_restated_plan_grants_another() {
    let mut w = world();
    let armed_at = w.arm(90, 30);
    let (contact, checkin) = (w.contact.insecure_clone(), w.checkin.insecure_clone());
    w.b.set_time(armed_at + 80 * DAY);
    w.b.contact_extend(&contact).unwrap();
    assert_eq!(w.b.plan().extended_until_ts, armed_at + 180 * DAY);
    w.b.set_time(armed_at + 100 * DAY);
    w.b.checkin(&checkin).unwrap();
    let s = w.b.plan();
    assert_eq!(s.extended_until_ts, armed_at + 180 * DAY, "a check-in leaves the extension alone");
    assert!(s.contact_used);
    assert_eq!(code(w.b.contact_extend(&contact)), err::CONTACT_ALREADY_USED);
    // a signature with the vault is the owner themselves: that ends it
    w.b.sign_of_life().unwrap();
    assert_eq!(w.b.plan().extended_until_ts, 0, "the owner signed: the extension is over");
    assert!(w.b.plan().contact_used, "and it stays spent until the plan is set again");

    // the owner restates the plan with the same contact: one more extension
    let p = w.plan(90, 30);
    w.b.set_plan(&p).unwrap();
    assert!(!w.b.plan().contact_used);
    w.b.contact_extend(&contact).expect("a second extension, granted by the owner");
}

// ---- start_succession ----

#[test]
fn nobody_starts_a_waiting_period_before_the_deadline() {
    let mut w = world();
    assert_eq!(code(w.b.start()), err::NOT_ARMED);
    let armed_at = w.arm(365, 60);
    for t in [armed_at, armed_at + 364 * DAY, armed_at + 365 * DAY] {
        w.b.set_time(t);
        assert_eq!(code(w.b.start()), err::BEFORE_DEADLINE, "at {}", t - armed_at);
    }
    assert!(!w.b.plan().wait_open);
    w.b.set_time(armed_at + 365 * DAY + 1);
    let payer_before = w.b.balance(&w.b.payer.pubkey());
    w.b.start().expect("one second past the deadline, by anyone");
    assert_eq!(w.b.balance(&w.b.payer.pubkey()), payer_before - FEE);
    let s = w.b.plan();
    assert!(s.wait_open);
    assert_eq!(s.wait_started_ts, armed_at + 365 * DAY + 1);
    assert_eq!(code(w.b.start()), err::WAIT_ALREADY_OPEN);
    assert_eq!(w.b.vault_state().spent, 1, "starting spends no leaf");
}

// ---- execute_succession ----

#[test]
fn the_release_waits_out_the_waiting_period_then_goes_to_the_claim_address_only() {
    let mut w = world();
    let armed_at = w.arm(90, 30);
    let claim = w.claim;
    assert_eq!(code(w.b.execute(&claim, &[])), err::NO_WAIT_OPEN);
    w.b.set_time(armed_at + 90 * DAY + 1);
    w.b.start().unwrap();
    let started = w.b.now();
    for t in [started, started + 29 * DAY, started + 30 * DAY - 1] {
        w.b.set_time(t);
        assert_eq!(code(w.b.execute(&claim, &[])), err::WAIT_NOT_OVER, "at {}", t - started);
    }
    w.b.set_time(started + 30 * DAY);
    // not to anyone else
    let thief = w.stranger.pubkey();
    assert_eq!(code(w.b.execute(&thief, &[])), err::WRONG_CLAIM);
    let payer = w.b.payer.pubkey();
    assert_eq!(code(w.b.execute(&payer, &[])), err::WRONG_CLAIM);
    assert!(!w.b.is_tombstone());

    let vault_before = w.b.balance(&w.b.vault);
    let keep = w.b.rent(TOMBSTONE_SPACE);
    let slot = w.b.slot();
    w.b.execute(&claim, &[]).expect("release");
    assert_eq!(w.b.balance(&claim), vault_before - keep, "everything above the tombstone's rent");
    let acc = w.b.account(&w.b.vault).unwrap();
    assert_eq!(acc.lamports, keep);
    assert_eq!(acc.owner, PROGRAM_ID);
    assert_eq!(acc.data.len(), TOMBSTONE_SPACE);
    assert_eq!(&acc.data[..8], &TOMBSTONE_DISC);
    assert_eq!(acc.data[8], 0xFE);
    assert_eq!(&acc.data[9..41], &vault_id_for(&w.b.key.public_key().to_bytes()));
    assert_eq!(u64::from_le_bytes(acc.data[41..49].try_into().unwrap()), slot);
    assert_eq!(&acc.data[49..81], claim.as_ref(), "the tombstone names the claim address as heir");
}

#[test]
fn a_released_vault_is_closed_for_good() {
    let mut w = world();
    let armed_at = w.arm(90, 30);
    let (claim, checkin, contact) = (w.claim, w.checkin.insecure_clone(), w.contact.insecure_clone());
    w.b.set_time(armed_at + 90 * DAY + 1);
    w.b.start().unwrap();
    w.b.advance(30 * DAY);
    w.b.execute(&claim, &[]).unwrap();
    // it cannot run twice, and nothing else reads the vault any more
    assert_eq!(code(w.b.execute(&claim, &[])), err::VAULT_CLOSED);
    assert_eq!(code(w.b.start()), err::VAULT_CLOSED);
    assert_eq!(code(w.b.checkin(&checkin)), err::VAULT_CLOSED);
    assert_eq!(code(w.b.contact_extend(&contact)), err::VAULT_CLOSED);
    assert_eq!(code(w.b.sign_of_life()), err::VAULT_CLOSED);
    let p = w.plan(90, 30);
    assert_eq!(code(w.b.set_plan(&p)), err::VAULT_CLOSED);
}

#[test]
fn the_release_needs_no_leaf_and_no_room_in_the_key_history() {
    let mut w = world();
    let armed_at = w.arm(90, 30);
    // Put the vault where its owner could do nothing more: every leaf spent, 128 past keys.
    let before = w.b.vault_state();
    let mut data = w.b.data(&w.b.vault);
    data[98..102].copy_from_slice(&32u32.to_le_bytes());
    let bitmap = BLOCK_OFFSET + BLOCK_LEN + 4;
    data[bitmap..bitmap + 4].copy_from_slice(&[0xFF; 4]);
    let history_len = bitmap + 4;
    assert_eq!(data.len(), history_len + 4);
    data[history_len..history_len + 4].copy_from_slice(&128u32.to_le_bytes());
    for i in 0..128u8 {
        data.extend_from_slice(&[i; 16]);
    }
    let lamports = w.b.rent(data.len()) + 3 * SOL;
    w.b.svm.set_account(w.b.vault, solana_account::Account { lamports, data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 }).unwrap();
    let v = w.b.vault_state();
    assert_eq!((v.spent, v.used_keys.len()), (32, 128));
    assert_eq!(v.succession, before.succession);
    // the owner really is locked out: no leaf is free
    assert_eq!(custom(w.b.signed_with_leaf(0, &action::transfer_sol(&w.claim, 1, w.b.slot(), w.b.slot() + 10), vec![AccountMeta::new(w.claim, false)]).unwrap_err()), ERR_LEAF_ALREADY_USED);

    let claim = w.claim;
    w.b.set_time(armed_at + 90 * DAY + 1);
    w.b.start().expect("start");
    w.b.advance(30 * DAY);
    w.b.execute(&claim, &[]).expect("release with no leaf and a full history");
    assert_eq!(w.b.balance(&claim), lamports - w.b.rent(TOMBSTONE_SPACE));
    assert!(w.b.is_tombstone());
}

#[test]
fn empty_token_accounts_are_closed_in_the_release_and_others_must_wait_for_a_sweep() {
    let mut w = world();
    let armed_at = w.arm(90, 30);
    let (claim, vault) = (w.claim, w.b.vault);
    let mint = w.b.mint(&TOKEN_PROGRAM_ID, 6);
    let mint22 = w.b.mint(&TOKEN_2022_PROGRAM_ID, 6);
    let empty = w.b.token_account(&TOKEN_PROGRAM_ID, &mint, &vault, 0);
    let empty22 = w.b.token_account(&TOKEN_2022_PROGRAM_ID, &mint22, &vault, 0);
    let full = w.b.token_account(&TOKEN_PROGRAM_ID, &mint, &vault, 500);
    let strangers = w.b.token_account(&TOKEN_PROGRAM_ID, &mint, &w.stranger.pubkey(), 0);
    w.b.set_time(armed_at + 90 * DAY + 1);
    w.b.start().unwrap();
    w.b.advance(30 * DAY);

    // the refusals Close has, with Close's own codes
    assert_eq!(code(w.b.execute(&claim, &[(full, TOKEN_PROGRAM_ID)])), err::TOKEN_ACCOUNT_NOT_EMPTY);
    assert_eq!(code(w.b.execute(&claim, &[(strangers, TOKEN_PROGRAM_ID)])), err::NOT_VAULT_TOKEN_ACCOUNT);
    assert_eq!(code(w.b.execute(&claim, &[(empty, TOKEN_2022_PROGRAM_ID)])), err::INVALID_TOKEN_PROGRAM);
    assert_eq!(code(w.b.execute(&claim, &[(empty, ATA_PROGRAM_ID)])), err::INVALID_TOKEN_PROGRAM);
    let mut odd = execute_succession_ix(&vault, &claim, &[(empty, TOKEN_PROGRAM_ID)]);
    odd.accounts.pop();
    assert_eq!(code(w.b.send(&[odd], &[])), err::MISSING_ACCOUNT);
    assert!(!w.b.is_tombstone());

    let token_rent = w.b.balance(&empty) + w.b.balance(&empty22);
    let vault_before = w.b.balance(&vault);
    w.b.execute(&claim, &[(empty, TOKEN_PROGRAM_ID), (empty22, TOKEN_2022_PROGRAM_ID)]).expect("release");
    assert!(w.b.account(&empty).is_none() && w.b.account(&empty22).is_none(), "both closed");
    assert_eq!(w.b.balance(&claim), vault_before - w.b.rent(TOMBSTONE_SPACE) + token_rent, "their rent went to the claim address too");
    assert_eq!(token_amount(&w.b.data(&full)), 500, "the account that held tokens is still there, still the vault's");
}

#[test]
fn after_the_release_the_sweeps_deliver_tokens_and_late_sol_to_the_claim_address() {
    // The claim address here is off the curve, like a claim-program plan account: nobody holds a key for it.
    let mut w = world();
    let claim = Pubkey::find_program_address(&[b"plan", &[7u8; 32]], &ATA_PROGRAM_ID).0;
    w.claim = claim;
    let armed_at = w.arm(90, 30);
    let vault = w.b.vault;
    let payer = w.b.payer.pubkey();
    let mint = w.b.mint(&TOKEN_PROGRAM_ID, 6);
    let mint22 = w.b.mint(&TOKEN_2022_PROGRAM_ID, 9);
    let held = w.b.token_account(&TOKEN_PROGRAM_ID, &mint, &vault, 1_000);
    let held22 = w.b.token_account(&TOKEN_2022_PROGRAM_ID, &mint22, &vault, 77);

    // before the release there is nothing to sweep
    assert_eq!(code(w.b.send(&[sweep_closed_ix(&payer, &vault, &claim, &held, &mint, &TOKEN_PROGRAM_ID)], &[])), err::VAULT_NOT_CLOSED);

    w.b.set_time(armed_at + 90 * DAY + 1);
    w.b.start().unwrap();
    w.b.advance(30 * DAY);
    w.b.execute(&claim, &[]).expect("release");
    let claim_sol = w.b.balance(&claim);

    // tokens: to the claim address's associated account, created on the way; to nobody else
    let thief = w.stranger.pubkey();
    assert_eq!(code(w.b.send(&[sweep_closed_ix(&payer, &vault, &thief, &held, &mint, &TOKEN_PROGRAM_ID)], &[])), err::WRONG_HEIR);
    let held_rent = w.b.balance(&held) + w.b.balance(&held22);
    w.b.send(&[sweep_closed_ix(&payer, &vault, &claim, &held, &mint, &TOKEN_PROGRAM_ID)], &[]).expect("sweep the Token account");
    w.b.send(&[sweep_closed_ix(&payer, &vault, &claim, &held22, &mint22, &TOKEN_2022_PROGRAM_ID)], &[]).expect("sweep the Token-2022 account");
    assert_eq!(token_amount(&w.b.data(&ata(&claim, &mint, &TOKEN_PROGRAM_ID))), 1_000);
    assert_eq!(token_amount(&w.b.data(&ata(&claim, &mint22, &TOKEN_2022_PROGRAM_ID))), 77);
    assert!(w.b.account(&held).is_none() && w.b.account(&held22).is_none());
    assert_eq!(w.b.balance(&claim), claim_sol + held_rent, "the swept accounts' rent");

    // SOL that reaches the old address later
    w.b.svm.airdrop(&vault, 2 * SOL).unwrap();
    assert_eq!(code(w.b.send(&[sweep_closed_sol_ix(&vault, &thief)], &[])), err::WRONG_HEIR);
    w.b.send(&[sweep_closed_sol_ix(&vault, &claim)], &[]).expect("sweep late SOL");
    assert_eq!(w.b.balance(&claim), claim_sol + held_rent + 2 * SOL);
    assert_eq!(w.b.balance(&vault), w.b.rent(TOMBSTONE_SPACE));
}

#[test]
fn nothing_is_released_sooner_than_window_plus_wait_after_a_plan_change() {
    // A plan with the default clock is changed on day 100 to a new claim address and the shortest
    // clock. The change is in force at once, and still nobody can be paid for 120 days.
    let mut w = world();
    let armed_at = w.arm(365, 60);
    let new_claim = Keypair::new().pubkey();
    let changed_at = armed_at + 100 * DAY;
    w.b.set_time(changed_at);
    let p = Plan { claim: new_claim, ..w.plan(90, 30) };
    w.b.set_plan(&p).unwrap();
    w.b.set_time(changed_at + 90 * DAY);
    assert_eq!(code(w.b.start()), err::BEFORE_DEADLINE);
    w.b.set_time(changed_at + 90 * DAY + 1);
    w.b.start().unwrap();
    w.b.set_time(changed_at + 120 * DAY);
    assert_eq!(code(w.b.execute(&new_claim, &[])), err::WAIT_NOT_OVER);
    w.b.set_time(changed_at + 120 * DAY + 1);
    let old_claim = w.claim;
    assert_eq!(code(w.b.execute(&old_claim, &[])), err::WRONG_CLAIM, "the old heir gets nothing");
    w.b.execute(&new_claim, &[]).expect("release to the new claim address");
}
