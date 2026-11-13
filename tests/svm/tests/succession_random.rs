//! Random sequences of signed actions, plan changes, check-ins, contact extensions, starts,
//! releases and clock jumps, against a model of the rules written out again here. After every
//! step the vault's succession block must equal the model's, field for field, and every
//! instruction must succeed or fail exactly as the model says, with the same code.
//!
//! What that pins, whatever the order of events:
//! - no waiting period opens before the deadline, and none while one is open;
//! - a signed action, a valid check-in or a contact extension cancels an open waiting period, and a
//!   check-in past the two-year cap does not;
//! - nothing is released before `window + wait` has passed since the last signed action, nor to
//!   any address but the plan's.
#![cfg(feature = "succession")]

use lamport_vault_svm_tests::succession::*;
use lamport_vault_svm_tests::*;
use solana_keypair::Keypair;
use solana_signer::Signer;

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
    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
}

/// The rules, restated without the program.
#[derive(Clone, Debug, PartialEq)]
struct Model {
    claim: Pubkey,
    window: i64,
    wait: i64,
    last_signed: i64,
    last_checkin: i64,
    checkin_key: Pubkey,
    contact_key: Pubkey,
    contact_used: bool,
    extended_until: i64,
    wait_open: bool,
    wait_started: i64,
    closed: bool,
}

impl Model {
    fn new() -> Self {
        Model {
            claim: Pubkey::default(),
            window: 0,
            wait: 0,
            last_signed: 0,
            last_checkin: 0,
            checkin_key: Pubkey::default(),
            contact_key: Pubkey::default(),
            contact_used: false,
            extended_until: 0,
            wait_open: false,
            wait_started: 0,
            closed: false,
        }
    }
    fn armed(&self) -> bool {
        self.claim != Pubkey::default()
    }
    fn deadline(&self) -> i64 {
        let activity = self.last_signed.max(self.last_checkin.min(self.last_signed + CHECKIN_CAP_SECS));
        (activity + self.window).max(self.extended_until)
    }
    fn signed(&mut self, now: i64) {
        self.last_signed = now;
        self.extended_until = 0;
        self.wait_open = false;
        self.wait_started = 0;
    }
    fn set_plan(&mut self, p: &Plan, now: i64) -> Result<(), u32> {
        if self.closed {
            return Err(err::VAULT_CLOSED);
        }
        if p.claim == Pubkey::default() {
            if p.window_secs != 0 || p.wait_secs != 0 || p.checkin_key != Pubkey::default() || p.contact_key != Pubkey::default() {
                return Err(err::CLEAR_CARRIES_PLAN);
            }
        } else {
            if !(MIN_WINDOW_SECS..=MAX_DURATION_SECS).contains(&p.window_secs) {
                return Err(err::WINDOW_OUT_OF_RANGE);
            }
            if !(MIN_WAIT_SECS..=MAX_DURATION_SECS).contains(&p.wait_secs) {
                return Err(err::WAIT_OUT_OF_RANGE);
            }
        }
        self.claim = p.claim;
        self.window = p.window_secs as i64;
        self.wait = p.wait_secs as i64;
        self.checkin_key = p.checkin_key;
        self.contact_key = p.contact_key;
        self.contact_used = false;
        self.signed(now);
        Ok(())
    }
    fn sign_of_life(&mut self, now: i64) -> Result<(), u32> {
        if self.closed {
            return Err(err::VAULT_CLOSED);
        }
        self.signed(now);
        Ok(())
    }
    fn checkin(&mut self, signer: &Pubkey, now: i64) -> Result<(), u32> {
        if self.closed {
            return Err(err::VAULT_CLOSED);
        }
        if !self.armed() {
            return Err(err::NOT_ARMED);
        }
        if self.checkin_key == Pubkey::default() || *signer != self.checkin_key {
            return Err(err::WRONG_CHECKIN_KEY);
        }
        if now > self.last_signed + CHECKIN_CAP_SECS {
            return Err(err::CHECKIN_PAST_CAP);
        }
        self.last_checkin = now;
        self.extended_until = 0;
        self.wait_open = false;
        self.wait_started = 0;
        Ok(())
    }
    fn contact_extend(&mut self, signer: &Pubkey, now: i64) -> Result<(), u32> {
        if self.closed {
            return Err(err::VAULT_CLOSED);
        }
        if !self.armed() {
            return Err(err::NOT_ARMED);
        }
        if self.contact_key == Pubkey::default() || *signer != self.contact_key {
            return Err(err::WRONG_CONTACT_KEY);
        }
        if self.contact_used {
            return Err(err::CONTACT_ALREADY_USED);
        }
        self.extended_until = self.deadline().max(now) + CONTACT_EXTENSION_SECS;
        self.contact_used = true;
        self.wait_open = false;
        self.wait_started = 0;
        Ok(())
    }
    fn start(&mut self, now: i64) -> Result<(), u32> {
        if self.closed {
            return Err(err::VAULT_CLOSED);
        }
        if !self.armed() {
            return Err(err::NOT_ARMED);
        }
        if self.wait_open {
            return Err(err::WAIT_ALREADY_OPEN);
        }
        if now <= self.deadline() {
            return Err(err::BEFORE_DEADLINE);
        }
        self.wait_open = true;
        self.wait_started = now;
        Ok(())
    }
    fn execute(&mut self, to: &Pubkey, now: i64) -> Result<(), u32> {
        if self.closed {
            return Err(err::VAULT_CLOSED);
        }
        if !self.armed() {
            return Err(err::NOT_ARMED);
        }
        if !self.wait_open {
            return Err(err::NO_WAIT_OPEN);
        }
        if now < self.wait_started + self.wait {
            return Err(err::WAIT_NOT_OVER);
        }
        if *to != self.claim {
            return Err(err::WRONG_CLAIM);
        }
        self.closed = true;
        Ok(())
    }
}

/// What the runs exercised, so the test can check it is not passing by doing nothing.
#[derive(Default, Debug)]
struct Seen {
    plans_set: u32,
    plans_refused: u32,
    checkins: u32,
    checkins_past_cap: u32,
    extensions: u32,
    starts: u32,
    starts_too_early: u32,
    waits_cancelled: u32,
    releases: u32,
    releases_too_early: u32,
    wrong_claim: u32,
}

fn run(seed: u64, seen: &mut Seen) {
    let mut rng = Rng(seed | 1);
    let mut b = Bench::new();
    let mut m = Model::new();
    let (checkin, contact, stranger) = (Keypair::new(), Keypair::new(), Keypair::new());
    let claims = [Keypair::new().pubkey(), Keypair::new().pubkey()];
    let day = DAY as u64;
    let mut signed_actions = 0;
    let mut steps_closed = 0;

    for step in 0..40 {
        // a few steps on a closed vault show it refuses everything; more would be wasted
        if m.closed {
            steps_closed += 1;
            if steps_closed > 4 {
                break;
            }
        }
        let now = b.now();
        let was_waiting = m.wait_open;
        // Left to chance, a run rarely gets as far as a release. So when the vault stands at the
        // threshold of the next stage, one step in four is the one that crosses it.
        let nudge = if m.armed() && !m.closed && rng.below(4) == 0 {
            if m.wait_open && now >= m.wait_started + m.wait {
                Some(14) // the waiting period is over: someone finishes it
            } else if m.wait_open {
                Some(3) // jump to the end of the waiting period
            } else if now > m.deadline() {
                Some(12) // the deadline has passed: someone starts
            } else {
                Some(2) // jump to the deadline
            }
        } else {
            None
        };
        match nudge.unwrap_or_else(|| rng.below(16)) {
            // time passes: a little, a lot, or right up to an edge
            0 | 1 => b.advance(rng.pick(&[1, 3_600, DAY, 29 * DAY, 30 * DAY, 89 * DAY, 91 * DAY, 200 * DAY, 400 * DAY])),
            2 if m.armed() && !m.closed => {
                let edge = m.deadline() + rng.pick(&[-1i64, 0, 1, 1, DAY]);
                if edge > now {
                    b.set_time(edge);
                }
            }
            3 if m.armed() && !m.closed && m.wait_open => {
                let edge = m.wait_started + m.wait + rng.pick(&[-1i64, 0, 0, 1]);
                if edge > now {
                    b.set_time(edge);
                }
            }
            4 if m.armed() && !m.closed => {
                let edge = m.last_signed + CHECKIN_CAP_SECS + rng.pick(&[-1i64, 0, 1]);
                if edge > now {
                    b.set_time(edge);
                }
            }
            // the owner signs something: a transfer, or a plan
            5 if signed_actions < 30 => {
                let expect = m.sign_of_life(now);
                assert_eq!(b.sign_of_life().map_err(custom), expect, "seed {seed} step {step}: signed transfer");
                signed_actions += expect.is_ok() as u32;
            }
            6 | 7 if signed_actions < 30 => {
                let plan = match rng.below(10) {
                    0 => Plan::clear(),
                    1 => Plan { window_secs: 90 * day - 1, ..Plan { claim: claims[0], window_secs: 0, wait_secs: 30 * day, checkin_key: Pubkey::default(), contact_key: Pubkey::default() } },
                    2 => Plan { claim: claims[0], window_secs: 90 * day, wait_secs: 30 * day - 1, checkin_key: Pubkey::default(), contact_key: Pubkey::default() },
                    3 => Plan { wait_secs: 30 * day, ..Plan::clear() },
                    _ => Plan {
                        claim: rng.pick(&claims),
                        window_secs: rng.pick(&[90, 91, 180, 365]) * day,
                        wait_secs: rng.pick(&[30, 31, 60]) * day,
                        checkin_key: if rng.below(4) == 0 { Pubkey::default() } else { checkin.pubkey() },
                        contact_key: if rng.below(3) == 0 { Pubkey::default() } else { contact.pubkey() },
                    },
                };
                let expect = m.set_plan(&plan, now);
                assert_eq!(b.set_plan(&plan).map_err(custom), expect, "seed {seed} step {step}: SetSuccession {plan:?}");
                signed_actions += expect.is_ok() as u32;
                if expect.is_ok() { seen.plans_set += 1 } else { seen.plans_refused += 1 }
            }
            8 | 9 | 10 => {
                let who = match rng.below(6) {
                    0 => &stranger,
                    1 => &contact,
                    _ => &checkin,
                };
                let expect = m.checkin(&who.pubkey(), now);
                assert_eq!(b.checkin(who).map_err(custom), expect, "seed {seed} step {step}: checkin");
                match expect {
                    Ok(()) => seen.checkins += 1,
                    Err(err::CHECKIN_PAST_CAP) => seen.checkins_past_cap += 1,
                    _ => {}
                }
            }
            11 => {
                let who = if rng.below(5) == 0 { &stranger } else { &contact };
                let expect = m.contact_extend(&who.pubkey(), now);
                assert_eq!(b.contact_extend(who).map_err(custom), expect, "seed {seed} step {step}: contact_extend");
                seen.extensions += expect.is_ok() as u32;
            }
            12 | 13 => {
                let expect = m.start(now);
                assert_eq!(b.start().map_err(custom), expect, "seed {seed} step {step}: start_succession at {now}, deadline {}", m.deadline());
                match expect {
                    Ok(()) => seen.starts += 1,
                    Err(err::BEFORE_DEADLINE) => seen.starts_too_early += 1,
                    _ => {}
                }
            }
            _ => {
                let to = if m.armed() && rng.below(4) != 0 { m.claim } else { stranger.pubkey() };
                let before = m.clone();
                let expect = m.execute(&to, now);
                assert_eq!(b.execute(&to, &[]).map_err(custom), expect, "seed {seed} step {step}: execute_succession");
                match expect {
                    Ok(()) => {
                        seen.releases += 1;
                        // the rule that protects a plan change: window + wait since the last signed action
                        assert!(now > before.last_signed + before.window + before.wait, "seed {seed} step {step}: released too soon");
                        assert_eq!(&b.data(&b.vault)[49..81], to.as_ref(), "seed {seed} step {step}: heir");
                    }
                    Err(err::WAIT_NOT_OVER) => seen.releases_too_early += 1,
                    Err(err::WRONG_CLAIM) => seen.wrong_claim += 1,
                    _ => {}
                }
            }
        }
        if was_waiting && !m.wait_open && !m.closed {
            seen.waits_cancelled += 1;
        }

        // after every step the chain and the model agree
        assert_eq!(b.is_tombstone(), m.closed, "seed {seed} step {step}: closed");
        if !m.closed {
            let s = b.plan();
            let chain = Model {
                claim: s.claim,
                window: s.window_secs as i64,
                wait: s.wait_secs as i64,
                last_signed: s.last_signed_ts,
                last_checkin: s.last_checkin_ts,
                checkin_key: s.checkin_key,
                contact_key: s.contact_key,
                contact_used: s.contact_used,
                extended_until: s.extended_until_ts,
                wait_open: s.wait_open,
                wait_started: s.wait_started_ts,
                closed: false,
            };
            assert_eq!(chain, m, "seed {seed} step {step}");
            assert!(s.reserved.iter().all(|x| *x == 0), "seed {seed} step {step}: reserved bytes");
        }
    }
}

#[test]
fn random_sequences_agree_with_the_model() {
    let mut seen = Seen::default();
    for seed in 0..400 {
        run(0x9E37_79B9_7F4A_7C15u64.wrapping_mul(seed + 1), &mut seen);
    }
    println!("{seen:?}");
    for (count, what) in [
        (seen.plans_set, "plans set"),
        (seen.plans_refused, "plans refused"),
        (seen.checkins, "check-ins"),
        (seen.checkins_past_cap, "check-ins past the cap"),
        (seen.extensions, "contact extensions"),
        (seen.starts, "waiting periods opened"),
        (seen.starts_too_early, "starts before the deadline"),
        (seen.waits_cancelled, "waiting periods cancelled"),
        (seen.releases, "releases"),
        (seen.releases_too_early, "releases before the wait ended"),
        (seen.wrong_claim, "releases to the wrong address"),
    ] {
        assert!(count >= 40, "{what}: only {count} times in 400 runs");
    }
}
