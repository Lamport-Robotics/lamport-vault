#![no_main]
//! The succession clock (`Succession` in `programs/lamport-vault/src/succession.rs`) against a model
//! of the rules written out again here, over arbitrary sequences of plan changes, signed actions,
//! check-ins, contact extensions, starts, release checks and clock jumps.
//!
//! After every step the block must equal the model, and every call must succeed or fail exactly as
//! the model says. On top of that, whatever the order of events:
//! - a waiting period opens only after the deadline, and only when none is open;
//! - a release is due only once `window + wait` has passed since the last signed action;
//! - a refused call changes nothing;
//! - the block always serialises to 200 bytes.
//!
//! A second mode fills the block with arbitrary raw values, as no sequence of instructions could,
//! and calls everything: the rules may refuse, they may not panic or overflow.

use anchor_lang::prelude::Pubkey;
use anchor_lang::AnchorSerialize;
use arbitrary::Arbitrary;
use lamport_vault::succession::{SetSuccession, Succession, CHECKIN_CAP_SECS, CONTACT_EXTENSION_SECS, DAY_SECS, MAX_DURATION_SECS, MIN_WAIT_SECS, MIN_WINDOW_SECS};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    /// Time passes: seconds.
    Seconds(u16),
    /// Time passes: days.
    Days(u16),
    /// Jump to an edge of the current state (deadline, end of the wait, the check-in cap), give or take a second.
    Edge(u8, i8),
    /// A signed action other than a plan change.
    Signed,
    /// A plan from a small table, so the same plan comes round again.
    Plan { claim: u8, window: u8, wait: u8, checkin: bool, contact: bool },
    /// A plan with raw durations: mostly out of range.
    RawPlan { window_secs: u64, wait_secs: u64 },
    /// A clear, canonical or not.
    Clear { dirty: u8 },
    Checkin(u8),
    Extend(u8),
    Start,
    Release,
}

#[derive(Arbitrary, Debug)]
enum Input {
    Sequence(Vec<Op>),
    Raw { fields: [i64; 6], window_secs: u64, wait_secs: u64, flags: u8, now: i64, signer: u8 },
}

fn key(i: u8) -> Pubkey {
    if i == 0 {
        Pubkey::default()
    } else {
        Pubkey::new_from_array([i; 32])
    }
}

const CHECKIN_KEY: u8 = 0xC1;
const CONTACT_KEY: u8 = 0xC2;

/// The rules, restated. Times are far from overflow in sequence mode, so plain arithmetic is exact.
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
}

impl Model {
    fn armed(&self) -> bool {
        self.claim != Pubkey::default()
    }
    fn deadline(&self) -> i64 {
        let activity = self.last_signed.max(self.last_checkin.min(self.last_signed + CHECKIN_CAP_SECS as i64));
        (activity + self.window).max(self.extended_until)
    }
    fn signed(&mut self, now: i64) {
        self.last_signed = now;
        self.extended_until = 0;
        self.wait_open = false;
        self.wait_started = 0;
    }
    fn set(&mut self, p: &SetSuccession) -> bool {
        if p.claim == Pubkey::default() {
            if p.window_secs != 0 || p.wait_secs != 0 || p.checkin_key != Pubkey::default() || p.contact_key != Pubkey::default() {
                return false;
            }
        } else if !(MIN_WINDOW_SECS..=MAX_DURATION_SECS).contains(&p.window_secs) || !(MIN_WAIT_SECS..=MAX_DURATION_SECS).contains(&p.wait_secs) {
            return false;
        }
        self.claim = p.claim;
        self.window = p.window_secs as i64;
        self.wait = p.wait_secs as i64;
        self.checkin_key = p.checkin_key;
        self.contact_key = p.contact_key;
        self.contact_used = false;
        true
    }
    fn checkin(&mut self, signer: &Pubkey, now: i64) -> bool {
        if !self.armed() || self.checkin_key == Pubkey::default() || *signer != self.checkin_key || now > self.last_signed + CHECKIN_CAP_SECS as i64 {
            return false;
        }
        self.last_checkin = now;
        self.wait_open = false;
        self.wait_started = 0;
        true
    }
    fn extend(&mut self, signer: &Pubkey, now: i64) -> bool {
        if !self.armed() || self.contact_key == Pubkey::default() || *signer != self.contact_key || self.contact_used {
            return false;
        }
        self.extended_until = self.deadline().max(now) + CONTACT_EXTENSION_SECS as i64;
        self.contact_used = true;
        self.wait_open = false;
        self.wait_started = 0;
        true
    }
    fn start(&mut self, now: i64) -> bool {
        if !self.armed() || self.wait_open || now <= self.deadline() {
            return false;
        }
        self.wait_open = true;
        self.wait_started = now;
        true
    }
    fn release_due(&self, now: i64) -> bool {
        self.armed() && self.wait_open && now >= self.wait_started + self.wait
    }
    fn of(s: &Succession) -> Self {
        Model {
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
        }
    }
}

fn plan(claim: Pubkey, window_secs: u64, wait_secs: u64, checkin_key: Pubkey, contact_key: Pubkey) -> SetSuccession {
    SetSuccession { claim, window_secs, wait_secs, checkin_key, contact_key, issued_slot: 0, expiry_slot: 0 }
}

fn sequence(ops: Vec<Op>) {
    let mut s = Succession::default();
    let mut m = Model::of(&s);
    let mut now: i64 = 1_800_000_000;
    let day = DAY_SECS as i64;

    for op in ops.into_iter().take(256) {
        let before = s.clone();
        // `Some(ok)` when the step called a rule that may refuse.
        let outcome: Option<bool> = match op {
            Op::Seconds(n) => {
                now += n as i64;
                None
            }
            Op::Days(n) => {
                now += n as i64 * day;
                None
            }
            Op::Edge(which, nudge) => {
                let edge = match which % 3 {
                    0 => m.deadline(),
                    1 => m.wait_started + m.wait,
                    _ => m.last_signed + CHECKIN_CAP_SECS as i64,
                } + (nudge % 3) as i64;
                // the clock only moves forward
                if edge > now {
                    now = edge;
                }
                None
            }
            Op::Signed => {
                s.on_signed_action(now);
                m.signed(now);
                None
            }
            Op::Plan { claim, window, wait, checkin, contact } => {
                let p = plan(
                    key(1 + claim % 3),
                    [90u64, 91, 365, 36_500][window as usize % 4] * DAY_SECS,
                    [30u64, 31, 60, 36_500][wait as usize % 4] * DAY_SECS,
                    if checkin { key(CHECKIN_KEY) } else { Pubkey::default() },
                    if contact { key(CONTACT_KEY) } else { Pubkey::default() },
                );
                Some(set_both(&mut s, &mut m, &p, now))
            }
            Op::RawPlan { window_secs, wait_secs } => Some(set_both(&mut s, &mut m, &plan(key(1), window_secs, wait_secs, Pubkey::default(), Pubkey::default()), now)),
            Op::Clear { dirty } => {
                let mut p = plan(Pubkey::default(), 0, 0, Pubkey::default(), Pubkey::default());
                match dirty % 5 {
                    1 => p.window_secs = MIN_WINDOW_SECS,
                    2 => p.wait_secs = 1,
                    3 => p.checkin_key = key(CHECKIN_KEY),
                    4 => p.contact_key = key(CONTACT_KEY),
                    _ => {}
                }
                Some(set_both(&mut s, &mut m, &p, now))
            }
            Op::Checkin(who) => {
                let signer = key([CHECKIN_KEY, CONTACT_KEY, 0, 7][who as usize % 4]);
                let got = s.checkin(&signer, now).is_ok();
                assert_eq!(got, m.checkin(&signer, now), "checkin at {now}");
                Some(got)
            }
            Op::Extend(who) => {
                let signer = key([CONTACT_KEY, CHECKIN_KEY, 0, 7][who as usize % 4]);
                let got = s.contact_extend(&signer, now).is_ok();
                assert_eq!(got, m.extend(&signer, now), "contact_extend at {now}");
                Some(got)
            }
            Op::Start => {
                let deadline = m.deadline();
                let got = s.start(now).is_ok();
                assert_eq!(got, m.start(now), "start at {now}, deadline {deadline}");
                if got {
                    assert!(now > deadline, "a waiting period opened at or before the deadline");
                    assert!(!before.wait_open, "a waiting period opened over another");
                }
                Some(got)
            }
            Op::Release => {
                let got = s.release_due(now).is_ok();
                assert_eq!(got, m.release_due(now), "release at {now}");
                if got {
                    // the rule that protects a plan change: window + wait since the last signed action
                    assert!(now > m.last_signed + m.window + m.wait, "released within window + wait of a signed action");
                    assert!(now >= s.release_at().unwrap());
                }
                // a release check never changes the block
                assert_eq!(s, before);
                None
            }
        };
        if outcome == Some(false) {
            assert_eq!(s, before, "a refused call changed the block");
        }
        assert_eq!(Model::of(&s), m, "block and model differ");
        assert!(s.reserved.iter().all(|b| *b == 0));
        assert_eq!(s.try_to_vec().unwrap().len(), Succession::SPACE);
        // derived values agree too, and an armed plan always has a deadline after its last signed action
        assert_eq!(s.deadline().unwrap(), m.deadline());
        assert_eq!(s.is_armed(), m.armed());
        if m.armed() {
            assert!(m.deadline() >= m.last_signed + m.window);
            assert!(m.window >= MIN_WINDOW_SECS as i64 && m.wait >= MIN_WAIT_SECS as i64);
        }
        if m.wait_open {
            assert!(m.armed(), "a waiting period on an unarmed vault");
        }
    }
}

/// A plan change is a signed action: when the plan is accepted the clock sees it too.
fn set_both(s: &mut Succession, m: &mut Model, p: &SetSuccession, now: i64) -> bool {
    let got = s.set(p).is_ok();
    assert_eq!(got, m.set(p), "set {p:?}");
    if got {
        s.on_signed_action(now);
        m.signed(now);
    }
    got
}

fn raw(fields: [i64; 6], window_secs: u64, wait_secs: u64, flags: u8, now: i64, signer: u8) {
    let s = Succession {
        claim: key(flags & 3),
        window_secs,
        wait_secs,
        last_signed_ts: fields[0],
        last_checkin_ts: fields[1],
        checkin_key: key((flags >> 2) & 3),
        contact_key: key((flags >> 4) & 3),
        contact_used: flags & 0x40 != 0,
        extended_until_ts: fields[2],
        wait_open: flags & 0x80 != 0,
        wait_started_ts: fields[3],
        reserved: [0; 54],
    };
    let who = key(signer & 3);
    // None of these may panic, whatever the block holds; a refusal leaves it as it was.
    let _ = s.activity();
    let _ = s.deadline();
    let _ = s.release_at();
    let _ = s.release_due(now);
    for call in 0..4 {
        let mut t = s.clone();
        let r = match call {
            0 => t.checkin(&who, now),
            1 => t.contact_extend(&who, now),
            2 => t.start(now),
            _ => t.set(&plan(key(signer), fields[4] as u64, fields[5] as u64, who, who)),
        };
        if r.is_err() {
            assert_eq!(t, s, "a refused call changed the block");
        }
    }
    let mut t = s.clone();
    t.on_signed_action(now);
    assert!(!t.wait_open && t.extended_until_ts == 0 && t.last_signed_ts == now);
}

fuzz_target!(|input: Input| {
    match input {
        Input::Sequence(ops) => sequence(ops),
        Input::Raw { fields, window_secs, wait_secs, flags, now, signer } => raw(fields, window_secs, wait_secs, flags, now, signer),
    }
});
