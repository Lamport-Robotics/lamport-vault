//! Cross-checks the Heir-enabled program's wire formats and clock rules against
//! `kat/succession_encoding.json`, the vectors the TypeScript SDK produces: the `SetSuccession`
//! action and its signed message under this program's id, the version-3 vault account, the new
//! instructions' discriminators, the duration constants, the error codes, and a table of clock
//! states with what the rules say about each. A mismatch here means the SDK and the program
//! would disagree: on the wire, or about when a vault can be released.
//!
//! The vectors are for the real clock, so a `short-clocks` build leaves this file out.
#![cfg(all(feature = "succession", not(feature = "short-clocks")))]

use anchor_lang::prelude::*;
use anchor_lang::{AccountDeserialize, AccountSerialize, Discriminator};
use lamport_lms::LmsType;
use lamport_vault::succession::{
    SetSuccession, Succession, SuccessionError, CHECKIN_CAP_SECS, CONTACT_EXTENSION_SECS, DAY_SECS, MAX_DURATION_SECS, MIN_WAIT_SECS, MIN_WINDOW_SECS,
};
use lamport_vault::{signed_message, vault_id_for, Action, Vault, VAULT_SEED};
use serde_json::Value;
use std::str::FromStr;

const JSON: &str = include_str!("../../../kat/succession_encoding.json");

fn v() -> Value {
    serde_json::from_str(JSON).expect("kat/succession_encoding.json")
}
fn hx(s: &Value) -> Vec<u8> {
    hex::decode(s.as_str().expect("hex string")).expect("hex")
}
fn pk(s: &Value) -> Pubkey {
    Pubkey::from_str(s.as_str().expect("base58 string")).expect("base58")
}
fn u(s: &Value) -> u64 {
    s.as_str().expect("decimal string").parse().expect("u64")
}
fn i(s: &Value) -> i64 {
    s.as_str().expect("decimal string").parse().expect("i64")
}
fn h5(d: &Value) -> [u8; 56] {
    hx(&d["inputs"]["h5_pubkey_hex"]).try_into().unwrap()
}

#[test]
fn vectors_target_this_program_id() {
    let d = v();
    assert_eq!(pk(&d["program_ids"]["lamport_vault_heir"]), lamport_vault::ID);
    assert_ne!(lamport_vault::ID, Pubkey::from_str("B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH").unwrap(), "never the vault program's own id");
    let key = h5(&d);
    let (vault, bump) = Pubkey::find_program_address(&[VAULT_SEED, &vault_id_for(&key)], &lamport_vault::ID);
    assert_eq!(vault, pk(&d["pdas"]["vault"]["address"]));
    assert_eq!(bump as u64, d["pdas"]["vault"]["bump"].as_u64().unwrap());
    assert_eq!(hx(&d["pdas"]["vault_id_hex"]), vault_id_for(&key));
}

#[test]
fn durations_discriminators_and_error_codes() {
    let d = v();
    let c = &d["limits"]["clock"];
    assert_eq!(u(&c["day_secs"]), DAY_SECS);
    assert_eq!(u(&c["min_window_secs"]), MIN_WINDOW_SECS);
    assert_eq!(u(&c["min_wait_secs"]), MIN_WAIT_SECS);
    assert_eq!(u(&c["max_duration_secs"]), MAX_DURATION_SECS);
    assert_eq!(u(&c["checkin_cap_secs"]), CHECKIN_CAP_SECS);
    assert_eq!(u(&c["contact_extension_secs"]), CONTACT_EXTENSION_SECS);
    // the test clock is the same table with a day of one second
    let s = &d["limits"]["short_clocks"];
    assert_eq!(u(&s["day_secs"]), 1);
    for key in ["min_window_secs", "min_wait_secs", "max_duration_secs", "checkin_cap_secs", "contact_extension_secs"] {
        assert_eq!(u(&s[key]) * DAY_SECS, u(&c[key]), "{key}");
    }

    use lamport_vault::instruction as I;
    let disc = &d["discriminators"];
    assert_eq!(hx(&disc["checkin"]), I::Checkin::DISCRIMINATOR);
    assert_eq!(hx(&disc["contact_extend"]), I::ContactExtend::DISCRIMINATOR);
    assert_eq!(hx(&disc["start_succession"]), I::StartSuccession::DISCRIMINATOR);
    assert_eq!(hx(&disc["execute_succession"]), I::ExecuteSuccession::DISCRIMINATOR);

    let codes: [(&str, SuccessionError); 17] = [
        ("NotArmed", SuccessionError::NotArmed),
        ("WrongCheckinKey", SuccessionError::WrongCheckinKey),
        ("CheckinPastCap", SuccessionError::CheckinPastCap),
        ("WrongContactKey", SuccessionError::WrongContactKey),
        ("ContactAlreadyUsed", SuccessionError::ContactAlreadyUsed),
        ("WaitAlreadyOpen", SuccessionError::WaitAlreadyOpen),
        ("BeforeDeadline", SuccessionError::BeforeDeadline),
        ("NoWaitOpen", SuccessionError::NoWaitOpen),
        ("WaitNotOver", SuccessionError::WaitNotOver),
        ("WindowOutOfRange", SuccessionError::WindowOutOfRange),
        ("WaitOutOfRange", SuccessionError::WaitOutOfRange),
        ("ClearCarriesPlan", SuccessionError::ClearCarriesPlan),
        ("ClaimAccountMissing", SuccessionError::ClaimAccountMissing),
        ("ClaimIsTheVault", SuccessionError::ClaimIsTheVault),
        ("ClaimNotUsable", SuccessionError::ClaimNotUsable),
        ("WrongClaim", SuccessionError::WrongClaim),
        ("Overflow", SuccessionError::Overflow),
    ];
    let errors = d["errors"].as_object().unwrap();
    assert_eq!(errors.len(), codes.len(), "every code, and no more");
    for (name, e) in codes {
        assert_eq!(errors[name].as_u64().unwrap() as u32, u32::from(e), "{name}");
    }
}

#[test]
fn set_succession_encoding_and_message() {
    let d = v();
    let key = h5(&d);
    let (vault, _) = Pubkey::find_program_address(&[VAULT_SEED, &vault_id_for(&key)], &lamport_vault::ID);
    let generation = d["inputs"]["generation"].as_u64().unwrap() as u32;
    assert_eq!(d["actions"]["variant"].as_u64().unwrap(), 5);
    assert_eq!(d["actions"]["size"].as_u64().unwrap(), 129);

    let vectors = d["actions"]["vectors"].as_object().unwrap();
    for name in ["set_succession", "set_succession_no_keys", "clear_succession"] {
        let vec = &vectors[name];
        let bytes = hx(&vec["action_hex"]);
        assert_eq!(bytes.len(), 129, "{name}");
        assert_eq!(bytes[0], 5, "{name}");
        let a = &vec["action"];
        let want = SetSuccession {
            claim: pk(&a["claim"]),
            window_secs: u(&a["windowSecs"]),
            wait_secs: u(&a["waitSecs"]),
            checkin_key: pk(&a["checkinKey"]),
            contact_key: pk(&a["contactKey"]),
            issued_slot: u(&a["issuedSlot"]),
            expiry_slot: u(&a["expirySlot"]),
        };
        let decoded = Action::decode(&bytes).unwrap_or_else(|_| panic!("{name} decodes"));
        assert_eq!(decoded, Action::SetSuccession(want.clone()), "{name}");
        assert_eq!(decoded.encode(), bytes, "{name} re-encodes");
        assert_eq!(decoded.window(), (want.issued_slot, want.expiry_slot), "{name}");
        assert_eq!(signed_message(&vault, generation, &bytes).to_vec(), hx(&vec["message_hex"]), "{name} message");
        // the plan itself is acceptable to the program
        Succession::default().set(&want).unwrap_or_else(|_| panic!("{name} is a valid plan"));
    }
    // a trailing byte, or one missing, is not an action
    let good = hx(&vectors["set_succession"]["action_hex"]);
    assert!(Action::decode(&good[..128]).is_err());
    let mut long = good.clone();
    long.push(0);
    assert!(Action::decode(&long).is_err());

    // the vault's own actions encode as they always did; their message carries this program's id
    for (name, variant) in [("transfer_sol", 0u8), ("close", 3)] {
        let bytes = hx(&vectors[name]["action_hex"]);
        assert_eq!(bytes[0], variant);
        let decoded = Action::decode(&bytes).unwrap();
        assert_eq!(decoded.encode(), bytes);
        assert_eq!(signed_message(&vault, generation, &bytes).to_vec(), hx(&vectors[name]["message_hex"]), "{name} message");
    }
}

fn succession_from(s: &Value) -> Succession {
    Succession {
        claim: pk(&s["claim"]),
        window_secs: u(&s["windowSecs"]),
        wait_secs: u(&s["waitSecs"]),
        last_signed_ts: i(&s["lastSignedTs"]),
        last_checkin_ts: i(&s["lastCheckinTs"]),
        checkin_key: pk(&s["checkinKey"]),
        contact_key: pk(&s["contactKey"]),
        contact_used: s["contactUsed"].as_bool().unwrap(),
        extended_until_ts: i(&s["extendedUntilTs"]),
        wait_open: s["waitOpen"].as_bool().unwrap(),
        wait_started_ts: i(&s["waitStartedTs"]),
        reserved: [0; 54],
    }
}

#[test]
fn the_version_3_vault_account() {
    let d = v();
    let a = &d["accounts"];
    assert_eq!(a["vault_version"].as_u64().unwrap() as u8, Vault::VERSION);
    assert_eq!(a["block_offset"].as_u64().unwrap() as usize, Vault::FIXED, "the block follows the fixed fields");
    assert_eq!(a["block_size"].as_u64().unwrap() as usize, Succession::SPACE);
    assert_eq!(Vault::EXT, Succession::SPACE);

    let bytes = hx(&a["vault_hex"]);
    let vault = Vault::try_deserialize(&mut &bytes[..]).expect("a version-3 vault");
    let j = &a["vault"];
    assert_eq!(vault.version, 3);
    assert_eq!(vault.bump as u64, j["bump"].as_u64().unwrap());
    assert_eq!(vault.vault_id.to_vec(), hx(&j["vaultId"]));
    assert_eq!(vault.lms_pubkey.to_vec(), hx(&j["lmsPubkey"]));
    assert_eq!(vault.spent as u64, j["spent"].as_u64().unwrap());
    assert_eq!(vault.generation as u64, j["generation"].as_u64().unwrap());
    assert_eq!(vault.created_slot, u(&j["createdSlot"]));
    assert_eq!(vault.used, hx(&j["used"]));
    let history: Vec<Vec<u8>> = j["usedKeys"].as_array().unwrap().iter().map(hx).collect();
    assert_eq!(vault.used_keys.iter().map(|k| k.to_vec()).collect::<Vec<_>>(), history);
    assert_eq!(vault.succession, succession_from(&j["succession"]));
    assert_eq!(hx(&j["succession"]["reserved"]), vec![0u8; 54]);

    // the block sits at a fixed offset whatever follows it
    let mut block = Vec::new();
    vault.succession.serialize(&mut block).unwrap();
    assert_eq!(&bytes[Vault::FIXED..Vault::FIXED + Succession::SPACE], &block[..]);

    let mut out = Vec::new();
    vault.try_serialize(&mut out).unwrap();
    assert_eq!(out, bytes, "re-serialises to the same bytes");
    assert_eq!(out.len(), Vault::space(LmsType::Sha256M32H5, vault.used_keys.len()));

    // a version-2 account (the vault program's layout) is not a vault of this program
    let mut v2 = bytes.clone();
    v2[8] = 2;
    assert!(Vault::try_deserialize(&mut &v2[..]).is_err());

    let sizes = &a["sizes"];
    assert_eq!(sizes["vault_h5"].as_u64().unwrap() as usize, Vault::space(LmsType::Sha256M32H5, 0));
    assert_eq!(sizes["vault_h10"].as_u64().unwrap() as usize, Vault::space(LmsType::Sha256M32H10, 0));
    assert_eq!(sizes["vault_h15"].as_u64().unwrap() as usize, Vault::space(LmsType::Sha256M32H15, 0));
    assert_eq!(Vault::space(LmsType::Sha256M32H5, 0), 126 + 200);
}

#[test]
fn the_sdk_and_the_program_agree_about_every_clock_state() {
    let d = v();
    let cases = d["clock"].as_array().unwrap();
    assert!(cases.len() >= 15);
    let mut phases = std::collections::BTreeSet::new();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let s = succession_from(&c["state"]);
        let now = i(&c["now"]);
        let phase = c["phase"].as_str().unwrap();
        phases.insert(phase.to_string());

        assert_eq!(s.is_armed(), phase != "unarmed", "{name}: armed");
        assert_eq!(s.activity().unwrap(), i(&c["activity"]), "{name}: activity");
        assert_eq!(s.deadline().unwrap(), i(&c["deadline"]), "{name}: deadline");
        assert_eq!(s.last_signed_ts + CHECKIN_CAP_SECS as i64, i(&c["checkin_counts_until"]), "{name}: check-in cap");
        match c["release_at"].as_str() {
            Some(t) => {
                assert!(s.wait_open, "{name}");
                assert_eq!(s.release_at().unwrap(), t.parse::<i64>().unwrap(), "{name}: release_at");
            }
            None => assert!(!s.wait_open, "{name}"),
        }

        // what the program would do at `now`, against the phase the SDK names
        let can_start = s.clone().start(now).is_ok();
        let can_release = s.release_due(now).is_ok();
        assert_eq!(can_start, phase == "overdue", "{name}: start_succession at {now}");
        assert_eq!(can_release, phase == "releasable", "{name}: execute_succession at {now}");
        if phase == "quiet" || phase == "waiting" {
            assert!(!can_start && !can_release, "{name}");
        }

        // the soonest a release could come if the owner does nothing more
        let earliest = if !s.is_armed() {
            None
        } else if s.wait_open {
            Some(s.release_at().unwrap().max(now))
        } else {
            Some((s.deadline().unwrap() + 1).max(now) + s.wait_secs as i64)
        };
        assert_eq!(c["earliest_release"].as_str().map(|t| t.parse::<i64>().unwrap()), earliest, "{name}: earliest release");
        if let Some(t) = earliest {
            // and the program does allow it then, and not a second before: open the wait as early as allowed, then finish it
            let mut probe = s.clone();
            if !probe.wait_open {
                let start_at = (probe.deadline().unwrap() + 1).max(now);
                assert!(probe.clone().start(start_at - 1).is_err() || start_at == now, "{name}: no earlier start");
                probe.start(start_at).unwrap_or_else(|_| panic!("{name}: start at the earliest moment"));
            }
            probe.release_due(t).unwrap_or_else(|_| panic!("{name}: release at the earliest moment"));
            if t > now {
                assert!(probe.release_due(t - 1).is_err(), "{name}: not a second before");
            }
        }
    }
    for phase in ["unarmed", "quiet", "overdue", "waiting", "releasable"] {
        assert!(phases.contains(phase), "the table covers the {phase} phase");
    }
}
