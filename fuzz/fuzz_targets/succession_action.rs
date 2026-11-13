#![no_main]
//! Borsh `Action` decoding in the Heir-enabled build, where variant 5 (`SetSuccession`) exists:
//! never panics, anything that decodes re-encodes to the same bytes, and a decoded `SetSuccession`
//! is exactly 129 bytes with its validity window last. The structured half builds the action from
//! arbitrary fields and checks the round trip. Same shape as `action_decode`, which covers the
//! vault's own five variants in the build without the feature.

use anchor_lang::prelude::Pubkey;
use arbitrary::Arbitrary;
use lamport_vault::succession::{SetSuccession, Succession};
use lamport_vault::Action;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Spec {
    Raw(Vec<u8>),
    /// Arbitrary bytes behind the `SetSuccession` variant byte, so the fuzzer does not have to find it.
    RawSet(Vec<u8>),
    Set { claim: [u8; 32], window_secs: u64, wait_secs: u64, checkin_key: [u8; 32], contact_key: [u8; 32], issued_slot: u64, expiry_slot: u64 },
}

fn check_raw(bytes: &[u8]) {
    if let Ok(a) = Action::decode(bytes) {
        let enc = a.encode();
        assert_eq!(enc, bytes, "decode/encode is not the identity on accepted input");
        assert_eq!(Action::decode(&enc).unwrap(), a);
        assert!(enc.len() <= lamport_vault::MAX_ACTION_LEN);
        assert_eq!(a.window(), (a.issued_slot(), a.expiry_slot()));
        assert!(matches!(enc[0], 0..=5));
        let n = enc.len();
        assert_eq!(a.expiry_slot(), u64::from_le_bytes(enc[n - 8..].try_into().unwrap()));
        assert_eq!(a.issued_slot(), u64::from_le_bytes(enc[n - 16..n - 8].try_into().unwrap()));
        if let Action::SetSuccession(plan) = &a {
            assert_eq!(enc[0], 5);
            assert_eq!(n, 129);
            // Whatever the plan says, applying it either fails or leaves a block that is exactly
            // the plan: never a panic, never a half-applied plan.
            let mut block = Succession::default();
            let before = block.clone();
            match block.set(plan) {
                Ok(()) => {
                    assert_eq!((block.claim, block.window_secs, block.wait_secs), (plan.claim, plan.window_secs, plan.wait_secs));
                    assert_eq!((block.checkin_key, block.contact_key), (plan.checkin_key, plan.contact_key));
                    assert!(!block.contact_used);
                }
                Err(_) => assert_eq!(block, before, "a refused plan changed the block"),
            }
        } else {
            assert_ne!(enc[0], 5);
        }
    }
}

fuzz_target!(|spec: Spec| {
    match spec {
        Spec::Raw(bytes) => check_raw(&bytes),
        Spec::RawSet(mut bytes) => {
            bytes.insert(0, 5);
            check_raw(&bytes);
        }
        Spec::Set { claim, window_secs, wait_secs, checkin_key, contact_key, issued_slot, expiry_slot } => {
            let plan = SetSuccession {
                claim: Pubkey::new_from_array(claim),
                window_secs,
                wait_secs,
                checkin_key: Pubkey::new_from_array(checkin_key),
                contact_key: Pubkey::new_from_array(contact_key),
                issued_slot,
                expiry_slot,
            };
            let action = Action::SetSuccession(plan);
            let enc = action.encode();
            assert_eq!(enc.len(), 129);
            assert_eq!(enc[0], 5);
            assert_eq!(Action::decode(&enc).unwrap(), action);
            check_raw(&enc);
            // Trailing or missing bytes are errors.
            let mut longer = enc.clone();
            longer.push(0);
            assert!(Action::decode(&longer).is_err());
            assert!(Action::decode(&enc[..enc.len() - 1]).is_err());
        }
    }
});
