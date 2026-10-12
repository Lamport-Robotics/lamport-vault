#![no_main]
//! Borsh `Action` decoding: never panics, and anything that decodes
//! re-encodes to the same bytes. The structured half builds actions from
//! arbitrary fields and checks the round trip.

use anchor_lang::prelude::Pubkey;
use arbitrary::Arbitrary;
use lamport_vault::Action;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Spec {
    Raw(Vec<u8>),
    TransferSol { to: [u8; 32], lamports: u64, issued_slot: u64, expiry_slot: u64 },
    TransferToken { mint: [u8; 32], to: [u8; 32], amount: u64, issued_slot: u64, expiry_slot: u64 },
    Rotate { new_lms_pubkey: [u8; 56], issued_slot: u64, expiry_slot: u64 },
    Close { to: [u8; 32], issued_slot: u64, expiry_slot: u64 },
}

fn check_raw(bytes: &[u8]) {
    if let Ok(a) = Action::decode(bytes) {
        let enc = a.encode();
        assert_eq!(enc, bytes, "decode/encode is not the identity on accepted input");
        assert_eq!(Action::decode(&enc).unwrap(), a);
        assert!(enc.len() <= lamport_vault::MAX_ACTION_LEN);
        assert_eq!(a.window(), (a.issued_slot(), a.expiry_slot()));
        assert!(matches!(enc[0], 0..=3));
    }
}

fuzz_target!(|spec: Spec| {
    let (action, expected_len) = match spec {
        Spec::Raw(bytes) => {
            check_raw(&bytes);
            return;
        }
        Spec::TransferSol { to, lamports, issued_slot, expiry_slot } => (
            Action::TransferSol { to: Pubkey::new_from_array(to), lamports, issued_slot, expiry_slot },
            57,
        ),
        Spec::TransferToken { mint, to, amount, issued_slot, expiry_slot } => (
            Action::TransferToken {
                mint: Pubkey::new_from_array(mint),
                to: Pubkey::new_from_array(to),
                amount,
                issued_slot,
                expiry_slot,
            },
            89,
        ),
        Spec::Rotate { new_lms_pubkey, issued_slot, expiry_slot } => {
            (Action::Rotate { new_lms_pubkey, issued_slot, expiry_slot }, 73)
        }
        Spec::Close { to, issued_slot, expiry_slot } => {
            (Action::Close { to: Pubkey::new_from_array(to), issued_slot, expiry_slot }, 49)
        }
    };
    let enc = action.encode();
    assert_eq!(enc.len(), expected_len);
    assert_eq!(Action::decode(&enc).unwrap(), action);
    let n = enc.len();
    assert_eq!(action.expiry_slot(), u64::from_le_bytes(enc[n - 8..].try_into().unwrap()));
    assert_eq!(action.issued_slot(), u64::from_le_bytes(enc[n - 16..n - 8].try_into().unwrap()));
    check_raw(&enc);
    // Trailing or missing bytes are errors.
    let mut longer = enc.clone();
    longer.push(0);
    assert!(Action::decode(&longer).is_err());
    assert!(Action::decode(&enc[..enc.len() - 1]).is_err());
});
