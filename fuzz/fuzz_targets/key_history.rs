#![no_main]
//! `Vault::used_keys` / `has_used_key` against a model, through the rotate
//! rules the program applies (refuse a reused key, cap the history at
//! `MAX_KEY_HISTORY`), plus raw pushes with duplicates. Also checks that
//! `Vault::space` matches the Borsh size at every step.

use anchor_lang::AnchorSerialize;
use arbitrary::Arbitrary;
use lamport_lms::LmsType;
use lamport_vault::{Vault, KEY_HASH_LEN, MAX_KEY_HISTORY};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    /// The program's rotate: refused if reused or history full.
    Rotate(u8),
    /// Direct push of a hash, as a corrupted or legacy account might hold; duplicates allowed.
    PushRaw(u8),
    Query(u8),
}

#[derive(Arbitrary, Debug)]
struct Input {
    height: u8,
    ops: Vec<Op>,
}

fn key(idx: u8) -> [u8; 56] {
    let mut k = [idx; 56];
    k[..4].copy_from_slice(&6u32.to_be_bytes());
    k[4..8].copy_from_slice(&3u32.to_be_bytes());
    k
}

fuzz_target!(|input: Input| {
    let lms_type = match input.height % 3 {
        0 => LmsType::Sha256M32H5,
        1 => LmsType::Sha256M32H10,
        _ => LmsType::Sha256M32H15,
    };
    let mut vault = Vault {
        version: Vault::VERSION,
        bump: 255,
        vault_id: [1; 32],
        lms_pubkey: key(0),
        spent: 0,
        generation: 0,
        created_slot: 0,
        used: vec![0; Vault::bitmap_len(lms_type)],
        used_keys: Vec::new(),
    };
    // Model: current key bytes plus the set of past hashes (with multiplicity).
    let mut current = key(0);
    let mut past: Vec<[u8; KEY_HASH_LEN]> = Vec::new();
    let mut rotations = 0usize;

    let check = |vault: &Vault, current: &[u8; 56], past: &[[u8; KEY_HASH_LEN]]| {
        assert_eq!(vault.lms_pubkey, *current);
        assert_eq!(vault.used_keys, past);
        assert_eq!(vault.used_keys.len(), past.len());
        let space = Vault::space(lms_type, vault.used_keys.len());
        assert_eq!(space, 8 + vault.try_to_vec().unwrap().len(), "space() vs Borsh size");
        for idx in 0..=255u8 {
            let k = key(idx);
            let expect = k == *current || past.contains(&Vault::key_hash(&k));
            assert_eq!(vault.has_used_key(&k), expect, "has_used_key({idx})");
        }
    };

    for op in input.ops {
        match op {
            Op::Rotate(idx) => {
                let new = key(idx);
                // The program's checks, in order (lib.rs rotate).
                if vault.has_used_key(&new) {
                    assert!(new == current || past.contains(&Vault::key_hash(&new)));
                    continue;
                }
                if vault.used_keys.len() >= MAX_KEY_HISTORY as usize {
                    assert_eq!(vault.used_keys.len(), MAX_KEY_HISTORY as usize, "history never exceeds the cap");
                    continue;
                }
                let old = vault.lms_pubkey;
                vault.used_keys.push(Vault::key_hash(&old));
                vault.lms_pubkey = new;
                vault.generation = vault.generation.checked_add(1).unwrap();
                past.push(Vault::key_hash(&old));
                current = new;
                rotations += 1;
                assert!(vault.has_used_key(&old), "the old key is used after rotate");
                assert!(vault.has_used_key(&new), "the current key is used");
            }
            Op::PushRaw(idx) => {
                if vault.used_keys.len() >= MAX_KEY_HISTORY as usize {
                    continue;
                }
                let h = Vault::key_hash(&key(idx));
                vault.used_keys.push(h);
                past.push(h);
                assert!(vault.has_used_key(&key(idx)));
            }
            Op::Query(idx) => {
                let k = key(idx);
                assert_eq!(vault.has_used_key(&k), k == current || past.contains(&Vault::key_hash(&k)));
            }
        }
        assert!(vault.used_keys.len() <= MAX_KEY_HISTORY as usize);
        assert_eq!(vault.generation as usize, rotations);
    }
    check(&vault, &current, &past);
    // 256 distinct keys exist, more than the cap, so a long enough run hits
    // HistoryFull; the cap is exactly 128 in the production build.
    assert_eq!(MAX_KEY_HISTORY, 128);
});
