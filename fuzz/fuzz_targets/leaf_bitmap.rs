#![no_main]
//! `Vault::leaf_used` / `spend_leaf` across H5, H10 and H15 against a set
//! model: every leaf spends exactly once, out-of-range leaves are errors (not
//! panics) and read as spent, `spent` counts distinct leaves, and the first
//! free leaf computed through the API matches the model.

use anchor_lang::AnchorSerialize;
use arbitrary::Arbitrary;
use lamport_lms::LmsType;
use lamport_vault::Vault;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

#[derive(Arbitrary, Debug)]
enum Q {
    /// Reduced into the tree.
    InRange(u16),
    /// Anything, mostly outside the tree.
    Raw(u32),
    /// Edges: the last leaf, 2^h, 2^h + k, u32::MAX - k.
    Edge(u8),
}

#[derive(Arbitrary, Debug)]
enum Op {
    Spend(Q),
    Test(Q),
    FirstFree,
}

#[derive(Arbitrary, Debug)]
struct Input {
    height: u8,
    ops: Vec<Op>,
}

fuzz_target!(|input: Input| {
    let lms_type = match input.height % 3 {
        0 => LmsType::Sha256M32H5,
        1 => LmsType::Sha256M32H10,
        _ => LmsType::Sha256M32H15,
    };
    let leaves = lms_type.leaf_count();
    let mut vault = Vault {
        version: Vault::VERSION,
        bump: 255,
        vault_id: [2; 32],
        lms_pubkey: [0; 56],
        spent: 0,
        generation: 0,
        created_slot: 0,
        used: vec![0; Vault::bitmap_len(lms_type)],
        used_keys: Vec::new(),
    };
    assert_eq!(vault.used.len() * 8, leaves as usize);
    let mut model: BTreeSet<u32> = BTreeSet::new();
    let resolve = |q: Q| -> u32 {
        match q {
            Q::InRange(x) => x as u32 % leaves,
            Q::Raw(x) => x,
            Q::Edge(k) => match k % 4 {
                0 => leaves - 1,
                1 => leaves,
                2 => leaves.wrapping_add(k as u32),
                _ => u32::MAX - k as u32,
            },
        }
    };
    for op in input.ops {
        match op {
            Op::Spend(q) => {
                let q = resolve(q);
                let before = vault.spent;
                let r = vault.spend_leaf(q);
                if q >= leaves {
                    assert!(r.is_err(), "out-of-range spend {q} succeeded");
                    assert_eq!(vault.spent, before);
                } else if model.insert(q) {
                    assert!(r.is_ok(), "first spend of {q} failed: {r:?}");
                    assert_eq!(vault.spent, before + 1);
                } else {
                    assert!(r.is_err(), "second spend of {q} succeeded");
                    assert_eq!(vault.spent, before);
                }
            }
            Op::Test(q) => {
                let q = resolve(q);
                assert_eq!(vault.leaf_used(q), q >= leaves || model.contains(&q), "leaf_used({q})");
            }
            Op::FirstFree => {
                let api = (0..leaves).find(|&q| !vault.leaf_used(q));
                let model_first = (0..leaves).find(|q| !model.contains(q));
                assert_eq!(api, model_first);
            }
        }
        assert_eq!(vault.spent as usize, model.len());
    }
    // Final sweep: bitmap bits are exactly the model, and the account size is stable.
    for q in 0..leaves {
        assert_eq!(vault.leaf_used(q), model.contains(&q));
        assert_eq!(vault.used[(q / 8) as usize] >> (q % 8) & 1 == 1, model.contains(&q));
    }
    assert!(vault.leaf_used(leaves));
    assert!(vault.leaf_used(u32::MAX));
    assert_eq!(Vault::space(lms_type, 0), 8 + vault.try_to_vec().unwrap().len());
});
