//! Known-answer tests for the RFC 9858 SHA-256/192 parameter sets, against
//! `kat/rfc9858_sha256_192.json` (RFC 9858 Appendix A.1 and A.4).
//!
//! Run with `cargo test -p lamport-lms --features sign` (`sign` enables `sha256-192`).

#![cfg(feature = "sha256-192")]

use lamport_lms::{lms_verify, Error, LmotsType, LmsPublicKey, LmsType};
use serde::Deserialize;

const KAT_JSON: &str = include_str!("../../../kat/rfc9858_sha256_192.json");

#[derive(Deserialize)]
struct Kat {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Vector {
    name: String,
    lms_type: u32,
    lmots_type: u32,
    seed_hex: String,
    #[serde(rename = "I_hex")]
    i_hex: String,
    public_key_hex: String,
    q: u32,
    message_hex: String,
    signature_hex: String,
}

fn kat() -> Vec<Vector> {
    serde_json::from_str::<Kat>(KAT_JSON).expect("kat json").vectors
}

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

#[test]
fn covers_w8_h5_and_w4_h20() {
    let v = kat();
    let sets: Vec<(u32, u32)> = v.iter().map(|v| (v.lms_type, v.lmots_type)).collect();
    assert_eq!(sets, vec![(10, 8), (13, 7)]);
}

#[test]
fn rfc_signatures_verify() {
    for v in kat() {
        let pk = LmsPublicKey::parse(&hx(&v.public_key_hex)).unwrap();
        assert_eq!(pk.encode(), hx(&v.public_key_hex), "{}", v.name);
        assert_eq!(lms_verify(&pk, &hx(&v.message_hex), &hx(&v.signature_hex)), Ok(v.q), "{}", v.name);
    }
}

#[test]
fn every_flipped_bit_region_fails() {
    for v in kat() {
        let pk = LmsPublicKey::parse(&hx(&v.public_key_hex)).unwrap();
        let msg = hx(&v.message_hex);
        let sig = hx(&v.signature_hex);
        // q, C, first chain value, last chain value, lms type, first and last path node
        let ots_len = pk.lmots_type.signature_len();
        for pos in [3, 8, 4 + 4 + 24, 4 + ots_len - 1, 4 + ots_len + 3, 8 + ots_len, sig.len() - 1] {
            let mut bad = sig.clone();
            bad[pos] ^= 0x01;
            assert!(lms_verify(&pk, &msg, &bad).is_err(), "{} byte {pos}", v.name);
        }
        let mut bad_msg = msg.clone();
        bad_msg[0] ^= 1;
        assert_eq!(lms_verify(&pk, &bad_msg, &sig), Err(Error::InvalidSignature));
    }
}

/// Signatures made by the TypeScript SDK (`kat/sdk_signatures_sha256_192.json`) verify here.
#[test]
fn sdk_signatures_verify_under_the_rust_verifier() {
    #[derive(Deserialize)]
    struct File {
        vectors: Vec<Key>,
    }
    #[derive(Deserialize)]
    struct Key {
        name: String,
        public_key_hex: String,
        signatures: Vec<Sig>,
    }
    #[derive(Deserialize)]
    struct Sig {
        q: u32,
        message_hex: String,
        signature_hex: String,
    }
    let f: File = serde_json::from_str(include_str!("../../../kat/sdk_signatures_sha256_192.json")).unwrap();
    let mut count = 0;
    for k in f.vectors {
        let pk = LmsPublicKey::parse(&hx(&k.public_key_hex)).unwrap();
        for s in k.signatures {
            assert_eq!(lms_verify(&pk, &hx(&s.message_hex), &hx(&s.signature_hex)), Ok(s.q), "{}", k.name);
            count += 1;
        }
    }
    assert_eq!(count, 3);
}

#[cfg(feature = "sign")]
mod sign {
    use super::*;
    use lamport_lms::LmsPrivateKey;

    /// A.1 is small enough (H5) to rebuild: the public key and the signature
    /// both come out byte for byte, including the randomizer C, which uses
    /// this crate's `0xfffd` derivation.
    #[test]
    fn a1_reproduces_from_seed() {
        let v = &kat()[0];
        let key = LmsPrivateKey::from_seed_slice(
            LmsType::Sha256M24H5,
            LmotsType::Sha256N24W8,
            hx(&v.i_hex).try_into().unwrap(),
            &hx(&v.seed_hex),
        );
        assert_eq!(key.public_key().encode(), hx(&v.public_key_hex));
        assert_eq!(key.sign(v.q, &hx(&v.message_hex)), hx(&v.signature_hex));
    }

    #[test]
    fn round_trip_every_sha256_192_set() {
        for (lms, ots) in [
            (LmsType::Sha256M24H5, LmotsType::Sha256N24W4),
            (LmsType::Sha256M24H5, LmotsType::Sha256N24W8),
        ] {
            let key = LmsPrivateKey::new(lms, ots, [7; 16], [9; 32]);
            let tree = key.tree();
            let pk = key.public_key_from_tree(&tree);
            assert_eq!(pk.encode().len(), 48);
            for q in [0u32, 13, 31] {
                let sig = key.sign_with_tree(&tree, q, b"lamport-vault/v1 test");
                assert_eq!(sig.len(), pk.signature_len());
                assert_eq!(lms_verify(&pk, b"lamport-vault/v1 test", &sig), Ok(q));
                assert!(lms_verify(&pk, b"lamport-vault/v1 tesT", &sig).is_err());
            }
        }
    }

    /// A 32-byte derived seed gives a SHA-256/192 key from its first 24 bytes.
    #[test]
    fn new_uses_first_n_seed_bytes() {
        let mut seed = [0u8; 32];
        for (k, b) in seed.iter_mut().enumerate() {
            *b = k as u8;
        }
        let a = LmsPrivateKey::new(LmsType::Sha256M24H5, LmotsType::Sha256N24W8, [1; 16], seed);
        let b = LmsPrivateKey::from_seed_slice(LmsType::Sha256M24H5, LmotsType::Sha256N24W8, [1; 16], &seed[..24]);
        assert_eq!(a, b);
    }
}
