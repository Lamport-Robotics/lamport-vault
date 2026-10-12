//! Known-answer tests against `kat/lms_sha256_w4.json` (vectors produced by an
//! independent RFC 8554 implementation) plus negative tests and, with the
//! `sign` feature, key reproduction and sign/verify round trips.
//!
//! Run everything with `cargo test -p lamport-lms --features sign`.

use lamport_lms::{lms_verify, parse_lms_signature, Error, LmsPublicKey};
use serde::Deserialize;

const KAT_JSON: &str = include_str!("../../../kat/lms_sha256_w4.json");
/// Signatures produced by the TypeScript SDK with the same keys; they must
/// verify under this crate (DESIGN.md section 7).
const SDK_JSON: &str = include_str!("../../../kat/sdk_signatures.json");

#[derive(Deserialize)]
struct Kat {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    lms_type: u32,
    lmots_type: u32,
    height: u32,
    seed_hex: String,
    #[serde(rename = "I_hex")]
    i_hex: String,
    public_key_hex: String,
    signatures: Vec<Sig>,
}

#[derive(Deserialize)]
struct Sig {
    q: u32,
    message_hex: String,
    signature_hex: String,
}

fn kat() -> Kat {
    serde_json::from_str(KAT_JSON).expect("kat json")
}

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

#[test]
fn kat_has_h5_and_h10() {
    let k = kat();
    let heights: Vec<u32> = k.vectors.iter().map(|v| v.height).collect();
    assert!(heights.contains(&5) && heights.contains(&10), "{heights:?}");
    assert!(k.vectors.iter().all(|v| v.lmots_type == 3));
    assert!(k.vectors.iter().all(|v| !v.signatures.is_empty()));
}

#[test]
fn kat_public_keys_parse_with_declared_typecodes() {
    for v in kat().vectors {
        let pk = LmsPublicKey::parse(&hx(&v.public_key_hex)).unwrap();
        assert_eq!(pk.lms_type.typecode(), v.lms_type, "{}", v.name);
        assert_eq!(pk.lmots_type.typecode(), v.lmots_type, "{}", v.name);
        assert_eq!(pk.lms_type.height(), v.height, "{}", v.name);
        assert_eq!(pk.i.to_vec(), hx(&v.i_hex), "{}", v.name);
        assert_eq!(pk.to_bytes().to_vec(), hx(&v.public_key_hex), "{}", v.name);
    }
}

#[test]
fn kat_every_signature_verifies() {
    for v in kat().vectors {
        let pk = LmsPublicKey::parse(&hx(&v.public_key_hex)).unwrap();
        for s in &v.signatures {
            let sig = hx(&s.signature_hex);
            assert_eq!(sig.len(), pk.signature_len(), "{} q={}", v.name, s.q);
            let q = lms_verify(&pk, &hx(&s.message_hex), &sig)
                .unwrap_or_else(|e| panic!("{} q={} failed: {e}", v.name, s.q));
            assert_eq!(q, s.q);
            let parsed = parse_lms_signature(&sig, &pk).unwrap();
            assert_eq!(parsed.q, s.q);
            assert_eq!(parsed.lms_type, pk.lms_type);
            assert_eq!(parsed.lmots.lmots_type, pk.lmots_type);
        }
    }
}

#[test]
fn sdk_signatures_verify_under_the_rust_verifier() {
    let k: Kat = serde_json::from_str(SDK_JSON).expect("sdk json");
    assert!(!k.vectors.is_empty());
    for v in &k.vectors {
        let pk = LmsPublicKey::parse(&hx(&v.public_key_hex)).unwrap();
        assert!(!v.signatures.is_empty(), "{}", v.name);
        for s in &v.signatures {
            let sig = hx(&s.signature_hex);
            let msg = hx(&s.message_hex);
            assert_eq!(lms_verify(&pk, &msg, &sig), Ok(s.q), "{} q={}", v.name, s.q);
            let mut bad = sig.clone();
            bad[50] ^= 0x10;
            assert_eq!(lms_verify(&pk, &msg, &bad), Err(Error::InvalidSignature), "{} q={}", v.name, s.q);
        }
    }
}

/// Every bit of one full H5 signature; one bit per byte for all the others.
#[test]
fn kat_flipped_signature_bit_fails() {
    let k = kat();
    let mut exhaustive_done = false;
    for v in &k.vectors {
        let pk = LmsPublicKey::parse(&hx(&v.public_key_hex)).unwrap();
        for s in &v.signatures {
            let msg = hx(&s.message_hex);
            let good = hx(&s.signature_hex);
            let exhaustive = !exhaustive_done && v.height == 5;
            for byte in 0..good.len() {
                let bits: Vec<u8> = if exhaustive {
                    (0..8).collect()
                } else {
                    vec![(byte % 8) as u8]
                };
                for bit in bits {
                    let mut bad = good.clone();
                    bad[byte] ^= 1 << bit;
                    let r = lms_verify(&pk, &msg, &bad);
                    assert!(
                        r.is_err(),
                        "{} q={} byte {byte} bit {bit}: flipped bit still verified",
                        v.name,
                        s.q
                    );
                }
            }
            if exhaustive {
                exhaustive_done = true;
            }
        }
    }
    assert!(exhaustive_done);
}

#[test]
fn kat_flipped_message_bit_fails() {
    for v in kat().vectors {
        let pk = LmsPublicKey::parse(&hx(&v.public_key_hex)).unwrap();
        for s in &v.signatures {
            let msg = hx(&s.message_hex);
            let sig = hx(&s.signature_hex);
            if msg.is_empty() {
                // Empty message: any appended byte must fail.
                assert_eq!(lms_verify(&pk, &[0u8], &sig), Err(Error::InvalidSignature));
                continue;
            }
            for byte in 0..msg.len() {
                let mut bad = msg.clone();
                bad[byte] ^= 1 << (byte % 8);
                assert_eq!(
                    lms_verify(&pk, &bad, &sig),
                    Err(Error::InvalidSignature),
                    "{} q={} message byte {byte}",
                    v.name,
                    s.q
                );
            }
            // Truncated and extended messages.
            assert!(lms_verify(&pk, &msg[..msg.len() - 1], &sig).is_err());
            let mut ext = msg.clone();
            ext.push(0);
            assert!(lms_verify(&pk, &ext, &sig).is_err());
        }
    }
}

#[test]
fn kat_wrong_q_fails() {
    for v in kat().vectors {
        let pk = LmsPublicKey::parse(&hx(&v.public_key_hex)).unwrap();
        let leaves = 1u32 << v.height;
        for s in &v.signatures {
            let msg = hx(&s.message_hex);
            let good = hx(&s.signature_hex);
            for other in [s.q.wrapping_sub(1), s.q + 1, 0, leaves - 1, s.q ^ 1] {
                if other == s.q {
                    continue;
                }
                let mut bad = good.clone();
                bad[0..4].copy_from_slice(&other.to_be_bytes());
                let r = lms_verify(&pk, &msg, &bad);
                if other >= leaves {
                    assert_eq!(r, Err(Error::LeafOutOfRange), "{} q={other}", v.name);
                } else {
                    assert_eq!(r, Err(Error::InvalidSignature), "{} q={other}", v.name);
                }
            }
            // q = 2^h exactly and q = u32::MAX are out of range.
            for other in [leaves, u32::MAX] {
                let mut bad = good.clone();
                bad[0..4].copy_from_slice(&other.to_be_bytes());
                assert_eq!(lms_verify(&pk, &msg, &bad), Err(Error::LeafOutOfRange));
            }
        }
    }
}

#[test]
fn kat_wrong_i_fails() {
    for v in kat().vectors {
        let good = LmsPublicKey::parse(&hx(&v.public_key_hex)).unwrap();
        for s in &v.signatures {
            let msg = hx(&s.message_hex);
            let sig = hx(&s.signature_hex);
            for byte in 0..16 {
                let mut pk = good;
                pk.i[byte] ^= 0x01;
                assert_eq!(lms_verify(&pk, &msg, &sig), Err(Error::InvalidSignature));
            }
            // And a wrong root.
            for byte in 0..32 {
                let mut pk = good;
                pk.t1[byte] ^= 0x80;
                assert_eq!(lms_verify(&pk, &msg, &sig), Err(Error::InvalidSignature));
            }
        }
    }
}

#[test]
fn kat_cross_key_and_length_errors() {
    let k = kat();
    let h5 = k.vectors.iter().find(|v| v.height == 5).unwrap();
    let h10 = k.vectors.iter().find(|v| v.height == 10).unwrap();
    let pk5 = LmsPublicKey::parse(&hx(&h5.public_key_hex)).unwrap();
    let pk10 = LmsPublicKey::parse(&hx(&h10.public_key_hex)).unwrap();
    let s5 = &h5.signatures[0];
    let s10 = &h10.signatures[0];
    let sig5 = hx(&s5.signature_hex);
    let sig10 = hx(&s10.signature_hex);

    // An H5 signature against an H10 key: the LMS typecode inside the
    // signature does not match the key.
    assert_eq!(
        lms_verify(&pk10, &hx(&s5.message_hex), &sig5),
        Err(Error::LmsTypeMismatch)
    );
    assert_eq!(
        lms_verify(&pk5, &hx(&s10.message_hex), &sig10),
        Err(Error::LmsTypeMismatch)
    );

    // Same height, different key (I): plain invalid.
    let mut other = pk5;
    other.i[0] ^= 0xff;
    assert_eq!(
        lms_verify(&other, &hx(&s5.message_hex), &sig5),
        Err(Error::InvalidSignature)
    );

    // Lengths.
    assert_eq!(lms_verify(&pk5, &[], &sig5[..sig5.len() - 1]), Err(Error::SignatureLength));
    let mut ext = sig5.clone();
    ext.push(0);
    assert_eq!(lms_verify(&pk5, &[], &ext), Err(Error::SignatureLength));
    assert_eq!(lms_verify(&pk5, &[], &sig5[..7]), Err(Error::SignatureLength));
    assert_eq!(lms_verify(&pk5, &[], &[]), Err(Error::SignatureLength));

    // Wrong OTS typecode inside the signature.
    let mut bad = sig5.clone();
    bad[4..8].copy_from_slice(&4u32.to_be_bytes());
    assert_eq!(lms_verify(&pk5, &[], &bad), Err(Error::LmotsTypeMismatch));
    // Wrong LMS typecode inside the signature (position 4 + 2180).
    let mut bad = sig5.clone();
    bad[2184..2188].copy_from_slice(&6u32.to_be_bytes());
    assert_eq!(lms_verify(&pk5, &[], &bad), Err(Error::LmsTypeMismatch));
}

#[cfg(feature = "sign")]
mod signing {
    use super::*;
    use lamport_lms::{LmotsType, LmsPrivateKey, LmsType};

    fn key_from_vector(v: &Vector) -> LmsPrivateKey {
        LmsPrivateKey::new(
            LmsType::from_typecode(v.lms_type).unwrap(),
            LmotsType::from_typecode(v.lmots_type).unwrap(),
            hx(&v.i_hex).try_into().unwrap(),
            hx(&v.seed_hex).try_into().unwrap(),
        )
    }

    /// xorshift64*, enough for test messages.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| (self.next() >> 24) as u8).collect()
        }
    }

    #[test]
    fn kat_public_keys_reproduced_from_seed_and_i() {
        for v in kat().vectors {
            let sk = key_from_vector(&v);
            let pk = sk.public_key();
            assert_eq!(
                hex::encode(pk.to_bytes()),
                v.public_key_hex,
                "{}: public key from SEED/I differs",
                v.name
            );
        }
    }

    #[test]
    fn our_signatures_verify_against_kat_public_keys() {
        // Our signer uses a deterministic C; the KAT signer used a random C.
        // Both must verify under the same public key.
        for v in kat().vectors {
            let sk = key_from_vector(&v);
            let tree = sk.tree();
            let pk = LmsPublicKey::parse(&hx(&v.public_key_hex)).unwrap();
            for s in &v.signatures {
                let msg = hx(&s.message_hex);
                let ours = sk.sign_with_tree(&tree, s.q, &msg);
                assert_eq!(ours.len(), pk.signature_len());
                assert_eq!(lms_verify(&pk, &msg, &ours), Ok(s.q), "{} q={}", v.name, s.q);
                // Same leaf, same message, different C: the KAT signature and
                // ours differ in C and in y but both verify.
                let theirs = hx(&s.signature_hex);
                assert_ne!(ours[8..40], theirs[8..40], "C should differ");
            }
        }
    }

    #[test]
    fn round_trip_h5_random_messages() {
        let mut rng = Rng(0x5eed_0000_0000_0005);
        let sk = LmsPrivateKey::new(
            LmsType::Sha256M32H5,
            LmotsType::Sha256N32W4,
            rng.bytes(16).try_into().unwrap(),
            rng.bytes(32).try_into().unwrap(),
        );
        let tree = sk.tree();
        let pk = sk.public_key_from_tree(&tree);
        assert_eq!(LmsPublicKey::parse(&pk.to_bytes()).unwrap(), pk);
        for q in 0..32u32 {
            let len = (rng.next() % 300) as usize;
            let msg = rng.bytes(len);
            let sig = sk.sign_with_tree(&tree, q, &msg);
            assert_eq!(sig.len(), 2348);
            assert_eq!(lms_verify(&pk, &msg, &sig), Ok(q), "q={q}");
            let mut other = msg.clone();
            other.push(1);
            assert_eq!(lms_verify(&pk, &other, &sig), Err(Error::InvalidSignature));
        }
        // A signature from a different key over the same message fails.
        let sk2 = LmsPrivateKey::new(sk.lms_type, sk.lmots_type, sk.i, rng.bytes(32).try_into().unwrap());
        let msg = rng.bytes(40);
        let sig2 = sk2.sign(3, &msg);
        assert_eq!(lms_verify(&pk, &msg, &sig2), Err(Error::InvalidSignature));
    }

    #[test]
    fn round_trip_h10_random_messages() {
        let mut rng = Rng(0x5eed_0000_0000_0010);
        let sk = LmsPrivateKey::new(
            LmsType::Sha256M32H10,
            LmotsType::Sha256N32W4,
            rng.bytes(16).try_into().unwrap(),
            rng.bytes(32).try_into().unwrap(),
        );
        let tree = sk.tree();
        let pk = sk.public_key_from_tree(&tree);
        let mut qs: Vec<u32> = (0..12).map(|_| (rng.next() % 1024) as u32).collect();
        qs.extend([0, 1, 511, 512, 1022, 1023]);
        for q in qs {
            let len = (rng.next() % 600) as usize;
            let msg = rng.bytes(len);
            let sig = sk.sign_with_tree(&tree, q, &msg);
            assert_eq!(sig.len(), 2508);
            assert_eq!(lms_verify(&pk, &msg, &sig), Ok(q), "q={q}");
            let mut bad = sig.clone();
            bad[2508 - 1] ^= 1; // last path byte
            assert_eq!(lms_verify(&pk, &msg, &bad), Err(Error::InvalidSignature));
            let mut bad = sig.clone();
            bad[40] ^= 1; // y[0]
            assert_eq!(lms_verify(&pk, &msg, &bad), Err(Error::InvalidSignature));
        }
    }

    #[test]
    fn explicit_randomizer_is_honoured() {
        let sk = LmsPrivateKey::new(
            LmsType::Sha256M32H5,
            LmotsType::Sha256N32W4,
            [7u8; 16],
            [9u8; 32],
        );
        let tree = sk.tree();
        let pk = sk.public_key_from_tree(&tree);
        let c = [0xabu8; 32];
        let ots = sk.ots_sign_with_randomizer(4, b"hello", &c);
        assert_eq!(&ots[4..36], &c);
        let mut sig = 4u32.to_be_bytes().to_vec();
        sig.extend_from_slice(&ots);
        sig.extend_from_slice(&5u32.to_be_bytes());
        for n in tree.path(4) {
            sig.extend_from_slice(&n);
        }
        assert_eq!(lms_verify(&pk, b"hello", &sig), Ok(4));
    }

    #[test]
    #[should_panic(expected = "leaf index out of range")]
    fn signing_past_the_last_leaf_panics() {
        let sk = LmsPrivateKey::new(
            LmsType::Sha256M32H5,
            LmotsType::Sha256N32W4,
            [1u8; 16],
            [2u8; 32],
        );
        let _ = sk.sign(32, b"x");
    }
}
