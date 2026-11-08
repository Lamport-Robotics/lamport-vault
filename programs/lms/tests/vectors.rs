//! Independent known-answer vectors beyond `kat/lms_sha256_w4.json`:
//!
//! * `kat/rfc8554_appendix_f.json`: RFC 8554 Appendix F test cases 1 and 2,
//!   HSS signatures whose LMS layers are H5/W8, H10/W4 and H5/W8. The HSS
//!   envelope is walked here, in the test; the crate only knows LMS.
//! * `kat/hashsigs_w4.json` and `kat/hashsigs_w1w2w8.json`: keys and
//!   signatures produced by Cisco's hash-sigs C implementation (W4 at
//!   H5/H10/H15, and W1/W2/W8 at H5 or H10), public keys and signatures only.
//!
//! W8, W1 and W2 keys go through [`LmsPublicKey::parse_any`]; the program's
//! parser, [`LmsPublicKey::parse`], must keep refusing them.
//!
//! Run with `cargo test -p lamport-lms --features sign`.

use lamport_lms::{lms_verify, parse_lms_signature, Error, LmotsType, LmsPublicKey, LmsType};
use serde::Deserialize;

const RFC_JSON: &str = include_str!("../../../kat/rfc8554_appendix_f.json");
const HASHSIGS_W4_JSON: &str = include_str!("../../../kat/hashsigs_w4.json");
const HASHSIGS_OTHER_JSON: &str = include_str!("../../../kat/hashsigs_w1w2w8.json");

/// The hash-sigs commit the vectors were generated with; pinned so the JSON
/// cannot silently drift from what docs/VECTORS.md says.
const HASHSIGS_COMMIT: &str = "cea4dda4f937e56ab42e1a74665f6397473a2838";

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

// ---------------------------------------------------------------- RFC 8554 F

#[derive(Deserialize)]
struct Rfc {
    test_cases: Vec<TestCase>,
}

#[derive(Deserialize)]
struct TestCase {
    test_case: u32,
    levels: u32,
    hss_public_key_hex: String,
    message_hex: String,
    nspk: u32,
    private_keys: Option<Vec<PrivateKey>>,
    lms_layers: Vec<Layer>,
    hss_signature_hex: String,
}

#[derive(Deserialize)]
struct PrivateKey {
    level: u32,
    seed_hex: String,
    #[serde(rename = "I_hex")]
    i_hex: String,
}

#[derive(Deserialize)]
struct Layer {
    layer: u32,
    public_key_hex: String,
    lms_type: u32,
    lmots_type: u32,
    #[serde(rename = "I_hex")]
    i_hex: String,
    message_hex: String,
    q: u32,
    signature_hex: String,
}

fn rfc() -> Rfc {
    serde_json::from_str(RFC_JSON).expect("rfc json")
}

#[test]
fn rfc_appendix_f_shape() {
    let r = rfc();
    assert_eq!(r.test_cases.len(), 2);
    let tc1 = &r.test_cases[0];
    let tc2 = &r.test_cases[1];
    assert_eq!((tc1.test_case, tc1.levels, tc1.nspk), (1, 2, 1));
    assert_eq!((tc2.test_case, tc2.levels, tc2.nspk), (2, 2, 1));
    // Test case 1: H5/W8 on both levels. Test case 2: H10/W4 on top, H5/W8 below.
    let types = |tc: &TestCase| -> Vec<(u32, u32)> { tc.lms_layers.iter().map(|l| (l.lms_type, l.lmots_type)).collect() };
    assert_eq!(types(tc1), vec![(5, 4), (5, 4)]);
    assert_eq!(types(tc2), vec![(6, 3), (5, 4)]);
    assert!(tc1.private_keys.is_none());
    assert_eq!(tc2.private_keys.as_ref().unwrap().len(), 2);
}

#[test]
fn rfc_appendix_f_every_lms_layer_verifies() {
    for tc in rfc().test_cases {
        for l in &tc.lms_layers {
            let pk = LmsPublicKey::parse_any(&hx(&l.public_key_hex))
                .unwrap_or_else(|e| panic!("tc{} layer {}: {e}", tc.test_case, l.layer));
            assert_eq!(pk.lms_type.typecode(), l.lms_type);
            assert_eq!(pk.lmots_type.typecode(), l.lmots_type);
            assert_eq!(pk.i.to_vec(), hx(&l.i_hex));
            let sig = hx(&l.signature_hex);
            assert_eq!(sig.len(), pk.signature_len(), "tc{} layer {}", tc.test_case, l.layer);
            let parsed = parse_lms_signature(&sig, &pk).unwrap();
            assert_eq!(parsed.q, l.q);
            assert_eq!(parsed.lmots.lmots_type, pk.lmots_type);
            assert_eq!(parsed.lmots.y.len(), 32 * pk.lmots_type.p());
            let got = lms_verify(&pk, &hx(&l.message_hex), &sig);
            assert_eq!(got, Ok(l.q), "tc{} layer {} ({:?})", tc.test_case, l.layer, pk.lmots_type);
        }
    }
}

/// RFC 8554 Section 6.3: walk the HSS public key and signature bytes with the
/// LMS verifier, which is all a two-level verifier needs.
fn hss_verify(hss_pk: &[u8], message: &[u8], hss_sig: &[u8]) -> Result<Vec<u32>, String> {
    let levels = u32::from_be_bytes(hss_pk[0..4].try_into().unwrap());
    let mut pk = LmsPublicKey::parse_any(&hss_pk[4..]).map_err(|e| e.to_string())?;
    let nspk = u32::from_be_bytes(hss_sig[0..4].try_into().unwrap());
    if nspk + 1 != levels {
        return Err(format!("Nspk {nspk} does not match levels {levels}"));
    }
    let mut pos = 4;
    let mut qs = Vec::new();
    for _ in 0..nspk {
        let sig_len = pk.signature_len();
        let sig = hss_sig.get(pos..pos + sig_len).ok_or("short")?;
        let next_pk = hss_sig.get(pos + sig_len..pos + sig_len + 56).ok_or("short")?;
        qs.push(lms_verify(&pk, next_pk, sig).map_err(|e| e.to_string())?);
        pk = LmsPublicKey::parse_any(next_pk).map_err(|e| e.to_string())?;
        pos += sig_len + 56;
    }
    let sig = hss_sig.get(pos..).ok_or("short")?;
    if sig.len() != pk.signature_len() {
        return Err("final signature length".into());
    }
    qs.push(lms_verify(&pk, message, sig).map_err(|e| e.to_string())?);
    Ok(qs)
}

#[test]
fn rfc_appendix_f_hss_envelope_verifies_end_to_end() {
    for tc in rfc().test_cases {
        let qs = hss_verify(&hx(&tc.hss_public_key_hex), &hx(&tc.message_hex), &hx(&tc.hss_signature_hex))
            .unwrap_or_else(|e| panic!("tc{}: {e}", tc.test_case));
        let want: Vec<u32> = tc.lms_layers.iter().map(|l| l.q).collect();
        assert_eq!(qs, want, "tc{}", tc.test_case);
        // Any change to the message breaks only the last layer, but the whole
        // HSS signature with it.
        let mut bad = hx(&tc.message_hex);
        bad[0] ^= 1;
        assert!(hss_verify(&hx(&tc.hss_public_key_hex), &bad, &hx(&tc.hss_signature_hex)).is_err());
        // Swapping the two test cases' final signatures fails at the key level.
        let hss_sig = hx(&tc.hss_signature_hex);
        let mut truncated = hss_sig.clone();
        truncated.pop();
        assert!(hss_verify(&hx(&tc.hss_public_key_hex), &hx(&tc.message_hex), &truncated).is_err());
    }
}

#[test]
fn rfc_appendix_f_w8_keys_are_refused_by_the_program_parser() {
    let mut w8_seen = 0;
    let mut w4_seen = 0;
    for tc in rfc().test_cases {
        for l in &tc.lms_layers {
            let bytes = hx(&l.public_key_hex);
            match l.lmots_type {
                4 => {
                    assert_eq!(LmsPublicKey::parse(&bytes), Err(Error::UnknownLmotsType));
                    assert_eq!(LmotsType::from_typecode(4), Err(Error::UnknownLmotsType));
                    assert_eq!(LmotsType::from_typecode_in(4, LmotsType::ALL), Ok(LmotsType::Sha256N32W8));
                    assert_eq!(LmotsType::from_typecode_in(4, &[LmotsType::Sha256N32W4]), Err(Error::UnknownLmotsType));
                    w8_seen += 1;
                }
                3 => {
                    // The H10/W4 top tree of test case 2 is a key the vault
                    // would accept, so the program path verifies it too.
                    let pk = LmsPublicKey::parse(&bytes).unwrap();
                    assert_eq!(pk.lms_type, LmsType::Sha256M32H10);
                    assert_eq!(lms_verify(&pk, &hx(&l.message_hex), &hx(&l.signature_hex)), Ok(l.q));
                    w4_seen += 1;
                }
                other => panic!("unexpected lmots type {other}"),
            }
        }
    }
    assert_eq!((w8_seen, w4_seen), (3, 1));
}

#[test]
fn rfc_appendix_f_flipped_bits_fail() {
    for tc in rfc().test_cases {
        for l in &tc.lms_layers {
            let pk = LmsPublicKey::parse_any(&hx(&l.public_key_hex)).unwrap();
            let msg = hx(&l.message_hex);
            let good = hx(&l.signature_hex);
            // W8 verification is ~9k hashes; sample every third byte there and
            // every byte on the W4 layer.
            let stride = if pk.lmots_type == LmotsType::Sha256N32W8 { 3 } else { 1 };
            for byte in (0..good.len()).step_by(stride) {
                let mut bad = good.clone();
                bad[byte] ^= 1 << (byte % 8);
                assert!(
                    lms_verify(&pk, &msg, &bad).is_err(),
                    "tc{} layer {} byte {byte}: flipped bit still verified",
                    tc.test_case,
                    l.layer
                );
            }
            for byte in (0..msg.len()).step_by(stride) {
                let mut bad = msg.clone();
                bad[byte] ^= 1 << (byte % 8);
                assert_eq!(lms_verify(&pk, &bad, &good), Err(Error::InvalidSignature));
            }
            // Wrong key: the other test case's key of the same parameter set,
            // or a flipped I.
            let mut other = pk;
            other.i[15] ^= 0x80;
            assert_eq!(lms_verify(&other, &msg, &good), Err(Error::InvalidSignature));
        }
    }
}

// ----------------------------------------------------------------- hash-sigs

#[derive(Deserialize)]
struct HashSigs {
    commit: String,
    vectors: Vec<HsVector>,
}

#[derive(Deserialize)]
struct HsVector {
    name: String,
    lms_type: u32,
    lmots_type: u32,
    height: u32,
    #[serde(rename = "I_hex")]
    i_hex: String,
    public_key_hex: String,
    hss_public_key_hex: String,
    signatures: Vec<HsSig>,
}

#[derive(Deserialize)]
struct HsSig {
    q: u32,
    message_hex: String,
    signature_hex: String,
}

fn hashsigs_w4() -> HashSigs {
    serde_json::from_str(HASHSIGS_W4_JSON).expect("hashsigs w4 json")
}

fn hashsigs_other() -> HashSigs {
    serde_json::from_str(HASHSIGS_OTHER_JSON).expect("hashsigs other json")
}

#[test]
fn hashsigs_vectors_are_pinned_to_the_documented_commit() {
    assert_eq!(hashsigs_w4().commit, HASHSIGS_COMMIT);
    assert_eq!(hashsigs_other().commit, HASHSIGS_COMMIT);
    let w4 = hashsigs_w4();
    let heights: Vec<u32> = w4.vectors.iter().map(|v| v.height).collect();
    assert!(heights.contains(&5) && heights.contains(&10) && heights.contains(&15), "{heights:?}");
    assert!(w4.vectors.iter().all(|v| v.lmots_type == 3));
    let other = hashsigs_other();
    let mut ws: Vec<u32> = other.vectors.iter().map(|v| v.lmots_type).collect();
    ws.sort();
    ws.dedup();
    assert_eq!(ws, vec![1, 2, 4]);
    for v in w4.vectors.iter().chain(other.vectors.iter()) {
        assert!(!v.signatures.is_empty(), "{}", v.name);
        // One-level HSS public key: u32 levels = 1 || LMS public key.
        let hss = hx(&v.hss_public_key_hex);
        assert_eq!(&hss[..4], &1u32.to_be_bytes());
        assert_eq!(hex::encode(&hss[4..]), v.public_key_hex);
        // Every vector covers leaf 0 and the last leaf.
        let qs: Vec<u32> = v.signatures.iter().map(|s| s.q).collect();
        assert!(qs.contains(&0) && qs.contains(&((1u32 << v.height) - 1)), "{}: {qs:?}", v.name);
    }
}

#[test]
fn hashsigs_w4_verifies_under_the_program_parser() {
    for v in hashsigs_w4().vectors {
        let pk = LmsPublicKey::parse(&hx(&v.public_key_hex)).unwrap();
        assert_eq!(pk.lms_type.typecode(), v.lms_type);
        assert_eq!(pk.lmots_type, LmotsType::Sha256N32W4);
        assert_eq!(pk.lms_type.height(), v.height);
        assert_eq!(pk.i.to_vec(), hx(&v.i_hex));
        for s in &v.signatures {
            let sig = hx(&s.signature_hex);
            assert_eq!(sig.len(), pk.signature_len());
            assert_eq!(lms_verify(&pk, &hx(&s.message_hex), &sig), Ok(s.q), "{} q={}", v.name, s.q);
        }
    }
}

#[test]
fn hashsigs_w1_w2_w8_verify_under_parse_any_and_not_under_parse() {
    for v in hashsigs_other().vectors {
        let bytes = hx(&v.public_key_hex);
        assert_eq!(LmsPublicKey::parse(&bytes), Err(Error::UnknownLmotsType), "{}", v.name);
        let pk = LmsPublicKey::parse_any(&bytes).unwrap();
        assert_eq!(pk.lmots_type.typecode(), v.lmots_type);
        assert_eq!(pk.lms_type.height(), v.height);
        let p = pk.lmots_type.p();
        for s in &v.signatures {
            let sig = hx(&s.signature_hex);
            assert_eq!(sig.len(), pk.signature_len(), "{}", v.name);
            assert_eq!(sig.len(), 4 + 4 + 32 * (p + 1) + 4 + 32 * v.height as usize);
            assert_eq!(lms_verify(&pk, &hx(&s.message_hex), &sig), Ok(s.q), "{} q={}", v.name, s.q);
        }
    }
}

#[test]
fn hashsigs_flipped_bits_fail() {
    for v in hashsigs_w4().vectors.into_iter().chain(hashsigs_other().vectors) {
        let pk = LmsPublicKey::parse_any(&hx(&v.public_key_hex)).unwrap();
        // Cost per verification grows with 2^w; thin the sweep accordingly.
        let stride = match pk.lmots_type {
            LmotsType::Sha256N32W8 => 8,
            LmotsType::Sha256N32W4 => 4,
            _ => 16,
        };
        for s in &v.signatures {
            let msg = hx(&s.message_hex);
            let good = hx(&s.signature_hex);
            for byte in (0..good.len()).step_by(stride) {
                let mut bad = good.clone();
                bad[byte] ^= 1 << (byte % 8);
                assert!(lms_verify(&pk, &msg, &bad).is_err(), "{} q={} byte {byte}", v.name, s.q);
            }
            if msg.is_empty() {
                assert_eq!(lms_verify(&pk, b"\0", &good), Err(Error::InvalidSignature));
            } else {
                let mut bad = msg.clone();
                bad[msg.len() / 2] ^= 0x40;
                assert_eq!(lms_verify(&pk, &bad, &good), Err(Error::InvalidSignature));
            }
        }
    }
}

#[test]
fn w8_and_w4_signatures_do_not_cross_verify() {
    // Same height (H5), different LM-OTS: the OTS typecode in the signature
    // does not match the key.
    let w8 = hashsigs_other().vectors.into_iter().find(|v| v.lmots_type == 4 && v.height == 5).unwrap();
    let w4 = hashsigs_w4().vectors.into_iter().find(|v| v.height == 5).unwrap();
    let pk8 = LmsPublicKey::parse_any(&hx(&w8.public_key_hex)).unwrap();
    let pk4 = LmsPublicKey::parse_any(&hx(&w4.public_key_hex)).unwrap();
    let s8 = &w8.signatures[0];
    let s4 = &w4.signatures[0];
    assert_eq!(lms_verify(&pk4, &hx(&s8.message_hex), &hx(&s8.signature_hex)), Err(Error::LmotsTypeMismatch));
    assert_eq!(lms_verify(&pk8, &hx(&s4.message_hex), &hx(&s4.signature_hex)), Err(Error::LmotsTypeMismatch));
}

// --------------------------------------------------------------------- signing

#[cfg(feature = "sign")]
mod signing {
    use super::*;
    use lamport_lms::LmsPrivateKey;

    fn key(lms_type: u32, lmots_type: u32, i_hex: &str, seed_hex: &str) -> LmsPrivateKey {
        LmsPrivateKey::new(
            LmsType::from_typecode(lms_type).unwrap(),
            LmotsType::from_typecode_in(lmots_type, LmotsType::ALL).unwrap(),
            hx(i_hex).try_into().unwrap(),
            hx(seed_hex).try_into().unwrap(),
        )
    }

    /// RFC 8554 test case 2 publishes SEED and I of both trees (Appendix A
    /// derivation). Our signer must reproduce both public keys and, given
    /// the RFC's randomizer C, both LMS signatures byte for byte.
    #[test]
    fn rfc_test_case_2_keys_and_signatures_reproduce_from_seed_and_i() {
        let r = rfc();
        let tc = &r.test_cases[1];
        let keys = tc.private_keys.as_ref().unwrap();
        assert_eq!(keys.len(), tc.lms_layers.len());
        for (k, l) in keys.iter().zip(&tc.lms_layers) {
            assert_eq!(k.level, l.layer);
            let sk = key(l.lms_type, l.lmots_type, &k.i_hex, &k.seed_hex);
            let tree = sk.tree();
            let pk = sk.public_key_from_tree(&tree);
            assert_eq!(hex::encode(pk.to_bytes()), l.public_key_hex, "level {} public key", k.level);

            let theirs = hx(&l.signature_hex);
            let msg = hx(&l.message_hex);
            let c: [u8; 32] = theirs[8..40].try_into().unwrap();
            let ots = sk.ots_sign_with_randomizer(l.q, &msg, &c);
            let mut ours = l.q.to_be_bytes().to_vec();
            ours.extend_from_slice(&ots);
            ours.extend_from_slice(&sk.lms_type.typecode().to_be_bytes());
            for node in tree.path(l.q) {
                ours.extend_from_slice(&node);
            }
            assert_eq!(hex::encode(&ours), l.signature_hex, "level {} signature", k.level);
            assert_eq!(lms_verify(&pk, &msg, &ours), Ok(l.q));

            // The crate's deterministic randomizer, C = H(I || q || 0xfffd ||
            // 0xff || SEED), is the convention hash-sigs used to produce the
            // RFC's vectors, so plain `sign_with_tree` reproduces the RFC
            // signature too, with no C supplied.
            let det = sk.sign_with_tree(&tree, l.q, &msg);
            assert_eq!(hex::encode(&det), l.signature_hex, "level {} deterministic C", k.level);
            assert_eq!(sk.randomizer(l.q), c);
        }
    }

    #[test]
    fn w1_w2_w8_round_trips() {
        for (t, sig_len) in [
            (LmotsType::Sha256N32W1, 4 + 8516 + 4 + 160),
            (LmotsType::Sha256N32W2, 4 + 4292 + 4 + 160),
            (LmotsType::Sha256N32W8, 4 + 1124 + 4 + 160),
        ] {
            let sk = LmsPrivateKey::new(LmsType::Sha256M32H5, t, [t as u8; 16], [0x5a; 32]);
            let tree = sk.tree();
            let pk = sk.public_key_from_tree(&tree);
            let bytes = pk.to_bytes();
            assert_eq!(LmsPublicKey::parse(&bytes), Err(Error::UnknownLmotsType), "{t:?}");
            assert_eq!(LmsPublicKey::parse_any(&bytes).unwrap(), pk);
            for q in [0u32, 1, 17, 31] {
                let msg = [q as u8; 77];
                let sig = sk.sign_with_tree(&tree, q, &msg);
                assert_eq!(sig.len(), sig_len, "{t:?}");
                assert_eq!(lms_verify(&pk, &msg, &sig), Ok(q), "{t:?} q={q}");
                let mut bad = sig.clone();
                bad[sig_len - 1] ^= 1;
                assert_eq!(lms_verify(&pk, &msg, &bad), Err(Error::InvalidSignature));
                let mut bad = sig.clone();
                bad[4 + 4 + 32] ^= 1; // y[0]
                assert_eq!(lms_verify(&pk, &msg, &bad), Err(Error::InvalidSignature));
                assert_eq!(lms_verify(&pk, &msg[..76], &sig), Err(Error::InvalidSignature));
            }
        }
    }
}
