//! NIST ACVP LMS vectors, `kat/acvp_lms.json`.
//!
//! Every LMS test group ACVP-Server publishes is a SP 800-208 SHA-256/192
//! set (`LMS_SHA256_M24_*`, `LMOTS_SHA256_N24_*`, n = m = 24): there are no
//! RFC 8554 n = 32 cases. This crate implements n = m = 32 only, so these
//! vectors are used two ways:
//!
//! 1. The shipped parser must reject every ACVP key and signature cleanly
//!    (48-byte keys, typecodes 0x0A/0x0B and 0x05/0x06) instead of
//!    misinterpreting them.
//! 2. A small **test-only** n = 24 instantiation of Algorithms 4b and 6a,
//!    built on the crate's `coef` and `H` (`hash::h`, truncated), checks that
//!    the algorithms as understood here agree with NIST: all valid signatures
//!    verify, every deliberately invalid one fails with the documented
//!    reason, and the keyGen public keys are reproduced from (SEED, I) with
//!    the Appendix A derivation. This exercises the shared arithmetic and the
//!    reading of the specification, not the production verifier.

use lamport_lms::hash::{h, D_INTR, D_LEAF, D_MESG, D_PBLC};
use lamport_lms::lmots::coef;
use lamport_lms::{lms_verify, Error, LmsPublicKey};
use serde::Deserialize;

const ACVP_JSON: &str = include_str!("../../../kat/acvp_lms.json");

#[derive(Deserialize)]
struct Acvp {
    commit: String,
    parameter_sets: ParameterSets,
    sig_ver: Vec<SigVer>,
    sig_gen: Vec<SigGen>,
    key_gen: Vec<KeyGen>,
}

#[derive(Deserialize)]
struct ParameterSets {
    lms: std::collections::BTreeMap<String, LmsSet>,
    lmots: std::collections::BTreeMap<String, LmotsSet>,
}

#[derive(Deserialize, Clone, Copy)]
struct LmsSet {
    typecode: u32,
    h: u32,
    m: usize,
}

#[derive(Deserialize, Clone, Copy)]
struct LmotsSet {
    typecode: u32,
    w: u32,
    n: usize,
    p: usize,
    ls: u32,
}

#[derive(Deserialize)]
struct SigVer {
    id: String,
    lms_mode: String,
    lmots_mode: String,
    public_key_hex: String,
    message_hex: String,
    signature_hex: String,
    expected_valid: bool,
    reason: String,
}

#[derive(Deserialize)]
struct SigGen {
    id: String,
    lms_mode: String,
    lmots_mode: String,
    public_key_hex: String,
    message_hex: String,
    signature_hex: String,
    q: u32,
}

#[derive(Deserialize)]
struct KeyGen {
    id: String,
    lms_mode: String,
    lmots_mode: String,
    seed_hex: String,
    #[serde(rename = "I_hex")]
    i_hex: String,
    public_key_hex: String,
}

fn acvp() -> Acvp {
    serde_json::from_str(ACVP_JSON).expect("acvp json")
}

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

#[test]
fn acvp_file_is_what_vectors_md_says() {
    let a = acvp();
    assert_eq!(a.commit, "975de31eb83d87039ec88934fdc47d8c312b892d");
    assert_eq!(a.sig_ver.len(), 16);
    assert_eq!(a.sig_ver.iter().filter(|s| s.expected_valid).count(), 4);
    assert_eq!(a.sig_gen.len(), 62);
    assert_eq!(a.key_gen.len(), 9);
    // Only SHA-256/192 sets are present; that is the whole reason for this file's shape.
    assert!(a.parameter_sets.lms.values().all(|s| s.m == 24));
    assert!(a.parameter_sets.lmots.values().all(|s| s.n == 24));
    let reasons: std::collections::BTreeSet<&str> = a.sig_ver.iter().map(|s| s.reason.as_str()).collect();
    assert_eq!(
        reasons,
        ["modify message", "modify signature", "modify signature header", "no modification"].into_iter().collect()
    );
}

/// 1. The production parser refuses every ACVP key, before and after padding
///    to the 56 bytes it expects, and the verifier never panics on their
///    signatures.
#[test]
fn acvp_m24_keys_are_rejected_by_the_m32_verifier() {
    let a = acvp();
    let keys = a
        .sig_ver
        .iter()
        .map(|s| (s.public_key_hex.as_str(), s.message_hex.as_str(), s.signature_hex.as_str()))
        .chain(a.sig_gen.iter().map(|s| (s.public_key_hex.as_str(), s.message_hex.as_str(), s.signature_hex.as_str())));
    for (pk_hex, msg_hex, sig_hex) in keys {
        let pk = hx(pk_hex);
        assert_eq!(pk.len(), 48);
        assert_eq!(LmsPublicKey::parse(&pk), Err(Error::PublicKeyLength));
        assert_eq!(LmsPublicKey::parse_any(&pk), Err(Error::PublicKeyLength));
        let mut padded = pk.clone();
        padded.resize(56, 0);
        assert_eq!(LmsPublicKey::parse_any(&padded), Err(Error::UnknownLmsType));
        // Forge the LMS typecode to an M32 one: the N24 OTS typecode is still foreign.
        let mut forged = padded.clone();
        forged[3] = if padded[3] == 0x0a { 5 } else { 6 };
        assert_eq!(LmsPublicKey::parse_any(&forged), Err(Error::UnknownLmotsType));
        // And with both typecodes forged to M32/W4 the signature cannot fit.
        forged[7] = 3;
        let pk32 = LmsPublicKey::parse(&forged).unwrap();
        let r = lms_verify(&pk32, &hx(msg_hex), &hx(sig_hex));
        assert!(matches!(r, Err(Error::LmotsTypeMismatch) | Err(Error::SignatureLength)), "{r:?}");
    }
    let _ = a.key_gen.len();
}

// ----------------------------------------------------- test-only n = 24 LMS

/// `H` truncated to `n` bytes (SP 800-208 Section 4: SHA-256/192 is the
/// leftmost 24 bytes of SHA-256).
fn h24(parts: &[&[u8]]) -> [u8; 24] {
    let full = h(parts);
    let mut out = [0u8; 24];
    out.copy_from_slice(&full[..24]);
    out
}

fn checksum24(q: &[u8; 24], t: LmotsSet) -> u16 {
    let max = (1u32 << t.w) - 1;
    let digits = (8 * t.n as u32) / t.w;
    let mut sum = 0u32;
    for i in 0..digits as usize {
        sum += max - coef(q, i, t.w);
    }
    ((sum << t.ls) & 0xffff) as u16
}

fn digits24(q: &[u8; 24], t: LmotsSet) -> Vec<u8> {
    let mut buf = [0u8; 26];
    buf[..24].copy_from_slice(q);
    buf[24..].copy_from_slice(&checksum24(q, t).to_be_bytes());
    (0..t.p).map(|i| coef(&buf, i, t.w) as u8).collect()
}

fn chain24(i_id: &[u8], q: u32, i: u16, j: u8, tmp: &[u8; 24]) -> [u8; 24] {
    h24(&[i_id, &q.to_be_bytes(), &i.to_be_bytes(), &[j], tmp])
}

/// Algorithm 4b with n = 24: `Kc` from the OTS signature body `C || y`.
fn ots_candidate24(t: LmotsSet, i_id: &[u8], q: u32, c: &[u8; 24], y: &[u8], message: &[u8]) -> [u8; 24] {
    let qh = h24(&[i_id, &q.to_be_bytes(), &D_MESG, c, message]);
    let a = digits24(&qh, t);
    let max = ((1u32 << t.w) - 1) as u8;
    let mut z = Vec::with_capacity(t.p);
    for (i, &ai) in a.iter().enumerate() {
        let mut tmp: [u8; 24] = y[i * 24..(i + 1) * 24].try_into().unwrap();
        let mut j = ai;
        while j < max {
            tmp = chain24(i_id, q, i as u16, j, &tmp);
            j += 1;
        }
        z.push(tmp);
    }
    let qb = q.to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![i_id, &qb, &D_PBLC];
    parts.extend(z.iter().map(|zi| zi.as_slice()));
    h24(&parts)
}

struct Sets {
    lms: LmsSet,
    ots: LmotsSet,
}

fn sets(a: &Acvp, lms_mode: &str, lmots_mode: &str) -> Sets {
    Sets {
        lms: a.parameter_sets.lms[lms_mode],
        ots: a.parameter_sets.lmots[lmots_mode],
    }
}

/// Algorithms 6 / 6a with m = n = 24. The public key is
/// `u32 lms || u32 ots || I[16] || T1[24]` (48 bytes).
fn verify24(a: &Acvp, s: &Sets, pk: &[u8], message: &[u8], sig: &[u8]) -> Result<u32, &'static str> {
    let _ = a;
    if pk.len() != 48 {
        return Err("public key length");
    }
    let be = |b: &[u8]| u32::from_be_bytes(b.try_into().unwrap());
    if be(&pk[0..4]) != s.lms.typecode || be(&pk[4..8]) != s.ots.typecode {
        return Err("key typecodes");
    }
    let i_id = &pk[8..24];
    let t1 = &pk[24..48];
    let ots_len = 4 + 24 * (s.ots.p + 1);
    if sig.len() < 8 {
        return Err("signature length");
    }
    let q = be(&sig[0..4]);
    if be(&sig[4..8]) != s.ots.typecode {
        return Err("ots typecode mismatch");
    }
    if sig.len() < 4 + ots_len + 4 {
        return Err("signature length");
    }
    if be(&sig[4 + ots_len..8 + ots_len]) != s.lms.typecode {
        return Err("lms typecode mismatch");
    }
    if sig.len() != 4 + ots_len + 4 + 24 * s.lms.h as usize {
        return Err("signature length");
    }
    if q >= 1u32 << s.lms.h {
        return Err("leaf out of range");
    }
    let c: [u8; 24] = sig[8..32].try_into().unwrap();
    let y = &sig[32..4 + ots_len];
    let path = &sig[8 + ots_len..];
    let kc = ots_candidate24(s.ots, i_id, q, &c, y, message);
    let mut node = (1u32 << s.lms.h) + q;
    let mut tmp = h24(&[i_id, &node.to_be_bytes(), &D_LEAF, &kc]);
    for i in 0..s.lms.h as usize {
        let sib = &path[i * 24..(i + 1) * 24];
        let parent = node / 2;
        tmp = if node & 1 == 1 {
            h24(&[i_id, &parent.to_be_bytes(), &D_INTR, sib, &tmp])
        } else {
            h24(&[i_id, &parent.to_be_bytes(), &D_INTR, &tmp, sib])
        };
        node = parent;
    }
    if tmp == t1 {
        Ok(q)
    } else {
        Err("root mismatch")
    }
}

/// 2a. sigVer: valid cases verify, the deliberately broken ones fail.
#[test]
fn acvp_sig_ver_expectations_hold_under_the_n24_reference() {
    let a = acvp();
    for s in &a.sig_ver {
        let st = sets(&a, &s.lms_mode, &s.lmots_mode);
        let r = verify24(&a, &st, &hx(&s.public_key_hex), &hx(&s.message_hex), &hx(&s.signature_hex));
        assert_eq!(r.is_ok(), s.expected_valid, "{} ({}): {r:?}", s.id, s.reason);
        if !s.expected_valid {
            // The failure mode must match the modification NIST made.
            match s.reason.as_str() {
                "modify signature header" => {
                    assert!(
                        matches!(r, Err("ots typecode mismatch") | Err("lms typecode mismatch") | Err("leaf out of range") | Err("root mismatch")),
                        "{}: {r:?}",
                        s.id
                    )
                }
                "modify signature" | "modify message" => assert_eq!(r, Err("root mismatch"), "{}", s.id),
                other => panic!("unknown reason {other}"),
            }
        }
    }
}

/// 2b. sigGen: NIST's own signatures, all valid, with varied message sizes.
#[test]
fn acvp_sig_gen_signatures_verify_under_the_n24_reference() {
    let a = acvp();
    let mut lens = std::collections::BTreeSet::new();
    for s in &a.sig_gen {
        let st = sets(&a, &s.lms_mode, &s.lmots_mode);
        let msg = hx(&s.message_hex);
        lens.insert(msg.len());
        let r = verify24(&a, &st, &hx(&s.public_key_hex), &msg, &hx(&s.signature_hex));
        assert_eq!(r, Ok(s.q), "{}", s.id);
        let mut bad = msg.clone();
        bad[0] ^= 1;
        assert_eq!(verify24(&a, &st, &hx(&s.public_key_hex), &bad, &hx(&s.signature_hex)), Err("root mismatch"));
    }
    assert!(lens.len() > 10, "message sizes should vary: {lens:?}");
}

/// 2c. keyGen: SP 800-208 keys use RFC 8554 Appendix A with an n-byte SEED.
#[test]
fn acvp_key_gen_public_keys_reproduce_from_seed_and_i() {
    let a = acvp();
    for k in &a.key_gen {
        let st = sets(&a, &k.lms_mode, &k.lmots_mode);
        let seed = hx(&k.seed_hex);
        assert_eq!(seed.len(), 24);
        let i_id = hx(&k.i_hex);
        let leaves = 1u32 << st.lms.h;
        let max = ((1u32 << st.ots.w) - 1) as u8;
        let mut nodes = vec![[0u8; 24]; 2 * leaves as usize];
        for q in 0..leaves {
            let mut y = Vec::with_capacity(st.ots.p * 24);
            for i in 0..st.ots.p as u16 {
                let mut tmp = h24(&[&i_id, &q.to_be_bytes(), &i.to_be_bytes(), &[0xff], &seed]);
                for j in 0..max {
                    tmp = chain24(&i_id, q, i, j, &tmp);
                }
                y.extend_from_slice(&tmp);
            }
            let qb = q.to_be_bytes();
            let mut parts: Vec<&[u8]> = vec![&i_id, &qb, &D_PBLC];
            parts.extend(y.chunks(24));
            let kpub = h24(&parts);
            let r = leaves + q;
            nodes[r as usize] = h24(&[&i_id, &r.to_be_bytes(), &D_LEAF, &kpub]);
        }
        for r in (1..leaves as usize).rev() {
            nodes[r] = h24(&[&i_id, &(r as u32).to_be_bytes(), &D_INTR, &nodes[2 * r], &nodes[2 * r + 1]]);
        }
        let mut pk = Vec::with_capacity(48);
        pk.extend_from_slice(&st.lms.typecode.to_be_bytes());
        pk.extend_from_slice(&st.ots.typecode.to_be_bytes());
        pk.extend_from_slice(&i_id);
        pk.extend_from_slice(&nodes[1]);
        assert_eq!(hex::encode(&pk), k.public_key_hex, "{}", k.id);
    }
}
