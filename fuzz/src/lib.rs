//! Shared fixtures for the fuzz targets: every public key and valid signature
//! from `kat/`, in a fixed order that `gen_seeds.py` mirrors.

use std::sync::OnceLock;

use lamport_lms::{lms_verify, LmsPublicKey};
use serde::Deserialize;

/// A key with at least one valid signature.
pub struct Fixture {
    pub name: String,
    pub pk_bytes: [u8; 56],
    pub pk: LmsPublicKey,
    /// `(message, signature)` pairs that verify under `pk`.
    pub sigs: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Deserialize)]
struct KatFile {
    vectors: Vec<KatVector>,
}

#[derive(Deserialize)]
struct KatVector {
    name: String,
    public_key_hex: String,
    signatures: Vec<KatSig>,
}

#[derive(Deserialize)]
struct KatSig {
    message_hex: String,
    signature_hex: String,
}

#[derive(Deserialize)]
struct RfcFile {
    test_cases: Vec<RfcCase>,
}

#[derive(Deserialize)]
struct RfcCase {
    test_case: u32,
    lms_layers: Vec<RfcLayer>,
}

#[derive(Deserialize)]
struct RfcLayer {
    layer: u32,
    public_key_hex: String,
    message_hex: String,
    signature_hex: String,
}

const KAT_FILES: &[&str] = &[
    include_str!("../../kat/lms_sha256_w4.json"),
    include_str!("../../kat/hashsigs_w4.json"),
    include_str!("../../kat/hashsigs_w1w2w8.json"),
];
const RFC_FILE: &str = include_str!("../../kat/rfc8554_appendix_f.json");

fn load() -> Vec<Fixture> {
    let mut out = Vec::new();
    let mut push = |name: String, pk_hex: &str, sigs: Vec<(Vec<u8>, Vec<u8>)>| {
        let pk_bytes: [u8; 56] = hex::decode(pk_hex).unwrap().try_into().unwrap();
        let pk = LmsPublicKey::parse_any(&pk_bytes).expect("fixture key");
        for (m, s) in &sigs {
            assert!(lms_verify(&pk, m, s).is_ok(), "fixture {name} does not verify");
        }
        out.push(Fixture {
            name,
            pk_bytes,
            pk,
            sigs,
        });
    };
    for f in KAT_FILES {
        let k: KatFile = serde_json::from_str(f).unwrap();
        for v in k.vectors {
            let sigs = v
                .signatures
                .iter()
                .map(|s| (hex::decode(&s.message_hex).unwrap(), hex::decode(&s.signature_hex).unwrap()))
                .collect();
            push(v.name, &v.public_key_hex, sigs);
        }
    }
    let r: RfcFile = serde_json::from_str(RFC_FILE).unwrap();
    for tc in r.test_cases {
        for l in tc.lms_layers {
            push(
                format!("rfc8554 tc{} layer {}", tc.test_case, l.layer),
                &l.public_key_hex,
                vec![(hex::decode(&l.message_hex).unwrap(), hex::decode(&l.signature_hex).unwrap())],
            );
        }
    }
    out
}

/// All fixtures, loaded once per process.
pub fn fixtures() -> &'static [Fixture] {
    static F: OnceLock<Vec<Fixture>> = OnceLock::new();
    F.get_or_init(load)
}

/// Picks a fixture and one of its signatures from two selector bytes.
pub fn pick(key_sel: u8, sig_sel: u8) -> (&'static Fixture, &'static [u8], &'static [u8]) {
    let fx = fixtures();
    let f = &fx[key_sel as usize % fx.len()];
    let (m, s) = &f.sigs[sig_sel as usize % f.sigs.len()];
    (f, m, s)
}
