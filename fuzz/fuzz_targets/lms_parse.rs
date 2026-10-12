#![no_main]
//! Public key and signature parsers on arbitrary bytes of every length: must
//! never panic, and whatever parses must be self-consistent.

use lamport_vault_fuzz::fixtures;
use libfuzzer_sys::fuzz_target;
use lamport_lms::{
    lms_signature_len, parse_lmots_signature, parse_lms_signature, peek_q, LmotsType, LmsPublicKey,
    N,
};

fuzz_target!(|data: &[u8]| {
    // Unstructured: the raw input through every parser.
    let _ = peek_q(data);
    let strict = LmsPublicKey::parse(data);
    let any = LmsPublicKey::parse_any(data);
    if let Ok(pk) = strict {
        assert_eq!(pk.lmots_type, LmotsType::Sha256N32W4, "program policy admits only W4");
        assert_eq!(any, Ok(pk));
    }
    if let Ok(pk) = any {
        assert_eq!(data.len(), 56);
        assert_eq!(pk.to_bytes(), data);
        assert_eq!(pk.signature_len(), lms_signature_len(pk.lms_type, pk.lmots_type));
        assert!(LmotsType::ALL.contains(&pk.lmots_type));
        // A signature of exactly the right length made of these same bytes
        // (repeated) parses or fails cleanly; the typecodes decide.
        let mut sig = Vec::with_capacity(pk.signature_len());
        while sig.len() < pk.signature_len() {
            sig.extend_from_slice(data);
        }
        sig.truncate(pk.signature_len());
        let _ = parse_lms_signature(&sig, &pk);
    }
    for t in LmotsType::ALL {
        if let Ok(s) = parse_lmots_signature(data, *t) {
            assert_eq!(s.lmots_type, *t);
            assert_eq!(data.len(), t.signature_len());
            assert_eq!(s.y.len(), N * t.p());
            let _ = s.y(t.p() - 1);
        }
    }

    // Structured: byte 0 picks a fixture key, the rest is a candidate signature.
    if let Some((&sel, rest)) = data.split_first() {
        let fx = fixtures();
        let f = &fx[sel as usize % fx.len()];
        match parse_lms_signature(rest, &f.pk) {
            Ok(sig) => {
                assert_eq!(rest.len(), f.pk.signature_len());
                assert_eq!(sig.lms_type, f.pk.lms_type);
                assert_eq!(sig.lmots.lmots_type, f.pk.lmots_type);
                assert!(sig.q < f.pk.lms_type.leaf_count());
                assert_eq!(Some(sig.q), peek_q(rest));
                assert_eq!(sig.lmots.y.len(), N * f.pk.lmots_type.p());
                assert_eq!(sig.path.len(), N * f.pk.lms_type.height() as usize);
                let _ = sig.path(f.pk.lms_type.height() as usize - 1);
                let _ = sig.lmots.y(f.pk.lmots_type.p() - 1);
            }
            Err(e) => {
                // Length errors must be exactly that.
                if rest.len() != f.pk.signature_len() {
                    assert!(
                        matches!(
                            e,
                            lamport_lms::Error::SignatureLength
                                | lamport_lms::Error::LmotsTypeMismatch
                                | lamport_lms::Error::LmsTypeMismatch
                        ),
                        "{e:?} for a wrong-length signature"
                    );
                }
            }
        }
    }
});
