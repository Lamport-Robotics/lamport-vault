#![no_main]
//! The verifier against fixed keys: random signatures must be rejected
//! without panicking, and any byte-level change to a valid signature or its
//! message must make verification fail.
//!
//! Input layout: `key_sel || sig_sel || mode || payload`.

use lamport_vault_fuzz::{fixtures, pick};
use libfuzzer_sys::fuzz_target;
use lamport_lms::{lms_verify, Error};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let (f, msg, good) = pick(data[0], data[1]);
    let mode = data[2];
    let payload = &data[3..];
    match mode % 5 {
        // Arbitrary bytes as the signature: only the fixture's own signature
        // may verify (the seed corpus contains it).
        0 => {
            let r = lms_verify(&f.pk, msg, payload);
            if payload == good {
                assert!(r.is_ok(), "{}: the valid signature failed: {r:?}", f.name);
            } else {
                assert!(r.is_err(), "{}: a signature other than the valid one verified", f.name);
            }
            if payload.len() != f.pk.signature_len() {
                assert_ne!(r, Err(Error::InvalidSignature), "wrong length must not reach the hash walk");
            }
        }
        // XOR mutations of the valid signature: payload is (u16 offset, u8 mask) triples.
        1 => {
            let mut sig = good.to_vec();
            for c in payload.chunks_exact(3) {
                let off = u16::from_be_bytes([c[0], c[1]]) as usize % sig.len();
                sig[off] ^= c[2];
            }
            let r = lms_verify(&f.pk, msg, &sig);
            if sig == good {
                assert!(r.is_ok(), "{}: unchanged signature failed: {r:?}", f.name);
            } else {
                assert!(r.is_err(), "{}: mutated signature verified", f.name);
            }
        }
        // Truncation / extension of the valid signature.
        2 => {
            let mut sig = good.to_vec();
            let n = if payload.is_empty() { 0 } else { u16::from_be_bytes([payload[0], *payload.get(1).unwrap_or(&0)]) as usize };
            if n % 2 == 0 {
                sig.truncate(sig.len().saturating_sub(n / 2 + 1));
            } else {
                sig.extend(std::iter::repeat(payload.get(2).copied().unwrap_or(0)).take(n / 2 + 1));
            }
            assert_eq!(lms_verify(&f.pk, msg, &sig), Err(Error::SignatureLength), "{}", f.name);
        }
        // Mutations of the message (same triple format); an unchanged message must still verify.
        3 => {
            let mut m = msg.to_vec();
            if m.is_empty() {
                m.extend_from_slice(payload);
                let r = lms_verify(&f.pk, &m, good);
                if payload.is_empty() {
                    assert!(r.is_ok());
                } else {
                    assert_eq!(r, Err(Error::InvalidSignature));
                }
            } else {
                for c in payload.chunks_exact(3) {
                    let off = u16::from_be_bytes([c[0], c[1]]) as usize % m.len();
                    m[off] ^= c[2];
                }
                let r = lms_verify(&f.pk, &m, good);
                if m == msg {
                    assert!(r.is_ok());
                } else {
                    assert_eq!(r, Err(Error::InvalidSignature), "{}", f.name);
                }
            }
        }
        // Another fixture's key and a mutated public key.
        _ => {
            let fx = fixtures();
            let other = &fx[payload.first().copied().unwrap_or(0) as usize % fx.len()];
            if other.pk_bytes != f.pk_bytes {
                assert!(lms_verify(&other.pk, msg, good).is_err(), "{} signature verified under {}", f.name, other.name);
            }
            let mut pk = f.pk;
            let which = payload.get(1).copied().unwrap_or(0);
            let mask = payload.get(2).copied().unwrap_or(1);
            if mask != 0 {
                if which % 2 == 0 {
                    pk.i[which as usize % 16] ^= mask;
                } else {
                    pk.t1[which as usize % 32] ^= mask;
                }
                assert_eq!(lms_verify(&pk, msg, good), Err(Error::InvalidSignature));
            }
        }
    }
});
