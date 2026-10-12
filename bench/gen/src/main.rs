//! Writes `bench/lms-cu/vectors.bin`: for each benchmarked parameter set, one
//! public key and SIGS (message, signature) pairs at H10. The benchmark program
//! embeds the file and verifies one pair per transaction.
//!
//! Layout: u8 case_count, then per case: u8 lms_type, u8 lmots_type,
//! u16le pk_len, pk, u8 sig_count, then per signature u16le msg_len, msg,
//! u16le sig_len, sig.

use lamport_lms::{lms_verify, LmotsType, LmsPrivateKey, LmsType};

const SIGS: u32 = 16;

fn main() {
    let cases = [
        (LmsType::Sha256M32H10, LmotsType::Sha256N32W4),
        (LmsType::Sha256M24H10, LmotsType::Sha256N24W4),
        (LmsType::Sha256M24H10, LmotsType::Sha256N24W8),
        (LmsType::Sha256M24H5, LmotsType::Sha256N24W8),
    ];
    let mut out = vec![cases.len() as u8];
    for (lms, ots) in cases {
        let key = LmsPrivateKey::new(lms, ots, [0x42; 16], [0x17; 32]);
        let tree = key.tree();
        let pk = key.public_key_from_tree(&tree).encode();
        let pkp = lamport_lms::LmsPublicKey::parse(&pk).unwrap();
        out.extend_from_slice(&[lms.typecode() as u8, ots.typecode() as u8]);
        out.extend_from_slice(&(pk.len() as u16).to_le_bytes());
        out.extend_from_slice(&pk);
        out.push(SIGS as u8);
        let mut sizes = 0;
        for k in 0..SIGS {
            // 32-byte messages, like the vault's sha256 action digest
            let msg = [k as u8 ^ 0x5a; 32];
            let q = (k * 37) % lms.leaf_count();
            let sig = key.sign_with_tree(&tree, q, &msg);
            assert_eq!(lms_verify(&pkp, &msg, &sig), Ok(q));
            sizes = sig.len();
            out.extend_from_slice(&(msg.len() as u16).to_le_bytes());
            out.extend_from_slice(&msg);
            out.extend_from_slice(&(sig.len() as u16).to_le_bytes());
            out.extend_from_slice(&sig);
        }
        eprintln!("{lms:?} {ots:?}: pk {} bytes, signature {sizes} bytes", pk.len());
    }
    std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/../lms-cu/vectors.bin"), out).unwrap();
}
