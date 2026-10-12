//! `lms-tool`: command-line key generation, signing and verification with the
//! `lamport-lms` crate. Used by the Anchor tests and handy for manual checks.
//!
//! ```text
//! lms-tool keygen --seed <hex32> --i <hex16> --lms-type <5..8> [--lmots-type 3]
//!     prints the 56-byte public key as hex
//! lms-tool sign   --seed <hex32> --i <hex16> --lms-type <5..8> [--lmots-type 3] --q <n> --msg <hex>
//!     prints the LMS signature as hex
//! lms-tool verify --pubkey <hex56> --msg <hex> --sig <hex>
//!     prints "ok q=<n>" and exits 0, or the error name and exits 1
//! lms-tool tree   --seed <hex32> --i <hex16> --lms-type <5..8> [--lmots-type 3]
//!     prints every node T[1..2^(h+1)) as hex, one per line (debugging aid)
//! ```
//!
//! The tool rebuilds the Merkle tree on every `sign`; for H10 that is about a
//! quarter of a second in a release build.

use std::collections::HashMap;
use std::process::ExitCode;

use lamport_lms::{lms_verify, LmotsType, LmsPrivateKey, LmsPublicKey, LmsType};

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  lms-tool keygen --seed HEX --i HEX --lms-type N [--lmots-type 3]\n  \
         lms-tool sign --seed HEX --i HEX --lms-type N [--lmots-type 3] --q N --msg HEX\n  \
         lms-tool verify --pubkey HEX --msg HEX --sig HEX\n  \
         lms-tool tree --seed HEX --i HEX --lms-type N [--lmots-type 3]"
    );
    ExitCode::from(2)
}

fn parse_args(args: &[String]) -> Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let key = k
            .strip_prefix("--")
            .ok_or_else(|| format!("unexpected argument {k}"))?;
        let v = it.next().ok_or_else(|| format!("missing value for --{key}"))?;
        map.insert(key.to_string(), v.clone());
    }
    Ok(map)
}

fn hex_arg<const L: usize>(m: &HashMap<String, String>, k: &str) -> Result<[u8; L], String> {
    let v = m.get(k).ok_or_else(|| format!("missing --{k}"))?;
    let bytes = hex::decode(v).map_err(|e| format!("--{k}: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("--{k}: expected {L} bytes"))
}

fn hex_vec(m: &HashMap<String, String>, k: &str) -> Result<Vec<u8>, String> {
    let v = m.get(k).ok_or_else(|| format!("missing --{k}"))?;
    hex::decode(v).map_err(|e| format!("--{k}: {e}"))
}

fn u32_arg(m: &HashMap<String, String>, k: &str, default: Option<u32>) -> Result<u32, String> {
    match (m.get(k), default) {
        (Some(v), _) => v.parse::<u32>().map_err(|e| format!("--{k}: {e}")),
        (None, Some(d)) => Ok(d),
        (None, None) => Err(format!("missing --{k}")),
    }
}

fn private_key(m: &HashMap<String, String>) -> Result<LmsPrivateKey, String> {
    let seed = hex_arg::<32>(m, "seed")?;
    let i = hex_arg::<16>(m, "i")?;
    let lms_type = LmsType::from_typecode(u32_arg(m, "lms-type", None)?)
        .map_err(|e| format!("--lms-type: {e}"))?;
    let lmots_type = LmotsType::from_typecode(u32_arg(m, "lmots-type", Some(3))?)
        .map_err(|e| format!("--lmots-type: {e}"))?;
    Ok(LmsPrivateKey::new(lms_type, lmots_type, i, seed))
}

fn run(cmd: &str, m: &HashMap<String, String>) -> Result<ExitCode, String> {
    match cmd {
        "keygen" => {
            let sk = private_key(m)?;
            println!("{}", hex::encode(sk.public_key().to_bytes()));
            Ok(ExitCode::SUCCESS)
        }
        "sign" => {
            let sk = private_key(m)?;
            let q = u32_arg(m, "q", None)?;
            if q >= sk.lms_type.leaf_count() {
                return Err(format!("--q: {q} is outside a tree of height {}", sk.lms_type.height()));
            }
            let msg = hex_vec(m, "msg")?;
            println!("{}", hex::encode(sk.sign(q, &msg)));
            Ok(ExitCode::SUCCESS)
        }
        "verify" => {
            let pk_bytes = hex_vec(m, "pubkey")?;
            let pk = LmsPublicKey::parse(&pk_bytes).map_err(|e| format!("--pubkey: {e}"))?;
            let msg = hex_vec(m, "msg")?;
            let sig = hex_vec(m, "sig")?;
            match lms_verify(&pk, &msg, &sig) {
                Ok(q) => {
                    println!("ok q={q}");
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    println!("{e}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        "tree" => {
            let sk = private_key(m)?;
            let tree = sk.tree();
            for r in 1..(2u32 << tree.height()) {
                println!("{}", hex::encode(tree.node(r)));
            }
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(format!("unknown command {cmd}")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        return usage();
    };
    let m = match parse_args(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}");
            return usage();
        }
    };
    match run(cmd, &m) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
