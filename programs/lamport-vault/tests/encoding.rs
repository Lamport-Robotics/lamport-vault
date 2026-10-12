//! Cross-checks the program's wire formats against `kat/vault_encoding.json`,
//! the vectors the TypeScript SDK produces: Borsh `Action` encodings, signed
//! messages, PDA derivation under this program's id, Anchor discriminators,
//! instruction data and account layouts. A mismatch here means the SDK and the
//! program would disagree on the wire.

use anchor_lang::prelude::*;
use anchor_lang::{AccountSerialize, Discriminator, InstructionData};
use lamport_vault::{signed_message, vault_id_for, Action, SigBuffer, Vault, SIG_SEED, VAULT_SEED};
use serde_json::Value;
use std::str::FromStr;

const JSON: &str = include_str!("../../../kat/vault_encoding.json");

fn v() -> Value {
    serde_json::from_str(JSON).unwrap()
}
fn hx(s: &Value) -> Vec<u8> {
    hex::decode(s.as_str().unwrap_or_else(|| panic!("missing hex field"))).unwrap()
}
fn pk(s: &Value) -> Pubkey {
    Pubkey::from_str(s.as_str().unwrap_or_else(|| panic!("missing pubkey field"))).unwrap()
}
fn u64s(s: &Value) -> u64 {
    s.as_str().unwrap().parse().unwrap()
}
/// True if `bytes` is one of the four action vectors in the file.
fn known_action(d: &Value, bytes: &[u8]) -> bool {
    ["transfer_sol", "transfer_token", "rotate", "close"]
        .iter()
        .any(|k| hx(&d["actions"][k]["action_hex"]) == bytes)
}
fn h5(d: &Value) -> [u8; 56] {
    hx(&d["inputs"]["h5_pubkey_hex"]).try_into().unwrap()
}

#[test]
fn vectors_target_this_program_id() {
    let d = v();
    assert_eq!(pk(&d["program_ids"]["lamport_vault"]), lamport_vault::ID);
}

#[test]
fn action_encodings_and_messages() {
    let d = v();
    let expiry = u64s(&d["inputs"]["expiry_slot"]);
    let h10: [u8; 56] = hx(&d["inputs"]["h10_pubkey_hex"]).try_into().unwrap();
    let (vault, _) = Pubkey::find_program_address(&[VAULT_SEED, &vault_id_for(&h5(&d))], &lamport_vault::ID);

    let a = &d["actions"];
    let cases: Vec<(&str, Action)> = vec![
        (
            "transfer_sol",
            Action::TransferSol {
                to: pk(&a["transfer_sol"]["action"]["to"]),
                lamports: u64s(&a["transfer_sol"]["action"]["lamports"]),
                expiry_slot: expiry,
            },
        ),
        (
            "transfer_token",
            Action::TransferToken {
                mint: pk(&a["transfer_token"]["action"]["mint"]),
                to: pk(&a["transfer_token"]["action"]["to"]),
                amount: u64s(&a["transfer_token"]["action"]["amount"]),
                expiry_slot: expiry,
            },
        ),
        (
            "rotate",
            Action::Rotate {
                new_lms_pubkey: h10,
                expiry_slot: expiry,
            },
        ),
        (
            "close",
            Action::Close {
                to: pk(&a["close"]["action"]["to"]),
                expiry_slot: expiry,
            },
        ),
    ];
    for (name, action) in cases {
        let bytes = action.encode();
        assert_eq!(bytes, hx(&a[name]["action_hex"]), "{name} encoding");
        assert_eq!(Action::decode(&bytes).unwrap(), action, "{name} decode");
        assert_eq!(
            signed_message(&vault, &bytes).to_vec(),
            hx(&a[name]["message_hex"]),
            "{name} message"
        );
    }
    assert_eq!(lamport_vault::MESSAGE_DOMAIN.to_vec(), hx(&d["messages"]["vault_prefix_hex"]));
}

#[test]
fn pdas_match() {
    let d = v();
    let vault_id = vault_id_for(&h5(&d));
    assert_eq!(vault_id.to_vec(), hx(&d["pdas"]["vault_id_hex"]));
    let (vault, bump) = Pubkey::find_program_address(&[VAULT_SEED, &vault_id], &lamport_vault::ID);
    assert_eq!(vault, pk(&d["pdas"]["vault"]["address"]));
    assert_eq!(bump as u64, d["pdas"]["vault"]["bump"].as_u64().unwrap());

    let payer = pk(&d["inputs"]["pk_11"]);
    let nonce = u64s(&d["inputs"]["nonce"]);
    assert_eq!(nonce.to_le_bytes().to_vec(), hx(&d["inputs"]["nonce_le_hex"]));
    let (buf, bump) = Pubkey::find_program_address(
        &[SIG_SEED, vault.as_ref(), payer.as_ref(), &nonce.to_le_bytes()],
        &lamport_vault::ID,
    );
    assert_eq!(buf, pk(&d["pdas"]["sig_buffer"]["address"]));
    assert_eq!(bump as u64, d["pdas"]["sig_buffer"]["bump"].as_u64().unwrap());
}

#[test]
fn discriminators_and_instruction_data() {
    let d = v();
    let ix = &d["discriminators"]["instructions"];
    use lamport_vault::instruction as I;
    assert_eq!(I::CreateVault::DISCRIMINATOR.to_vec(), hx(&ix["create_vault"]));
    assert_eq!(I::OpenSigBuffer::DISCRIMINATOR.to_vec(), hx(&ix["open_sig_buffer"]));
    assert_eq!(I::WriteSig::DISCRIMINATOR.to_vec(), hx(&ix["write_sig"]));
    assert_eq!(I::CloseSigBuffer::DISCRIMINATOR.to_vec(), hx(&ix["close_sig_buffer"]));
    assert_eq!(I::Execute::DISCRIMINATOR.to_vec(), hx(&ix["execute"]));
    let acc = &d["discriminators"]["accounts"];
    assert_eq!(Vault::DISCRIMINATOR.to_vec(), hx(&acc["Vault"]));
    assert_eq!(SigBuffer::DISCRIMINATOR.to_vec(), hx(&acc["SigBuffer"]));

    let key = h5(&d);
    assert_eq!(
        I::CreateVault { vault_id: vault_id_for(&key), lms_pubkey: key }.data(),
        hx(&d["instruction_data"]["create_vault_hex"])
    );

    // open_sig_buffer: disc || u64 nonce || vec action || u16 sig_len || vec first_chunk
    let open = hx(&d["instruction_data"]["open_sig_buffer_hex"]);
    let action_len = u32::from_le_bytes(open[16..20].try_into().unwrap()) as usize;
    let action = open[20..20 + action_len].to_vec();
    assert!(known_action(&d, &action), "open_sig_buffer carries an unknown action");
    let tail = 8 + 8 + 4 + action.len();
    let sig_len = u16::from_le_bytes(open[tail..tail + 2].try_into().unwrap());
    let fc_len = u32::from_le_bytes(open[tail + 2..tail + 6].try_into().unwrap()) as usize;
    let first_chunk = open[tail + 6..tail + 6 + fc_len].to_vec();
    assert_eq!(open.len(), tail + 6 + fc_len, "trailing bytes in open_sig_buffer vector");
    let expected = I::OpenSigBuffer {
        nonce: u64s(&d["inputs"]["nonce"]),
        action,
        sig_len,
        first_chunk,
    }
    .data();
    assert_eq!(expected, open);

    // write_sig: disc || u16 offset || vec chunk
    let write = hx(&d["instruction_data"]["write_sig_hex"]);
    let offset = u16::from_le_bytes(write[8..10].try_into().unwrap());
    let len = u32::from_le_bytes(write[10..14].try_into().unwrap()) as usize;
    let chunk = write[14..14 + len].to_vec();
    assert_eq!(I::WriteSig { offset, chunk }.data(), write);
}

#[test]
fn account_layouts() {
    let d = v();
    let key = h5(&d);
    let vault_hex = hx(&d["accounts"]["vault_hex"]);
    let vault = Vault {
        version: vault_hex[8],
        bump: vault_hex[9],
        vault_id: vault_id_for(&key),
        lms_pubkey: key,
        next_q: u32::from_le_bytes(vault_hex[98..102].try_into().unwrap()),
        rotations: u32::from_le_bytes(vault_hex[102..106].try_into().unwrap()),
        created_slot: u64::from_le_bytes(vault_hex[106..114].try_into().unwrap()),
    };
    let mut out = Vec::new();
    vault.try_serialize(&mut out).unwrap();
    assert_eq!(out, vault_hex);
    assert_eq!(out.len(), Vault::SPACE);

    let sb_hex = hx(&d["accounts"]["sig_buffer_hex"]);
    let fixed = 8 + 1 + 1 + 32 + 32 + 8;
    let action_len = u32::from_le_bytes(sb_hex[fixed..fixed + 4].try_into().unwrap()) as usize;
    let action = sb_hex[fixed + 4..fixed + 4 + action_len].to_vec();
    assert!(known_action(&d, &action), "sig_buffer carries an unknown action");
    let after_action = fixed + 4 + action.len();
    let sig_len = u16::from_le_bytes(sb_hex[after_action..after_action + 2].try_into().unwrap());
    let filled = u16::from_le_bytes(sb_hex[after_action + 2..after_action + 4].try_into().unwrap());
    let sig_start = after_action + 4 + 4;
    let sb = SigBuffer {
        version: sb_hex[8],
        bump: sb_hex[9],
        vault: Pubkey::new_from_array(sb_hex[10..42].try_into().unwrap()),
        payer: pk(&d["inputs"]["pk_11"]),
        nonce: u64s(&d["inputs"]["nonce"]),
        action: action.clone(),
        sig_len,
        filled,
        sig: sb_hex[sig_start..sig_start + sig_len as usize].to_vec(),
    };
    let mut out = Vec::new();
    sb.try_serialize(&mut out).unwrap();
    assert_eq!(out, sb_hex);
    assert_eq!(out.len(), SigBuffer::space(action.len(), sig_len as usize));
}

#[test]
fn chunking_table_matches_signature_lengths() {
    let d = v();
    let max = d["chunking"]["max_chunk_bytes"].as_u64().unwrap() as usize;
    assert_eq!(max, 900);
    for (name, len) in [
        ("plain_h5_chunks", 2348usize),
        ("plain_h10_chunks", 2508),
        ("plain_h15_chunks", 2668),
        ("plain_h20_chunks", 2828),
    ] {
        let chunks: Vec<usize> = d["chunking"][name]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_u64().unwrap() as usize)
            .collect();
        assert!(chunks.iter().all(|&c| c <= max));
        assert_eq!(chunks.iter().sum::<usize>(), len, "{name}");
    }
}
