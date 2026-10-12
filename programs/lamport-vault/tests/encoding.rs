//! Cross-checks the program's wire formats against `kat/vault_encoding.json`,
//! the vectors the TypeScript SDK produces: Borsh `Action` encodings, signed
//! messages, PDA derivation under this program's id, Anchor discriminators,
//! instruction data and account layouts. A mismatch here means the SDK and the
//! program would disagree on the wire.

use anchor_lang::prelude::*;
use anchor_lang::{AccountDeserialize, AccountSerialize, Discriminator, InstructionData};
use lamport_lms::LmsType;
use lamport_vault::{
    signed_message, vault_id_for, Action, SigBuffer, Tombstone, Vault, KEY_HASH_LEN, MAX_VALIDITY_SLOTS, MESSAGE_VERSION, SIG_SEED, VAULT_SEED,
};
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
fn u32s(s: &Value) -> u32 {
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
    let issued = u64s(&d["inputs"]["issued_slot"]);
    let expiry = u64s(&d["inputs"]["expiry_slot"]);
    assert_eq!(issued.to_le_bytes().to_vec(), hx(&d["inputs"]["issued_slot_le_hex"]));
    assert_eq!(expiry.to_le_bytes().to_vec(), hx(&d["inputs"]["expiry_slot_le_hex"]));
    assert_eq!(d["validity"]["max_validity_slots"].as_u64().unwrap(), MAX_VALIDITY_SLOTS);
    let sizes = &d["validity"]["action_sizes"];
    let generation = u32s(&d["inputs"]["generation"]);
    let h10: [u8; 56] = hx(&d["inputs"]["h10_pubkey_hex"]).try_into().unwrap();
    let (vault, _) = Pubkey::find_program_address(&[VAULT_SEED, &vault_id_for(&h5(&d))], &lamport_vault::ID);
    let m = &d["messages"];
    assert_eq!(m["message_version"].as_u64().unwrap(), MESSAGE_VERSION as u64);
    assert_eq!(pk(&m["vault_message_inputs"]["program_id"]), lamport_vault::ID);
    assert_eq!(pk(&m["vault_message_inputs"]["vault"]), vault);
    assert_eq!(u32s(&m["vault_message_inputs"]["generation"]), generation);

    let a = &d["actions"];
    let cases: Vec<(&str, Action)> = vec![
        (
            "transfer_sol",
            Action::TransferSol {
                to: pk(&a["transfer_sol"]["action"]["to"]),
                lamports: u64s(&a["transfer_sol"]["action"]["lamports"]),
                issued_slot: issued,
                expiry_slot: expiry,
            },
        ),
        (
            "transfer_token",
            Action::TransferToken {
                mint: pk(&a["transfer_token"]["action"]["mint"]),
                to: pk(&a["transfer_token"]["action"]["to"]),
                amount: u64s(&a["transfer_token"]["action"]["amount"]),
                issued_slot: issued,
                expiry_slot: expiry,
            },
        ),
        (
            "rotate",
            Action::Rotate {
                new_lms_pubkey: h10,
                issued_slot: issued,
                expiry_slot: expiry,
            },
        ),
        (
            "close",
            Action::Close {
                to: pk(&a["close"]["action"]["to"]),
                issued_slot: issued,
                expiry_slot: expiry,
            },
        ),
    ];
    for (name, action) in cases {
        let bytes = action.encode();
        assert_eq!(bytes, hx(&a[name]["action_hex"]), "{name} encoding");
        assert_eq!(Action::decode(&bytes).unwrap(), action, "{name} decode");
        assert_eq!(action.window(), (issued, expiry), "{name} window");
        let size_key = match name {
            "transfer_sol" => "TransferSol",
            "transfer_token" => "TransferToken",
            "rotate" => "Rotate",
            _ => "Close",
        };
        assert_eq!(bytes.len() as u64, sizes[size_key].as_u64().unwrap(), "{name} size");
        // The window is the last 16 bytes of every variant: issued_slot then expiry_slot.
        let n = bytes.len();
        assert_eq!(&bytes[n - 16..n - 8], &issued.to_le_bytes());
        assert_eq!(&bytes[n - 8..], &expiry.to_le_bytes());
        assert_eq!(
            signed_message(&vault, generation, &bytes).to_vec(),
            hx(&a[name]["message_hex"]),
            "{name} message"
        );
        assert_ne!(signed_message(&vault, generation + 1, &bytes).to_vec(), hx(&a[name]["message_hex"]));
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
    assert_eq!(I::ExecuteDirect::DISCRIMINATOR.to_vec(), hx(&ix["execute_direct"]));
    let acc = &d["discriminators"]["accounts"];
    assert_eq!(Vault::DISCRIMINATOR.to_vec(), hx(&acc["Vault"]));
    assert_eq!(Tombstone::DISCRIMINATOR.to_vec(), hx(&acc["Tombstone"]));
    assert_eq!(SigBuffer::DISCRIMINATOR.to_vec(), hx(&acc["SigBuffer"]));
    assert_ne!(Vault::DISCRIMINATOR, Tombstone::DISCRIMINATOR);

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
    // disc(8) version bump vault_id(32) lms_pubkey(56) spent(4) generation(4) created(8)
    // || vec<u8> used (u32 len, 2^h/8 bytes) || vec<[u8;16]> used_keys (u32 len, 16 each)
    assert_eq!(vault_hex[8], Vault::VERSION);
    let used_len = u32::from_le_bytes(vault_hex[114..118].try_into().unwrap()) as usize;
    assert_eq!(used_len, Vault::bitmap_len(LmsType::Sha256M32H5), "H5 bitmap is 4 bytes");
    let used = vault_hex[118..118 + used_len].to_vec();
    let p = 118 + used_len;
    let hist_len = u32::from_le_bytes(vault_hex[p..p + 4].try_into().unwrap()) as usize;
    let used_keys: Vec<[u8; KEY_HASH_LEN]> = (0..hist_len)
        .map(|i| vault_hex[p + 4 + 16 * i..p + 4 + 16 * (i + 1)].try_into().unwrap())
        .collect();
    assert_eq!(vault_hex.len(), p + 4 + 16 * hist_len, "trailing bytes in vault vector");
    let vault = Vault {
        version: vault_hex[8],
        bump: vault_hex[9],
        vault_id: vault_id_for(&key),
        lms_pubkey: key,
        spent: u32::from_le_bytes(vault_hex[98..102].try_into().unwrap()),
        generation: u32::from_le_bytes(vault_hex[102..106].try_into().unwrap()),
        created_slot: u64::from_le_bytes(vault_hex[106..114].try_into().unwrap()),
        used,
        used_keys,
    };
    assert_eq!(vault.generation as usize, hist_len, "one past key per rotation");
    assert_eq!(vault.spent, vault.used.iter().map(|b| b.count_ones()).sum::<u32>());
    let h10: [u8; 56] = hx(&d["inputs"]["h10_pubkey_hex"]).try_into().unwrap();
    assert!(vault.has_used_key(&h10), "the H10 key is in the vector's history");
    let mut out = Vec::new();
    vault.try_serialize(&mut out).unwrap();
    assert_eq!(out, vault_hex);
    assert_eq!(out.len(), Vault::space(LmsType::Sha256M32H5, hist_len));

    // Tombstone: disc(8) version(0xfe) vault_id(32) closed_slot(8), 49 bytes; reading it as a Vault
    // says VaultClosed, and a Vault serialised after `Close` marked it writes nothing.
    let tomb_hex = hx(&d["accounts"]["tombstone_hex"]);
    assert_eq!(tomb_hex.len(), Tombstone::SPACE);
    assert_eq!(tomb_hex[8], Tombstone::VERSION);
    let tomb = Tombstone::try_deserialize(&mut &tomb_hex[..]).unwrap();
    assert_eq!(tomb.vault_id, vault_id_for(&key));
    assert_eq!(tomb.closed_slot, 0x1122334466);
    let mut out = Vec::new();
    tomb.try_serialize(&mut out).unwrap();
    assert_eq!(out, tomb_hex);
    let closed = Vault::try_deserialize(&mut &tomb_hex[..]).expect_err("a tombstone is not a vault");
    assert_eq!(closed, anchor_lang::error::Error::from(lamport_vault::VaultError::VaultClosed));
    let mut retired = vault.clone();
    retired.version = Tombstone::VERSION;
    let mut none = Vec::new();
    retired.try_serialize(&mut none).unwrap();
    assert!(none.is_empty(), "a vault marked closed is never written back");
    assert!(Vault::try_deserialize(&mut &none[..]).is_err());

    let sizes = &d["accounts"]["sizes"];
    assert_eq!(sizes["vault_h5"].as_u64().unwrap() as usize, Vault::space(LmsType::Sha256M32H5, 0));
    assert_eq!(sizes["vault_h10"].as_u64().unwrap() as usize, Vault::space(LmsType::Sha256M32H10, 0));
    assert_eq!(sizes["vault_h15"].as_u64().unwrap() as usize, Vault::space(LmsType::Sha256M32H15, 0));
    assert_eq!(sizes["key_history_entry"].as_u64().unwrap() as usize, KEY_HASH_LEN);
    assert_eq!(sizes["vault_max_key_history"].as_u64().unwrap(), lamport_vault::MAX_KEY_HISTORY as u64);

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
