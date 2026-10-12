//! Cross-checks the registry's wire formats against `kat/vault_encoding.json`
//! (the SDK's vectors): discriminators, `commit` / `open_pq_buffer` data, PDAs
//! under this program's id, the rotation message and account layouts.

use anchor_lang::prelude::*;
use anchor_lang::{AccountSerialize, Discriminator, InstructionData};
use pq_registry::{signed_message, Commitment, PqSigBuffer, KEY_HASH_LEN, MAX_VALIDITY_SLOTS, MESSAGE_VERSION, PQ_SEED, PQ_SIG_SEED};
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

#[test]
fn vectors_target_this_program_id() {
    assert_eq!(pk(&v()["program_ids"]["pq_registry"]), pq_registry::ID);
}

#[test]
fn discriminators_and_instruction_data() {
    let d = v();
    let ix = &d["discriminators"]["instructions"];
    use pq_registry::instruction as I;
    assert_eq!(I::Commit::DISCRIMINATOR.to_vec(), hx(&ix["commit"]));
    assert_eq!(I::OpenPqBuffer::DISCRIMINATOR.to_vec(), hx(&ix["open_pq_buffer"]));
    assert_eq!(I::WritePqSig::DISCRIMINATOR.to_vec(), hx(&ix["write_pq_sig"]));
    assert_eq!(I::ClosePqBuffer::DISCRIMINATOR.to_vec(), hx(&ix["close_pq_buffer"]));
    assert_eq!(I::RotatePq::DISCRIMINATOR.to_vec(), hx(&ix["rotate_pq"]));
    let acc = &d["discriminators"]["accounts"];
    assert_eq!(Commitment::DISCRIMINATOR.to_vec(), hx(&acc["Commitment"]));
    assert_eq!(PqSigBuffer::DISCRIMINATOR.to_vec(), hx(&acc["PqSigBuffer"]));

    let h10: [u8; 56] = hx(&d["inputs"]["h10_pubkey_hex"]).try_into().unwrap();
    let h5: [u8; 56] = hx(&d["inputs"]["h5_pubkey_hex"]).try_into().unwrap();
    assert_eq!(I::Commit { pq_pubkey: h10 }.data(), hx(&d["instruction_data"]["commit_hex"]));

    // open_pq_buffer: disc || u64 nonce || [u8;56] new key || u16 sig_len || u64 issued_slot || u64 expiry_slot
    let open = hx(&d["instruction_data"]["open_pq_buffer_hex"]);
    let p = 8 + 8 + 56;
    let sig_len = u16::from_le_bytes(open[p..p + 2].try_into().unwrap());
    let issued_slot = u64::from_le_bytes(open[p + 2..p + 10].try_into().unwrap());
    let expiry_slot = u64::from_le_bytes(open[p + 10..p + 18].try_into().unwrap());
    assert_eq!(open.len(), p + 18, "trailing bytes in open_pq_buffer vector");
    assert_eq!(issued_slot, u64s(&d["inputs"]["issued_slot"]));
    assert_eq!(expiry_slot, u64s(&d["inputs"]["expiry_slot"]));
    assert_eq!(
        I::OpenPqBuffer { nonce: u64s(&d["inputs"]["nonce"]), new_pq_pubkey: h5, sig_len, issued_slot, expiry_slot }.data(),
        open
    );
    assert_eq!(d["validity"]["max_validity_slots"].as_u64().unwrap(), MAX_VALIDITY_SLOTS);
}

#[test]
fn pdas_and_message() {
    let d = v();
    let owner = pk(&d["inputs"]["pk_11"]);
    let payer = pk(&d["inputs"]["pk_22"]);
    let nonce = u64s(&d["inputs"]["nonce"]);
    let (c, bump) = Pubkey::find_program_address(&[PQ_SEED, owner.as_ref()], &pq_registry::ID);
    assert_eq!(c, pk(&d["pdas"]["commitment"]["address"]));
    assert_eq!(bump as u64, d["pdas"]["commitment"]["bump"].as_u64().unwrap());
    let (b, bump) = Pubkey::find_program_address(
        &[PQ_SIG_SEED, owner.as_ref(), payer.as_ref(), &nonce.to_le_bytes()],
        &pq_registry::ID,
    );
    assert_eq!(b, pk(&d["pdas"]["pq_sig_buffer"]["address"]));
    assert_eq!(bump as u64, d["pdas"]["pq_sig_buffer"]["bump"].as_u64().unwrap());

    let m = &d["messages"];
    assert_eq!(pq_registry::MESSAGE_DOMAIN.to_vec(), hx(&m["registry_prefix_hex"]));
    assert_eq!(m["message_version"].as_u64().unwrap(), MESSAGE_VERSION as u64);
    let inp = &m["registry_message_inputs"];
    assert_eq!(pk(&inp["program_id"]), pq_registry::ID);
    let new_key: [u8; 56] = hx(&inp["new_pq_pubkey_hex"]).try_into().unwrap();
    let generation = u32s(&inp["generation"]);
    let issued = u64s(&inp["issued_slot"]);
    let expiry = u64s(&inp["expiry_slot"]);
    let owner = pk(&inp["owner"]);
    assert_eq!(signed_message(&owner, generation, &new_key, issued, expiry).to_vec(), hx(&m["registry_message_hex"]));
    assert_ne!(signed_message(&owner, generation + 1, &new_key, issued, expiry).to_vec(), hx(&m["registry_message_hex"]));
    assert_ne!(signed_message(&owner, generation, &new_key, issued + 1, expiry).to_vec(), hx(&m["registry_message_hex"]));
    assert_ne!(signed_message(&owner, generation, &new_key, issued, expiry + 1).to_vec(), hx(&m["registry_message_hex"]));
}

#[test]
fn account_layouts() {
    let d = v();
    let h10: [u8; 56] = hx(&d["inputs"]["h10_pubkey_hex"]).try_into().unwrap();
    let c_hex = hx(&d["accounts"]["commitment_hex"]);
    // disc(8) version bump owner(32) scheme key(56) next_q(4) generation(4) created(8) updated(8)
    // || vec<[u8;16]> used_keys
    assert_eq!(c_hex[8], Commitment::VERSION);
    let hist_len = u32::from_le_bytes(c_hex[123..127].try_into().unwrap()) as usize;
    let used_keys: Vec<[u8; KEY_HASH_LEN]> =
        (0..hist_len).map(|i| c_hex[127 + 16 * i..127 + 16 * (i + 1)].try_into().unwrap()).collect();
    assert_eq!(c_hex.len(), 127 + 16 * hist_len, "trailing bytes in commitment vector");
    let c = Commitment {
        version: c_hex[8],
        bump: c_hex[9],
        owner: Pubkey::new_from_array(c_hex[10..42].try_into().unwrap()),
        scheme: c_hex[42],
        pq_pubkey: h10,
        next_q: u32::from_le_bytes(c_hex[99..103].try_into().unwrap()),
        generation: u32::from_le_bytes(c_hex[103..107].try_into().unwrap()),
        created_slot: u64::from_le_bytes(c_hex[107..115].try_into().unwrap()),
        updated_slot: u64::from_le_bytes(c_hex[115..123].try_into().unwrap()),
        used_keys,
    };
    assert_eq!(c.generation as usize, hist_len);
    let h5: [u8; 56] = hx(&d["inputs"]["h5_pubkey_hex"]).try_into().unwrap();
    assert!(c.has_used_key(&h5), "the H5 key is in the vector's history");
    let mut out = Vec::new();
    c.try_serialize(&mut out).unwrap();
    assert_eq!(out, c_hex);
    assert_eq!(out.len(), Commitment::space(hist_len));
    let sizes = &d["accounts"]["sizes"];
    assert_eq!(sizes["commitment"].as_u64().unwrap() as usize, Commitment::SPACE);
    assert_eq!(sizes["commitment_max_key_history"].as_u64().unwrap(), pq_registry::MAX_KEY_HISTORY as u64);

    let b_hex = hx(&d["accounts"]["pq_sig_buffer_hex"]);
    let h5: [u8; 56] = hx(&d["inputs"]["h5_pubkey_hex"]).try_into().unwrap();
    // disc(8) version bump owner(32) payer(32) nonce(8) key(56) issued(8) expiry(8) sig_len(2) filled(2) vec sig
    let w = 8 + 1 + 1 + 32 + 32 + 8 + 56;
    let p = w + 16;
    let issued_slot = u64::from_le_bytes(b_hex[w..w + 8].try_into().unwrap());
    let expiry_slot = u64::from_le_bytes(b_hex[w + 8..w + 16].try_into().unwrap());
    assert_eq!(issued_slot, u64s(&d["inputs"]["issued_slot"]));
    assert_eq!(expiry_slot, u64s(&d["inputs"]["expiry_slot"]));
    let sig_len = u16::from_le_bytes(b_hex[p..p + 2].try_into().unwrap());
    let filled = u16::from_le_bytes(b_hex[p + 2..p + 4].try_into().unwrap());
    let b = PqSigBuffer {
        version: b_hex[8],
        bump: b_hex[9],
        owner: Pubkey::new_from_array(b_hex[10..42].try_into().unwrap()),
        payer: Pubkey::new_from_array(b_hex[42..74].try_into().unwrap()),
        nonce: u64::from_le_bytes(b_hex[74..82].try_into().unwrap()),
        new_pq_pubkey: h5,
        issued_slot,
        expiry_slot,
        sig_len,
        filled,
        sig: b_hex[p + 8..p + 8 + sig_len as usize].to_vec(),
    };
    let mut out = Vec::new();
    b.try_serialize(&mut out).unwrap();
    assert_eq!(out, b_hex);
    assert_eq!(out.len(), PqSigBuffer::space(sig_len as usize));
}
