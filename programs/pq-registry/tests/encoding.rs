//! Cross-checks the registry's wire formats against `kat/vault_encoding.json`
//! (the SDK's vectors): discriminators, `commit` / `open_pq_buffer` data, PDAs
//! under this program's id, the rotation message and account layouts.

use anchor_lang::prelude::*;
use anchor_lang::{AccountSerialize, Discriminator, InstructionData};
use pq_registry::{signed_message, Commitment, PqSigBuffer, PQ_SEED, PQ_SIG_SEED};
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

    // open_pq_buffer: disc || u64 nonce || [u8;56] new key || u16 sig_len
    let open = hx(&d["instruction_data"]["open_pq_buffer_hex"]);
    let sig_len = u16::from_le_bytes(open[8 + 8 + 56..8 + 8 + 56 + 2].try_into().unwrap());
    assert_eq!(
        I::OpenPqBuffer { nonce: u64s(&d["inputs"]["nonce"]), new_pq_pubkey: h5, sig_len }.data(),
        open
    );
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
    let new_key: [u8; 56] = hx(&m["registry_message_inputs"]["new_pq_pubkey_hex"]).try_into().unwrap();
    assert_eq!(
        signed_message(&pk(&m["registry_message_inputs"]["owner"]), &new_key).to_vec(),
        hx(&m["registry_message_hex"])
    );
}

#[test]
fn account_layouts() {
    let d = v();
    let h10: [u8; 56] = hx(&d["inputs"]["h10_pubkey_hex"]).try_into().unwrap();
    let c_hex = hx(&d["accounts"]["commitment_hex"]);
    // disc(8) version bump owner(32) scheme key(56) next_q(4) created(8) updated(8)
    let c = Commitment {
        version: c_hex[8],
        bump: c_hex[9],
        owner: Pubkey::new_from_array(c_hex[10..42].try_into().unwrap()),
        scheme: c_hex[42],
        pq_pubkey: h10,
        next_q: u32::from_le_bytes(c_hex[99..103].try_into().unwrap()),
        created_slot: u64::from_le_bytes(c_hex[103..111].try_into().unwrap()),
        updated_slot: u64::from_le_bytes(c_hex[111..119].try_into().unwrap()),
    };
    let mut out = Vec::new();
    c.try_serialize(&mut out).unwrap();
    assert_eq!(out, c_hex);
    assert_eq!(out.len(), Commitment::SPACE);

    let b_hex = hx(&d["accounts"]["pq_sig_buffer_hex"]);
    let h5: [u8; 56] = hx(&d["inputs"]["h5_pubkey_hex"]).try_into().unwrap();
    // disc(8) version bump owner(32) payer(32) nonce(8) key(56) sig_len(2) filled(2) vec sig
    let p = 8 + 1 + 1 + 32 + 32 + 8 + 56;
    let sig_len = u16::from_le_bytes(b_hex[p..p + 2].try_into().unwrap());
    let filled = u16::from_le_bytes(b_hex[p + 2..p + 4].try_into().unwrap());
    let b = PqSigBuffer {
        version: b_hex[8],
        bump: b_hex[9],
        owner: Pubkey::new_from_array(b_hex[10..42].try_into().unwrap()),
        payer: Pubkey::new_from_array(b_hex[42..74].try_into().unwrap()),
        nonce: u64::from_le_bytes(b_hex[74..82].try_into().unwrap()),
        new_pq_pubkey: h5,
        sig_len,
        filled,
        sig: b_hex[p + 8..p + 8 + sig_len as usize].to_vec(),
    };
    let mut out = Vec::new();
    b.try_serialize(&mut out).unwrap();
    assert_eq!(out, b_hex);
    assert_eq!(out.len(), PqSigBuffer::space(sig_len as usize));
}
