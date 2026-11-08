//! Helpers for the LiteSVM tests of `execute_direct`: the vault's wire formats, rebuilt here
//! byte for byte (no dependency on the program crate, so one solana crate set in the graph).
use lamport_lms::{LmotsType, LmsPrivateKey, LmsType};
use sha2::{Digest, Sha256};
use solana_address::Address;

pub type Pubkey = Address;

fn hashv(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub const PROGRAM_ID: Pubkey = Address::from_str_const("B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH");
pub const TOKEN_PROGRAM_ID: Pubkey = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const MESSAGE_DOMAIN: &[u8] = b"lamport-vault/v1";

/// Anchor instruction discriminators, `sha256("global:<name>")[..8]`.
pub const IX_CREATE_VAULT: [u8; 8] = [29, 237, 247, 208, 193, 82, 54, 135];
pub const IX_EXECUTE_DIRECT: [u8; 8] = [242, 7, 89, 162, 34, 140, 116, 30];
pub const VAULT_DISC: [u8; 8] = [211, 8, 232, 43, 2, 152, 117, 119];
pub const TOMBSTONE_DISC: [u8; 8] = [45, 187, 252, 155, 232, 114, 36, 22];
pub const TOMBSTONE_SPACE: usize = 8 + 1 + 32 + 8 + 32;

/// `VaultError` codes (declaration order from 6000).
pub const ERR_SIGNATURE_TYPE_MISMATCH: u32 = 6009;
pub const ERR_LEAF_ALREADY_USED: u32 = 6012;
pub const ERR_INVALID_SIGNATURE: u32 = 6013;
pub const ERR_WRONG_DESTINATION: u32 = 6019;
pub const ERR_VAULT_CLOSED: u32 = 6032;

pub fn h5_key(seed_byte: u8) -> LmsPrivateKey {
    LmsPrivateKey::new(LmsType::Sha256M32H5, LmotsType::Sha256N32W4, [seed_byte; 16], [seed_byte; 32])
}

pub fn vault_id_for(lms_pubkey: &[u8; 56]) -> [u8; 32] {
    hashv(&[lms_pubkey])
}

pub fn vault_address(vault_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault", vault_id], &PROGRAM_ID)
}

/// `sha256("lamport-vault/v1" || program_id || vault || u32le(generation) || action)`.
pub fn signed_message(vault: &Pubkey, generation: u32, action: &[u8]) -> [u8; 32] {
    hashv(&[MESSAGE_DOMAIN, PROGRAM_ID.as_ref(), vault.as_ref(), &generation.to_le_bytes(), action])
}

fn window(out: &mut Vec<u8>, issued: u64, expiry: u64) {
    out.extend_from_slice(&issued.to_le_bytes());
    out.extend_from_slice(&expiry.to_le_bytes());
}

/// Borsh `Action` (programs/lamport-vault/src/action.rs).
pub mod action {
    use super::*;
    pub fn transfer_sol(to: &Pubkey, lamports: u64, issued: u64, expiry: u64) -> Vec<u8> {
        let mut v = vec![0u8];
        v.extend_from_slice(to.as_ref());
        v.extend_from_slice(&lamports.to_le_bytes());
        window(&mut v, issued, expiry);
        v
    }
    pub fn transfer_token(mint: &Pubkey, to: &Pubkey, amount: u64, issued: u64, expiry: u64) -> Vec<u8> {
        let mut v = vec![1u8];
        v.extend_from_slice(mint.as_ref());
        v.extend_from_slice(to.as_ref());
        v.extend_from_slice(&amount.to_le_bytes());
        window(&mut v, issued, expiry);
        v
    }
    pub fn rotate(new_lms_pubkey: &[u8; 56], issued: u64, expiry: u64) -> Vec<u8> {
        let mut v = vec![2u8];
        v.extend_from_slice(new_lms_pubkey);
        window(&mut v, issued, expiry);
        v
    }
    pub fn close(to: &Pubkey, issued: u64, expiry: u64) -> Vec<u8> {
        let mut v = vec![3u8];
        v.extend_from_slice(to.as_ref());
        window(&mut v, issued, expiry);
        v
    }
}

/// The `Vault` account, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultState {
    pub version: u8,
    pub bump: u8,
    pub vault_id: [u8; 32],
    pub lms_pubkey: [u8; 56],
    pub spent: u32,
    pub generation: u32,
    pub created_slot: u64,
    pub used: Vec<u8>,
    pub used_keys: Vec<[u8; 16]>,
}

pub fn decode_vault(data: &[u8]) -> VaultState {
    assert_eq!(&data[..8], &VAULT_DISC, "not a Vault");
    let mut o = 8;
    let mut take = |n: usize| { let s = &data[o..o + n]; o += n; s };
    let version = take(1)[0];
    let bump = take(1)[0];
    let vault_id: [u8; 32] = take(32).try_into().unwrap();
    let lms_pubkey: [u8; 56] = take(56).try_into().unwrap();
    let spent = u32::from_le_bytes(take(4).try_into().unwrap());
    let generation = u32::from_le_bytes(take(4).try_into().unwrap());
    let created_slot = u64::from_le_bytes(take(8).try_into().unwrap());
    let n = u32::from_le_bytes(take(4).try_into().unwrap()) as usize;
    let used = take(n).to_vec();
    let k = u32::from_le_bytes(take(4).try_into().unwrap()) as usize;
    let used_keys = (0..k).map(|_| take(16).try_into().unwrap()).collect();
    VaultState { version, bump, vault_id, lms_pubkey, spent, generation, created_slot, used, used_keys }
}

impl VaultState {
    pub fn is_used(&self, q: u32) -> bool {
        self.used[(q / 8) as usize] & (1 << (q % 8)) != 0
    }
}

/// `sha256(lms_pubkey)[..16]`, what `Rotate` stores in `used_keys`.
pub fn key_hash(lms_pubkey: &[u8; 56]) -> [u8; 16] {
    let full = hashv(&[lms_pubkey]);
    full[..16].try_into().unwrap()
}

/// Instruction data of `execute_direct(action, signature)`: discriminator, then two Borsh `Vec<u8>`.
pub fn execute_direct_data(action: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut d = IX_EXECUTE_DIRECT.to_vec();
    d.extend_from_slice(&(action.len() as u32).to_le_bytes());
    d.extend_from_slice(action);
    d.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    d.extend_from_slice(signature);
    d
}

pub fn create_vault_data(vault_id: &[u8; 32], lms_pubkey: &[u8; 56]) -> Vec<u8> {
    let mut d = IX_CREATE_VAULT.to_vec();
    d.extend_from_slice(vault_id);
    d.extend_from_slice(lms_pubkey);
    d
}
