//! Error codes. Anchor numbers them from 6000 in declaration order.

use anchor_lang::prelude::*;

/// Every way an instruction can fail that is specific to this program.
#[error_code]
pub enum VaultError {
    #[msg("LMS typecode must be 5..=7 (H5, H10, H15)")]
    InvalidLmsType, // 6000
    #[msg("LM-OTS typecode must be 3 (SHA256_N32_W4)")]
    InvalidLmotsType, // 6001
    #[msg("public key is malformed")]
    InvalidPublicKey, // 6002
    #[msg("action must be 1..=256 bytes")]
    ActionTooLarge, // 6003
    #[msg("action bytes do not decode to exactly one Action")]
    ActionDecode, // 6004
    #[msg("sig_len is not the signature length of the vault's parameter set")]
    SignatureLengthMismatch, // 6005
    #[msg("offset must equal the number of bytes written so far")]
    OffsetMismatch, // 6006
    #[msg("chunk would write past sig_len")]
    ChunkOutOfBounds, // 6007
    #[msg("signature buffer is not completely written")]
    SignatureIncomplete, // 6008
    #[msg("signature typecodes differ from the vault's key")]
    SignatureTypeMismatch, // 6009
    #[msg("signature is malformed")]
    SignatureMalformed, // 6010
    #[msg("leaf index q is outside the tree")]
    LeafOutOfRange, // 6011
    #[msg("leaf q is already spent")]
    LeafAlreadyUsed, // 6012
    #[msg("LMS signature does not verify")]
    InvalidSignature, // 6013
    #[msg("action expired: expiry_slot is in the past")]
    ActionExpired, // 6014
    #[msg("the last free leaf may only be spent on Rotate")]
    LastLeafReservedForRotate, // 6015
    #[msg("transfer would take the vault below its rent-exempt minimum")]
    InsufficientFunds, // 6016
    #[msg("Rotate to a key this vault has used before (including the current one)")]
    KeyReused, // 6017
    #[msg("a required remaining account is missing")]
    MissingAccount, // 6018
    #[msg("destination account does not match the signed action")]
    WrongDestination, // 6019
    #[msg("mint account does not match the signed action")]
    WrongMint, // 6020
    #[msg("token program must be Token or Token-2022 and own the token accounts")]
    InvalidTokenProgram, // 6021
    #[msg("token account must be empty before Close")]
    TokenAccountNotEmpty, // 6022
    #[msg("destination must not be the vault or the buffer itself")]
    SelfTransfer, // 6023
    #[msg("signature buffer belongs to another vault")]
    VaultMismatch, // 6024
    #[msg("signer is not the buffer's payer")]
    WrongPayer, // 6025
    #[msg("arithmetic overflow")]
    Overflow, // 6026
    #[msg("vault_id must equal sha256(lms_pubkey)")]
    VaultIdMismatch, // 6027
    #[msg("key history is full; Close the vault and create a new one")]
    HistoryFull, // 6028
    #[msg("Rotate must keep the vault's LMS and LM-OTS typecodes")]
    RotateTypeMismatch, // 6029
    #[msg("action issued in the future: issued_slot is beyond the current slot")]
    IssuedInFuture, // 6030
    #[msg("validity window is inverted or longer than MAX_VALIDITY_SLOTS")]
    InvalidValidityWindow, // 6031
    #[msg("vault is closed: a Tombstone holds its address; create a vault with a fresh key")]
    VaultClosed, // 6032
}
