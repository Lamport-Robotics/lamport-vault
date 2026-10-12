//! The Borsh `Action` enum that a signature authorises.
//!
//! Encoding (Borsh): one byte variant index, then the fields in order, all
//! integers little-endian.
//!
//! ```text
//! 0 TransferSol   { to: Pubkey, lamports: u64, expiry_slot: u64 }        49 bytes
//! 1 TransferToken { mint: Pubkey, to: Pubkey, amount: u64, expiry_slot: u64 }  81 bytes
//! 2 Rotate        { new_lms_pubkey: [u8; 56], expiry_slot: u64 }         65 bytes
//! 3 Close         { to: Pubkey, expiry_slot: u64 }                       41 bytes
//! ```

use anchor_lang::prelude::*;

use crate::error::VaultError;

/// What a signature authorises the vault to do.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Move `lamports` to `to`, keeping the vault rent-exempt.
    TransferSol {
        /// Destination system account (any account; receives lamports directly).
        to: Pubkey,
        /// Amount in lamports.
        lamports: u64,
        /// Last slot at which the action may execute.
        expiry_slot: u64,
    },
    /// SPL transfer (Token or Token-2022) signed by the vault PDA.
    TransferToken {
        /// The token mint.
        mint: Pubkey,
        /// Destination token account.
        to: Pubkey,
        /// Amount in base units.
        amount: u64,
        /// Last slot at which the action may execute.
        expiry_slot: u64,
    },
    /// Replace the LMS key. `next_q` resets to 0, `rotations += 1`.
    Rotate {
        /// The new 56-byte LMS public key.
        new_lms_pubkey: [u8; 56],
        /// Last slot at which the action may execute.
        expiry_slot: u64,
    },
    /// Send every lamport to `to` and delete the vault account.
    Close {
        /// Destination of all lamports.
        to: Pubkey,
        /// Last slot at which the action may execute.
        expiry_slot: u64,
    },
}

impl Action {
    /// Decodes exactly one `Action`; trailing bytes are an error.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut slice = bytes;
        let action = Action::deserialize(&mut slice).map_err(|_| VaultError::ActionDecode)?;
        require!(slice.is_empty(), VaultError::ActionDecode);
        Ok(action)
    }

    /// Borsh encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        self.serialize(&mut out).expect("in-memory serialize");
        out
    }

    /// The action's expiry slot.
    pub fn expiry_slot(&self) -> u64 {
        match self {
            Action::TransferSol { expiry_slot, .. }
            | Action::TransferToken { expiry_slot, .. }
            | Action::Rotate { expiry_slot, .. }
            | Action::Close { expiry_slot, .. } => *expiry_slot,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_sizes_and_round_trip() {
        let a = Action::TransferSol {
            to: Pubkey::new_unique(),
            lamports: 5,
            expiry_slot: 9,
        };
        let b = a.encode();
        assert_eq!(b.len(), 49);
        assert_eq!(b[0], 0);
        assert_eq!(Action::decode(&b).unwrap(), a);

        let t = Action::TransferToken {
            mint: Pubkey::new_unique(),
            to: Pubkey::new_unique(),
            amount: 1,
            expiry_slot: 2,
        };
        assert_eq!(t.encode().len(), 81);
        let r = Action::Rotate {
            new_lms_pubkey: [7; 56],
            expiry_slot: 3,
        };
        assert_eq!(r.encode().len(), 65);
        let c = Action::Close {
            to: Pubkey::new_unique(),
            expiry_slot: 4,
        };
        assert_eq!(c.encode().len(), 41);
        assert_eq!(c.encode()[0], 3);

        let mut trailing = c.encode();
        trailing.push(0);
        assert!(Action::decode(&trailing).is_err());
        assert!(Action::decode(&b[..48]).is_err());
        assert!(Action::decode(&[9]).is_err());
    }
}
