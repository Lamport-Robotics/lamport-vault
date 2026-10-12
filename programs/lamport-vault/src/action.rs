//! The Borsh `Action` enum that a signature authorises.
//!
//! Encoding (Borsh): one byte variant index, then the fields in order, all
//! integers little-endian. Every variant ends in the validity window
//! `issued_slot: u64, expiry_slot: u64` (see [`crate::MAX_VALIDITY_SLOTS`]).
//!
//! ```text
//! 0 TransferSol   { to: Pubkey, lamports: u64, issued_slot: u64, expiry_slot: u64 }         57 bytes
//! 1 TransferToken { mint: Pubkey, to: Pubkey, amount: u64, issued_slot: u64, expiry_slot: u64 }  89 bytes
//! 2 Rotate        { new_lms_pubkey: [u8; 56], issued_slot: u64, expiry_slot: u64 }          73 bytes
//! 3 Close         { to: Pubkey, issued_slot: u64, expiry_slot: u64 }                        49 bytes
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
        /// Slot the action was signed at; must not be in the future.
        issued_slot: u64,
        /// Last slot at which the action may execute; at most `issued_slot + MAX_VALIDITY_SLOTS`.
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
        /// Slot the action was signed at; must not be in the future.
        issued_slot: u64,
        /// Last slot at which the action may execute; at most `issued_slot + MAX_VALIDITY_SLOTS`.
        expiry_slot: u64,
    },
    /// Replace the LMS key: bitmap cleared, `spent = 0`, `generation += 1`. The
    /// new key must have the same typecodes and must never have been this
    /// vault's key before.
    Rotate {
        /// The new 56-byte LMS public key.
        new_lms_pubkey: [u8; 56],
        /// Slot the action was signed at; must not be in the future.
        issued_slot: u64,
        /// Last slot at which the action may execute; at most `issued_slot + MAX_VALIDITY_SLOTS`.
        expiry_slot: u64,
    },
    /// Send every lamport but a tombstone's rent to `to` and rewrite the account
    /// as a [`crate::Tombstone`]; the address can never hold a vault again.
    Close {
        /// Destination of the lamports.
        to: Pubkey,
        /// Slot the action was signed at; must not be in the future.
        issued_slot: u64,
        /// Last slot at which the action may execute; at most `issued_slot + MAX_VALIDITY_SLOTS`.
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

    /// The action's validity window `(issued_slot, expiry_slot)`.
    pub fn window(&self) -> (u64, u64) {
        match self {
            Action::TransferSol { issued_slot, expiry_slot, .. }
            | Action::TransferToken { issued_slot, expiry_slot, .. }
            | Action::Rotate { issued_slot, expiry_slot, .. }
            | Action::Close { issued_slot, expiry_slot, .. } => (*issued_slot, *expiry_slot),
        }
    }

    /// The action's issued slot.
    pub fn issued_slot(&self) -> u64 {
        self.window().0
    }

    /// The action's expiry slot.
    pub fn expiry_slot(&self) -> u64 {
        self.window().1
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
            issued_slot: 8,
            expiry_slot: 9,
        };
        let b = a.encode();
        assert_eq!(b.len(), 57);
        assert_eq!(b[0], 0);
        assert_eq!(&b[41..49], &8u64.to_le_bytes(), "issued_slot sits before expiry_slot");
        assert_eq!(&b[49..57], &9u64.to_le_bytes());
        assert_eq!(Action::decode(&b).unwrap(), a);
        assert_eq!(a.window(), (8, 9));

        let t = Action::TransferToken {
            mint: Pubkey::new_unique(),
            to: Pubkey::new_unique(),
            amount: 1,
            issued_slot: 1,
            expiry_slot: 2,
        };
        assert_eq!(t.encode().len(), 89);
        let r = Action::Rotate {
            new_lms_pubkey: [7; 56],
            issued_slot: 2,
            expiry_slot: 3,
        };
        assert_eq!(r.encode().len(), 73);
        let c = Action::Close {
            to: Pubkey::new_unique(),
            issued_slot: 3,
            expiry_slot: 4,
        };
        assert_eq!(c.encode().len(), 49);
        assert_eq!(c.encode()[0], 3);
        assert_eq!(c.issued_slot(), 3);
        assert_eq!(c.expiry_slot(), 4);

        let mut trailing = c.encode();
        trailing.push(0);
        assert!(Action::decode(&trailing).is_err());
        assert!(Action::decode(&b[..56]).is_err());
        assert!(Action::decode(&[9]).is_err());
    }
}
