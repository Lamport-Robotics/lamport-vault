import { PublicKey } from "@solana/web3.js";

/**
 * Program ids as declared in `programs/lamport-vault` and `programs/pq-registry` (`declare_id!`).
 * Every builder and client takes a `programId` so a different deployment can be addressed.
 */
export const LAMPORT_VAULT_PROGRAM_ID = new PublicKey("B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH");
export const PQ_REGISTRY_PROGRAM_ID = new PublicKey("48J2BtWFjEUbGPYf1yMPBkHxpy4dLo69gK2znQR2q2ad");

/**
 * The Heir-enabled vault: `programs/lamport-vault` built with the `succession` feature, which is a
 * separate program with its own id (docs/SUCCESSION.md). Nothing is deployed yet: this id is a
 * placeholder with no private key, the SHA-256 of `lamport-heir/placeholder-program-id/heir-vault/v1`.
 * It changes when the program is first deployed.
 */
export const LAMPORT_VAULT_HEIR_PROGRAM_ID = new PublicKey("HK1QPbqjkozJHB74QuGaduYzAtqBe9hry3nV64LmpCsb");
/** The `short-clocks` test build of the Heir-enabled vault, in which a day lasts a second. Placeholder, as above. */
export const LAMPORT_VAULT_HEIR_SHORT_CLOCKS_PROGRAM_ID = new PublicKey("DGe6SeUVApXcN7j3X613SeTmazXGqtAuFSn7RQWBiDDS");
