import { PublicKey } from "@solana/web3.js";

/**
 * Program ids as declared in `programs/lamport-vault` and `programs/pq-registry` (`declare_id!`).
 * Every builder and client takes a `programId` so a different deployment can be addressed.
 */
export const LAMPORT_VAULT_PROGRAM_ID = new PublicKey("B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH");
export const PQ_REGISTRY_PROGRAM_ID = new PublicKey("48J2BtWFjEUbGPYf1yMPBkHxpy4dLo69gK2znQR2q2ad");
