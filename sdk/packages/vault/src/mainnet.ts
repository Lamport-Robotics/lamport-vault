import { PublicKey } from "@solana/web3.js";

/**
 * The mainnet program ids: what `declare_id!` compiles in when the programs are built with the
 * `mainnet` cargo feature (docs/VERIFY.md).
 *
 * Mainnet has ids of its own because the message a vault key signs binds the program id and
 * nothing else about the cluster: under the devnet ids, a devnet signature by a raw or hardware
 * key would be a mainnet signature too.
 *
 * They live in this file, and not in `programIds.ts`, so that a devnet bundle does not carry them.
 * Nothing in the SDK defaults to them: a caller that means mainnet passes `programId`.
 */
export const LAMPORT_VAULT_MAINNET_PROGRAM_ID = new PublicKey("7EiE5pRP5byrY7mzvUBfXS2UD8GwGtPhbGne6D1BTR5H");
export const PQ_REGISTRY_MAINNET_PROGRAM_ID = new PublicKey("9MYg9uqYBrTPXA6MNRZ6cbpwHSissY3496Y84iofTaNF");
/** The Heir-enabled vault on mainnet: `mainnet` and `succession` together (docs/SUCCESSION.md). */
export const LAMPORT_VAULT_HEIR_MAINNET_PROGRAM_ID = new PublicKey("3XsnTrQJ5XmFyEyVauMmMseHph4wXkn6QWUZCRPjuEEX");
