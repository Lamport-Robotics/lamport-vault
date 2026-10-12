/** The messages the LMS key actually signs. Both bind the program id and the key generation. */
import { sha256 } from "@noble/hashes/sha2.js";
import { PublicKey } from "@solana/web3.js";
import { ByteWriter } from "./borsh.ts";
import { LAMPORT_VAULT_PROGRAM_ID, PQ_REGISTRY_PROGRAM_ID } from "./programIds.ts";

const enc = new TextEncoder();

/** Version of the signed-message format (the domain strings end in it). Mirrors the programs' `MESSAGE_VERSION`. */
export const MESSAGE_VERSION = 1;
export const VAULT_MESSAGE_PREFIX = enc.encode(`lamport-vault/v${MESSAGE_VERSION}`);
export const REGISTRY_MESSAGE_PREFIX = enc.encode(`pq-registry/v${MESSAGE_VERSION}`);

/**
 * message = sha256("lamport-vault/v1" || program_id || vault_pubkey || u32le(generation) || action_bytes)
 *
 * `generation` is the vault account's current value: a signature is valid only under the key
 * generation it was made for. `programId` defaults to the id declared in `programs/lamport-vault`.
 */
export function vaultMessage(vault: PublicKey, generation: number, actionBytes: Uint8Array, programId: PublicKey = LAMPORT_VAULT_PROGRAM_ID): Uint8Array {
  return sha256(new ByteWriter().raw(VAULT_MESSAGE_PREFIX).pubkey(programId).pubkey(vault).u32(generation).raw(actionBytes).bytes());
}

/** message = sha256("pq-registry/v1" || program_id || owner || u32le(generation) || new_pq_pubkey) */
export function registryMessage(owner: PublicKey, generation: number, newPqPubkey: Uint8Array, programId: PublicKey = PQ_REGISTRY_PROGRAM_ID): Uint8Array {
  if (newPqPubkey.length !== 56) throw new Error("pq_pubkey must be 56 bytes");
  return sha256(new ByteWriter().raw(REGISTRY_MESSAGE_PREFIX).pubkey(programId).pubkey(owner).u32(generation).raw(newPqPubkey).bytes());
}
