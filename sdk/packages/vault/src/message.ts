/** The messages the LMS key actually signs. Both carry the key generation (vault `rotations`, commitment `generation`). */
import { sha256 } from "@noble/hashes/sha2.js";
import { PublicKey } from "@solana/web3.js";
import { ByteWriter } from "./borsh.ts";

const enc = new TextEncoder();

export const VAULT_MESSAGE_PREFIX = enc.encode("lamport-vault/v1");
export const REGISTRY_MESSAGE_PREFIX = enc.encode("pq-registry/v1");

/**
 * message = sha256("lamport-vault/v1" || vault_pubkey || u32le(rotations) || action_bytes)
 *
 * `rotations` is the vault account's current value: a signature is valid only under the key
 * generation it was made for.
 */
export function vaultMessage(vault: PublicKey, rotations: number, actionBytes: Uint8Array): Uint8Array {
  return sha256(new ByteWriter().raw(VAULT_MESSAGE_PREFIX).pubkey(vault).u32(rotations).raw(actionBytes).bytes());
}

/** message = sha256("pq-registry/v1" || owner || u32le(generation) || new_pq_pubkey) */
export function registryMessage(owner: PublicKey, generation: number, newPqPubkey: Uint8Array): Uint8Array {
  if (newPqPubkey.length !== 56) throw new Error("pq_pubkey must be 56 bytes");
  return sha256(new ByteWriter().raw(REGISTRY_MESSAGE_PREFIX).pubkey(owner).u32(generation).raw(newPqPubkey).bytes());
}
