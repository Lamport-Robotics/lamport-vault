/** PDA derivations for both programs (docs/DESIGN.md Sections 2 and 3). */
import { sha256 } from "@noble/hashes/sha2.js";
import { PublicKey } from "@solana/web3.js";
import { u64le } from "./borsh.ts";

const enc = new TextEncoder();

export const VAULT_SEED = enc.encode("vault");
export const SIG_SEED = enc.encode("sig");
export const PQ_SEED = enc.encode("pq");
/** Staging buffer for `rotate_pq` (`PqSigBuffer`), mirrors the vault's SigBuffer. */
export const PQ_SIG_SEED = enc.encode("pqsig");

export interface Pda {
  readonly address: PublicKey;
  readonly bump: number;
}

/** vault_id = sha256(initial lms_pubkey), 56 bytes in. */
export function vaultId(lmsPubkey: Uint8Array): Uint8Array {
  if (lmsPubkey.length !== 56) throw new Error("lms_pubkey must be 56 bytes");
  return sha256(lmsPubkey);
}

/** ["vault", vault_id] */
export function findVaultPda(programId: PublicKey, vaultIdBytes: Uint8Array): Pda {
  if (vaultIdBytes.length !== 32) throw new Error("vault_id must be 32 bytes");
  const [address, bump] = PublicKey.findProgramAddressSync([VAULT_SEED, vaultIdBytes], programId);
  return { address, bump };
}

/** Convenience: vault PDA straight from the initial LMS public key. */
export function findVaultPdaForKey(programId: PublicKey, lmsPubkey: Uint8Array): Pda {
  return findVaultPda(programId, vaultId(lmsPubkey));
}

/** ["sig", vault, payer, nonce_le_u64] */
export function findSigBufferPda(programId: PublicKey, vault: PublicKey, payer: PublicKey, nonce: bigint | number): Pda {
  const [address, bump] = PublicKey.findProgramAddressSync(
    [SIG_SEED, vault.toBytes(), payer.toBytes(), u64le(nonce)],
    programId,
  );
  return { address, bump };
}

/** ["pq", owner] */
export function findCommitmentPda(programId: PublicKey, owner: PublicKey): Pda {
  const [address, bump] = PublicKey.findProgramAddressSync([PQ_SEED, owner.toBytes()], programId);
  return { address, bump };
}

/** ["pqsig", owner, payer, nonce_le_u64] */
export function findPqSigBufferPda(programId: PublicKey, owner: PublicKey, payer: PublicKey, nonce: bigint | number): Pda {
  const [address, bump] = PublicKey.findProgramAddressSync(
    [PQ_SIG_SEED, owner.toBytes(), payer.toBytes(), u64le(nonce)],
    programId,
  );
  return { address, bump };
}

export const TOKEN_PROGRAM_ID = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const TOKEN_2022_PROGRAM_ID = new PublicKey("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
export const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/** The associated token account of `owner` (works for PDAs) for `mint` under the given token program. */
export function associatedTokenAddress(owner: PublicKey, mint: PublicKey, tokenProgram = TOKEN_PROGRAM_ID): PublicKey {
  const [address] = PublicKey.findProgramAddressSync(
    [owner.toBytes(), tokenProgram.toBytes(), mint.toBytes()],
    ASSOCIATED_TOKEN_PROGRAM_ID,
  );
  return address;
}
