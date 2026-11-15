/**
 * The vault SDK as a mainnet build of the vault's own page and signer sees it. The programs on
 * mainnet are the same source under other ids (docs/VERIFY.md), so the page and the signer are the
 * same source too, with three names meaning something else:
 *
 *   LAMPORT_VAULT_PROGRAM_ID   the vault program's mainnet id
 *   PQ_REGISTRY_PROGRAM_ID     the registry program's mainnet id
 *   vaultMessage               binds the mainnet id when the caller names none (a signature made
 *                              for the devnet id is refused on mainnet, and should be)
 *
 * A mainnet build resolves `@lamport-robotics/vault` to this file (cluster.config.ts); a devnet
 * build never sees it. The Heir build has its own file, heir-sdk.ts, which knows both clusters.
 * Everything else is the SDK, untouched.
 */
export * from "../node_modules/@lamport-robotics/vault/dist/index.js";
import type { PublicKey } from "@solana/web3.js";
import { LAMPORT_VAULT_MAINNET_PROGRAM_ID, PQ_REGISTRY_MAINNET_PROGRAM_ID, vaultMessage as vaultMessageFor } from "../node_modules/@lamport-robotics/vault/dist/index.js";

/** the program this build operates vaults of. a vault's key derivation binds it, so the same words give other keys here */
export const LAMPORT_VAULT_PROGRAM_ID = LAMPORT_VAULT_MAINNET_PROGRAM_ID;
export const PQ_REGISTRY_PROGRAM_ID = PQ_REGISTRY_MAINNET_PROGRAM_ID;

/** the message a vault key signs. it binds the program id: this build's, unless the caller names another */
export function vaultMessage(vault: PublicKey, generation: number, actionBytes: Uint8Array, programId: PublicKey = LAMPORT_VAULT_PROGRAM_ID): Uint8Array {
  return vaultMessageFor(vault, generation, actionBytes, programId);
}
