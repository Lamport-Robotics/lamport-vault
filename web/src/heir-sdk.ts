/**
 * The vault SDK as a Heir build sees it. A Heir-enabled vault is the same source built as another
 * program (docs/SUCCESSION.md), so the page and the signer are the same source too, with three
 * names meaning something else:
 *
 *   LAMPORT_VAULT_PROGRAM_ID   the Heir-enabled program's id
 *   vaultMessage               binds that id when the caller names none (a signature made for the
 *                              vault's own id is refused by the Heir-enabled program, and should be)
 *   encodeAction               the encoder that also knows `SetSuccession`
 *
 * The Heir builds resolve `@lamport-robotics/vault` to this file (vite.heir.config.ts); the
 * vault's own builds never see it. Everything else is the SDK, untouched.
 */
export * from "../node_modules/@lamport-robotics/vault/dist/index.js";
import type { PublicKey } from "@solana/web3.js";
import { LAMPORT_VAULT_HEIR_PROGRAM_ID, LAMPORT_VAULT_HEIR_SHORT_CLOCKS_PROGRAM_ID, encodeHeirAction, vaultMessage as vaultMessageFor } from "../node_modules/@lamport-robotics/vault/dist/index.js";

declare const __HEIR_SHORT_CLOCKS__: boolean;

/** the program this build operates vaults of. a vault's key derivation binds it, so the same words give other keys here */
export const LAMPORT_VAULT_PROGRAM_ID = __HEIR_SHORT_CLOCKS__ ? LAMPORT_VAULT_HEIR_SHORT_CLOCKS_PROGRAM_ID : LAMPORT_VAULT_HEIR_PROGRAM_ID;

/** the message a vault key signs. it binds the program id: this build's, unless the caller names another */
export function vaultMessage(vault: PublicKey, generation: number, actionBytes: Uint8Array, programId: PublicKey = LAMPORT_VAULT_PROGRAM_ID): Uint8Array {
  return vaultMessageFor(vault, generation, actionBytes, programId);
}

/** the vault's five actions encode exactly as before; the sixth is `SetSuccession` */
export const encodeAction = encodeHeirAction;
