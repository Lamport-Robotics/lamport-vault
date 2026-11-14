/**
 * What a Heir build knows about the address a vault releases to, beyond its being an address.
 *
 * This file knows nothing: to the vault program a claim address is 32 bytes. Lamport Heir builds
 * the page and the signer it ships from this same source and puts its own module in this one's
 * place (https://github.com/Lamport-Robotics/lamport-heir), which knows the claim program: it can
 * derive a plan's address again from the heirs it names, offline, and so tell the owner who
 * inherits. The three functions below are the whole seam.
 *
 * Nothing here runs when the module loads. The vault's own page and signer import it and never
 * reach it, and their bundles must come out without it.
 */
import type { HeirCtx, PlanRequest } from "./heir-plan.ts";

export interface ClaimExplained {
  /** set when the request's `terms` do not produce its claim address, or cannot be read: the signer refuses */
  problem?: string;
  /** label and text, shown under the claim address */
  rows: [string, string][];
}

/** who is behind a claim address, worked out from the request alone; null when this build cannot tell */
export function explainClaim(_a: PlanRequest, _vault: string): ClaimExplained | null {
  return null;
}

/** a way to choose the claim address other than typing it: `set` receives the address and what it is made of */
export function claimComposer(_ctx: HeirCtx, _set: (claim: string, terms: unknown) => void): HTMLElement | null {
  return null;
}

/** more for the Inheritance tab, under the plan's status */
export function extraPanels(_ctx: HeirCtx): HTMLElement | null {
  return null;
}
