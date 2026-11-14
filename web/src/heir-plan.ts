/**
 * `SetSuccession`, the one action a Heir-enabled vault has that the vault does not
 * (docs/SUCCESSION.md): how a request for it is checked, shown and turned into the bytes that get
 * signed. The cold signer and the page share this file, so the owner reads the same sentences on
 * the offline machine as on the online one.
 *
 * Only a Heir build reaches it (`__HEIR__`). Nothing here runs when the module loads: the vault's
 * own page and signer import it, never call it, and their bundles come out without it.
 */
import { PublicKey } from "@solana/web3.js";
import { LAMPORT_VAULT_PROGRAM_ID, UNUSABLE_CLAIM_OWNERS, checkSuccessionPlan, successionClockFor, successionLimits, type Action, type SetSuccessionAction, type VaultAccount } from "@lamport-robotics/vault";
import { el, isPubkey, type SignRequest } from "./common.ts";
import type { Holding } from "./tokens.ts";
import type { Wallet } from "./wallet.ts";
import { explainClaim } from "./heir-ext.ts";

export type PlanRequest = Extract<SignRequest["action"], { kind: "SetSuccession" }>;

/** what the Inheritance tab is given: the open vault as the page last read it */
export interface HeirCtx { vault: VaultAccount; address: PublicKey; lamports: number; tokens: Holding[]; wallet: Wallet | null; reload: () => Promise<void> }

/** the default address, as text: "no key" for the two optional keys, and with zero durations, "no plan" */
export const NO_ADDRESS = "11111111111111111111111111111111";
/** the one request that removes a plan */
export function clearRequest(): PlanRequest { return { kind: "SetSuccession", claim: NO_ADDRESS, windowSecs: "0", waitSecs: "0", checkinKey: NO_ADDRESS, contactKey: NO_ADDRESS }; }
export function isClear(a: PlanRequest): boolean { return a.claim === NO_ADDRESS; }

/** the clock of the program this build talks to: a day is 86 400 seconds, or one in the `short-clocks` test build */
export function planClock() { return successionClockFor(LAMPORT_VAULT_PROGRAM_ID); }

function isU64(x: unknown): x is string { return typeof x === "string" && /^\d{1,20}$/.test(x) && BigInt(x) <= 0xffffffffffffffffn; }
function isPk(x: unknown): x is string { return typeof x === "string" && x === x.trim() && isPubkey(x); }

/** a duration in the program's days, the way both screens say it */
export function days(secs: string | bigint): string {
  const day = planClock().daySecs, n = BigInt(secs);
  if (n % day !== 0n) return `${n} seconds`;
  return `${n / day} day${n / day === 1n ? "" : "s"}`;
}

/** programs and sysvars: an address the vault program refuses, or that could never pass on what it received */
function unusableClaim(claim: string): boolean {
  return claim === LAMPORT_VAULT_PROGRAM_ID.toBase58() || claim === "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" || claim === "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" || UNUSABLE_CLAIM_OWNERS.includes(claim);
}

/**
 * what is wrong with a `SetSuccession` request, or null. everything the program would refuse that
 * can be seen without the chain, so that a plan the chain refuses does not cost a one-time key.
 */
export function planProblem(a: PlanRequest, vault: string): string | null {
  if (!isPk(a.claim) || !isPk(a.checkinKey) || !isPk(a.contactKey)) return "the claim address, check-in key or contact key is not a valid address";
  if (!isU64(a.windowSecs) || !isU64(a.waitSecs)) return "the window and the waiting period must be whole numbers of seconds";
  try { checkSuccessionPlan({ claim: new PublicKey(a.claim), windowSecs: BigInt(a.windowSecs), waitSecs: BigInt(a.waitSecs), checkinKey: new PublicKey(a.checkinKey), contactKey: new PublicKey(a.contactKey) }, new PublicKey(vault), planClock()); }
  catch (e) { return String((e as Error).message ?? e); }
  if (isClear(a)) return a.terms === undefined ? null : "a request that removes the plan carries no terms";
  if (unusableClaim(a.claim)) return `the claim address ${a.claim} is a program or a sysvar: nothing released there could ever be moved on`;
  return explainClaim(a, vault)?.problem ?? null;
}

/** the plan in words: label and text, the same on the page and in the signer */
export function planLines(a: PlanRequest, vault: string): [string, string][] {
  if (isClear(a)) return [["action", "remove the inheritance plan from this vault. Nothing is released to anyone until a new plan is signed"]];
  const lim = successionLimits(planClock());
  const total = BigInt(a.windowSecs) + BigInt(a.waitSecs);
  const who = explainClaim(a, vault)?.rows ?? [["who that is", "this signer only sees an address. Compare it, character by character, with the address you mean; whoever controls it receives the vault"]];
  const lines: [string, string][] = [
    ["action", "set the inheritance plan of this vault. It replaces any plan the vault has now"],
    ["releases to", a.claim],
    ...(who as [string, string][]),
    ["after", `${days(a.windowSecs)} with no signature from these words and no check-in. Then anyone may open a public waiting period`],
    ["waiting period", `${days(a.waitSecs)}. When it ends, anyone may send everything in the vault to the address above. Until then any signature from these words, or a check-in, cancels it`],
    ["soonest release", `${days(total)} after your last signature`],
    ["check-in key", a.checkinKey === NO_ADDRESS ? "none: only a signature from these words resets the clock" : `${a.checkinKey} · may reset the clock, for at most ${days(lim.checkinCapSecs)} after your last signature. It can move nothing`],
    ["trusted contact", a.contactKey === NO_ADDRESS ? "none" : `${a.contactKey} · may push the deadline back by ${days(lim.contactExtensionSecs)}, once. It can move nothing`],
  ];
  if (planClock().daySecs !== 86_400n) lines.push(["clock", `TEST BUILD: one day lasts ${planClock().daySecs} second${planClock().daySecs === 1n ? "" : "s"}`]);
  return lines;
}

/** `planLines` as rows of a definition list */
export function planRows(a: PlanRequest, vault: string): HTMLElement[] {
  return planLines(a, vault).flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]);
}

/**
 * in the signer: the plan, where the request view has its action row. the view is built by code that knows the
 * vault's five actions; this throws rather than leave a line that describes another action.
 */
export function showPlan(view: HTMLElement, a: PlanRequest, vault: string): void {
  const dl = view.querySelector("dl");
  const dt = dl?.children[2], dd = dl?.children[3];
  if (!dl || !dt || !dd || dt.tagName !== "DT" || dd.tagName !== "DD" || dt.textContent !== "action") throw new Error("refusing the request: this signer could not show the plan it would sign");
  dd.remove();
  dt.replaceWith(...planRows(a, vault));
}

/** one sentence for a confirmation */
export function describePlan(a: PlanRequest): string {
  if (isClear(a)) return "Remove the inheritance plan from this vault";
  return `Set the inheritance plan: release to ${a.claim} after ${days(a.windowSecs)} of silence, then a waiting period of ${days(a.waitSecs)}`;
}

/**
 * the action as it is signed and submitted. `Action` is the vault's five; a Heir build resolves
 * the SDK's encoder to the one that knows the sixth (src/heir-sdk.ts), so the cast is true there.
 */
export function planAction(a: PlanRequest, issuedSlot: bigint, expirySlot: bigint): Action {
  const action: SetSuccessionAction = { kind: "SetSuccession", claim: new PublicKey(a.claim), windowSecs: BigInt(a.windowSecs), waitSecs: BigInt(a.waitSecs), checkinKey: new PublicKey(a.checkinKey), contactKey: new PublicKey(a.contactKey), issuedSlot, expirySlot };
  return action as unknown as Action;
}
