/**
 * The succession clock of the Heir-enabled vault: the program built from `programs/lamport-vault`
 * with the `succession` feature (docs/SUCCESSION.md). It is a separate program with its own id; the
 * vault program itself has none of this.
 *
 * If the owner of a vault signs nothing and checks in nowhere for longer than the window they
 * chose, anyone may open a waiting period (`start_succession`). Any signed action or check-in
 * cancels it. If none comes before it ends, anyone may release the vault to the plan's claim
 * address (`execute_succession`), by the same path a signed `Close` takes.
 *
 * This file mirrors `programs/lamport-vault/src/succession.rs`: the rules that read a
 * {@link SuccessionState}, the checks a plan must pass, and the four instructions. Times are unix
 * seconds as the cluster's clock gives them, as bigints.
 */
import { type AccountMeta, PublicKey, TransactionInstruction } from "@solana/web3.js";
import { type SuccessionState } from "./accounts.ts";
import { type Action, decodeAction, encodeAction, type ValidityWindow } from "./action.ts";
import { ByteReader, ByteWriter } from "./borsh.ts";
import { IX } from "./discriminator.ts";
import { TOKEN_PROGRAM_ID } from "./pda.ts";
import { LAMPORT_VAULT_HEIR_SHORT_CLOCKS_PROGRAM_ID } from "./programIds.ts";

/** How long a day lasts on a program's succession clock. */
export interface SuccessionClock {
  /** seconds in one day: 86 400, or 1 in a `short-clocks` test build */
  readonly daySecs: bigint;
}

/** The clock of the Heir-enabled vault. */
export const SUCCESSION_CLOCK: SuccessionClock = { daySecs: 86_400n };
/** The clock of the `short-clocks` test build, where a day lasts one second. Never for real funds. */
export const SHORT_SUCCESSION_CLOCK: SuccessionClock = { daySecs: 1n };

/** The clock a program id runs on: the short one for the `short-clocks` test build, else the real one. */
export function successionClockFor(programId: PublicKey): SuccessionClock {
  return programId.equals(LAMPORT_VAULT_HEIR_SHORT_CLOCKS_PROGRAM_ID) ? SHORT_SUCCESSION_CLOCK : SUCCESSION_CLOCK;
}

/** The program's duration constants, in seconds on `clock`. */
export interface SuccessionLimits {
  /** shortest inactivity window: 90 days */
  minWindowSecs: bigint;
  /** shortest waiting period: 30 days */
  minWaitSecs: bigint;
  /** longest window or waiting period: 100 years */
  maxDurationSecs: bigint;
  /** a check-in counts only up to this long after the last signed action: two years */
  checkinCapSecs: bigint;
  /** how far the trusted contact moves the deadline, once: 90 days */
  contactExtensionSecs: bigint;
}

export function successionLimits(clock: SuccessionClock = SUCCESSION_CLOCK): SuccessionLimits {
  const d = clock.daySecs;
  return { minWindowSecs: 90n * d, minWaitSecs: 30n * d, maxDurationSecs: 36_500n * d, checkinCapSecs: 730n * d, contactExtensionSecs: 90n * d };
}

const max = (a: bigint, b: bigint): bigint => (a > b ? a : b);
const min = (a: bigint, b: bigint): bigint => (a < b ? a : b);

/** Whether a plan is armed: the claim address is not the default address. */
export function isSuccessionArmed(s: Pick<SuccessionState, "claim">): boolean {
  return !s.claim.equals(PublicKey.default);
}

/**
 * The owner's last sign of life: the last signed action, or a later check-in, but a check-in
 * counts only up to the cap past the last signed action.
 */
export function successionActivity(s: SuccessionState, clock: SuccessionClock = SUCCESSION_CLOCK): bigint {
  return max(s.lastSignedTs, min(s.lastCheckinTs, s.lastSignedTs + successionLimits(clock).checkinCapSecs));
}

/** The moment after which a waiting period may be opened. */
export function successionDeadline(s: SuccessionState, clock: SuccessionClock = SUCCESSION_CLOCK): bigint {
  return max(successionActivity(s, clock) + s.windowSecs, s.extendedUntilTs);
}

/** The moment from which the open waiting period may be finished; undefined when none is open. */
export function successionReleaseAt(s: SuccessionState): bigint | undefined {
  return s.waitOpen ? s.waitStartedTs + s.waitSecs : undefined;
}

/** The last moment a check-in still counts: the cap past the last signed action. */
export function checkinCountsUntil(s: SuccessionState, clock: SuccessionClock = SUCCESSION_CLOCK): bigint {
  return s.lastSignedTs + successionLimits(clock).checkinCapSecs;
}

/**
 * Where a vault's succession stands at `now`:
 *
 * - `unarmed`: no plan;
 * - `quiet`: a plan, and the deadline has not passed;
 * - `overdue`: the deadline has passed and nobody has opened the waiting period yet;
 * - `waiting`: a waiting period is open and not over;
 * - `releasable`: the waiting period is over; anyone may release the vault.
 */
export type SuccessionPhase = "unarmed" | "quiet" | "overdue" | "waiting" | "releasable";

export interface SuccessionStatus {
  phase: SuccessionPhase;
  /** after this moment a waiting period may be opened (armed plans only) */
  deadline?: bigint;
  /** from this moment the open waiting period may be finished (waiting / releasable only) */
  releaseAt?: bigint;
  /** the last moment a check-in still counts (armed plans only) */
  checkinCountsUntil?: bigint;
  /**
   * The soonest the vault could be released if the owner does nothing more and others act the
   * moment the chain allows. For an armed plan this is never sooner than `window + wait` after the
   * last signed action.
   */
  earliestRelease?: bigint;
}

export function successionStatus(s: SuccessionState, now: bigint, clock: SuccessionClock = SUCCESSION_CLOCK): SuccessionStatus {
  if (!isSuccessionArmed(s)) return { phase: "unarmed" };
  const deadline = successionDeadline(s, clock);
  const until = checkinCountsUntil(s, clock);
  if (s.waitOpen) {
    const releaseAt = s.waitStartedTs + s.waitSecs;
    return { phase: now >= releaseAt ? "releasable" : "waiting", deadline, releaseAt, checkinCountsUntil: until, earliestRelease: max(releaseAt, now) };
  }
  // a waiting period opens strictly after the deadline, and lasts `waitSecs`
  const earliestStart = max(deadline + 1n, now);
  return { phase: now > deadline ? "overdue" : "quiet", deadline, checkinCountsUntil: until, earliestRelease: earliestStart + s.waitSecs };
}

/**
 * `SetSuccession`, variant 5 of the Heir-enabled program's `Action`, 129 bytes:
 *
 *   5 SetSuccession { claim: Pubkey, window_secs: u64, wait_secs: u64, checkin_key: Pubkey, contact_key: Pubkey, issued_slot: u64, expiry_slot: u64 }
 *
 * Arms, changes or clears the succession plan. The vault program itself has no such action, so
 * `decodeAction` and `encodeAction` in `action.ts` do not know it: use {@link encodeHeirAction}
 * and {@link decodeHeirAction} for the Heir-enabled program. `VaultSigner` signs it only for a
 * version-3 vault.
 */
export type SetSuccessionAction = { kind: "SetSuccession" } & SuccessionPlan & ValidityWindow;

/** Every action of the Heir-enabled program: the vault's five, and `SetSuccession`. */
export type HeirAction = Action | SetSuccessionAction;

/** Borsh variant index of `SetSuccession`. */
export const SET_SUCCESSION_VARIANT = 5;
/** Encoded size of `SetSuccession`: variant byte, the plan, the validity window. */
export const SET_SUCCESSION_ACTION_SIZE = 1 + 32 + 8 + 8 + 32 + 32 + 8 + 8;

/** Borsh encoding of any action of the Heir-enabled program. The vault's five encode exactly as `encodeAction` does. */
export function encodeHeirAction(a: HeirAction): Uint8Array {
  if (a.kind !== "SetSuccession") return encodeAction(a);
  return new ByteWriter()
    .u8(SET_SUCCESSION_VARIANT)
    .pubkey(a.claim)
    .u64(a.windowSecs)
    .u64(a.waitSecs)
    .pubkey(a.checkinKey)
    .pubkey(a.contactKey)
    .u64(a.issuedSlot)
    .u64(a.expirySlot)
    .bytes();
}

/** Decodes exactly one action of the Heir-enabled program; trailing bytes are an error. */
export function decodeHeirAction(bytes: Uint8Array): HeirAction {
  if (bytes[0] !== SET_SUCCESSION_VARIANT) return decodeAction(bytes);
  const r = new ByteReader(bytes);
  r.u8();
  const a: SetSuccessionAction = {
    kind: "SetSuccession",
    claim: r.pubkey(),
    windowSecs: r.u64(),
    waitSecs: r.u64(),
    checkinKey: r.pubkey(),
    contactKey: r.pubkey(),
    issuedSlot: r.u64(),
    expirySlot: r.u64(),
  };
  r.finish();
  return a;
}

/** A plan, as `SetSuccession` carries it. */
export interface SuccessionPlan {
  /** where the vault releases to; the default address clears the plan */
  claim: PublicKey;
  windowSecs: bigint;
  waitSecs: bigint;
  /** a key that may only check in; the default address for none */
  checkinKey: PublicKey;
  /** a trusted contact's key that may move the deadline once; the default address for none */
  contactKey: PublicKey;
}

/** The one encoding that clears a plan: every field zero. */
export const CLEAR_SUCCESSION_PLAN: SuccessionPlan = Object.freeze({
  claim: PublicKey.default,
  windowSecs: 0n,
  waitSecs: 0n,
  checkinKey: PublicKey.default,
  contactKey: PublicKey.default,
});

/**
 * The rules the program applies to a plan, for a client to check before a signature is spent on
 * it: the floors and the ceiling, the single encoding of a clear, and that the vault is not its
 * own claim address. Throws a RangeError naming the rule. (The program also refuses a claim
 * account that could never receive a release; that needs the account, see `VaultSigner`.)
 */
export function checkSuccessionPlan(plan: SuccessionPlan, vault: PublicKey, clock: SuccessionClock = SUCCESSION_CLOCK): void {
  const lim = successionLimits(clock);
  if (plan.claim.equals(PublicKey.default)) {
    if (plan.windowSecs !== 0n || plan.waitSecs !== 0n || !plan.checkinKey.equals(PublicKey.default) || !plan.contactKey.equals(PublicKey.default)) {
      throw new RangeError("clearing the plan takes no window, waiting period or keys (ClearCarriesPlan)");
    }
    return;
  }
  if (plan.claim.equals(vault)) throw new RangeError("the claim address is the vault itself (ClaimIsTheVault)");
  if (plan.windowSecs < lim.minWindowSecs || plan.windowSecs > lim.maxDurationSecs) {
    throw new RangeError(`the window must be between ${lim.minWindowSecs} and ${lim.maxDurationSecs} seconds, got ${plan.windowSecs} (WindowOutOfRange)`);
  }
  if (plan.waitSecs < lim.minWaitSecs || plan.waitSecs > lim.maxDurationSecs) {
    throw new RangeError(`the waiting period must be between ${lim.minWaitSecs} and ${lim.maxDurationSecs} seconds, got ${plan.waitSecs} (WaitOutOfRange)`);
  }
}

/**
 * Owners whose accounts the program refuses as a claim address, besides the two token programs:
 * sysvars and program loaders (`UNUSABLE_OWNERS` in `succession.rs`).
 */
export const UNUSABLE_CLAIM_OWNERS: readonly string[] = [
  "Sysvar1111111111111111111111111111111111111",
  "NativeLoader1111111111111111111111111111111",
  "BPFLoader1111111111111111111111111111111111",
  "BPFLoader2111111111111111111111111111111111",
  "BPFLoaderUpgradeab1e11111111111111111111111",
  "LoaderV411111111111111111111111111111111111",
];

/** `SuccessionError` codes of the Heir-enabled program, numbered from 6100. */
export const SUCCESSION_ERROR = {
  NotArmed: 6100,
  WrongCheckinKey: 6101,
  CheckinPastCap: 6102,
  WrongContactKey: 6103,
  ContactAlreadyUsed: 6104,
  WaitAlreadyOpen: 6105,
  BeforeDeadline: 6106,
  NoWaitOpen: 6107,
  WaitNotOver: 6108,
  WindowOutOfRange: 6109,
  WaitOutOfRange: 6110,
  ClearCarriesPlan: 6111,
  ClaimAccountMissing: 6112,
  ClaimIsTheVault: 6113,
  ClaimNotUsable: 6114,
  WrongClaim: 6115,
  Overflow: 6116,
} as const;

const w = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: false, isWritable: true });
const r = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: false, isWritable: false });
const signer = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: true, isWritable: false });

/**
 * `checkin`: the plan's check-in key signs. It counts as activity and cancels an open waiting
 * period, while it is within the cap; past the cap it fails with `CheckinPastCap` and a signed
 * action is due. The key signs and nothing more: any account may pay the fee.
 */
export function checkinInstruction(p: { programId: PublicKey; vault: PublicKey; checkinKey: PublicKey }): TransactionInstruction {
  return new TransactionInstruction({ programId: p.programId, keys: [w(p.vault), signer(p.checkinKey)], data: Buffer.from(IX.checkin) });
}

/** `contact_extend`: the plan's contact key signs, once per plan as last set. Any account may pay the fee. */
export function contactExtendInstruction(p: { programId: PublicKey; vault: PublicKey; contactKey: PublicKey }): TransactionInstruction {
  return new TransactionInstruction({ programId: p.programId, keys: [w(p.vault), signer(p.contactKey)], data: Buffer.from(IX.contactExtend) });
}

/** `start_succession`: anyone, once the deadline has passed and no waiting period is open. */
export function startSuccessionInstruction(p: { programId: PublicKey; vault: PublicKey }): TransactionInstruction {
  return new TransactionInstruction({ programId: p.programId, keys: [w(p.vault)], data: Buffer.from(IX.startSuccession) });
}

/**
 * `execute_succession`: anyone, once the waiting period is over. Releases the vault to `claim`,
 * which must be the plan's claim address. `closeTokenAccounts` are empty token accounts the vault
 * owns, closed to the claim address in the same instruction; accounts that hold tokens are swept
 * afterwards with `sweepClosedInstruction`, as after a `Close`.
 */
export function executeSuccessionInstruction(p: {
  programId: PublicKey;
  vault: PublicKey;
  claim: PublicKey;
  closeTokenAccounts?: { account: PublicKey; tokenProgram?: PublicKey }[];
}): TransactionInstruction {
  const pairs = (p.closeTokenAccounts ?? []).flatMap((t) => [w(t.account), r(t.tokenProgram ?? TOKEN_PROGRAM_ID)]);
  return new TransactionInstruction({ programId: p.programId, keys: [w(p.vault), w(p.claim), ...pairs], data: Buffer.from(IX.executeSuccession) });
}
