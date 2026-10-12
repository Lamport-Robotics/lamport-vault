/**
 * The vault's `Action` enum (docs/DESIGN.md, "Actions"), Borsh-encoded:
 *
 *   0 TransferSol   { to: Pubkey, lamports: u64, issued_slot: u64, expiry_slot: u64 }
 *   1 TransferToken { mint: Pubkey, to: Pubkey, amount: u64, issued_slot: u64, expiry_slot: u64 }
 *   2 Rotate        { new_lms_pubkey: [u8;56], issued_slot: u64, expiry_slot: u64 }
 *   3 Close         { to: Pubkey, issued_slot: u64, expiry_slot: u64 }
 *
 * The variant index is one byte, integers are little-endian, Pubkeys and the 56-byte key are raw.
 * Every variant ends in its validity window: the program refuses an action issued after the
 * current slot, expired, or whose window is longer than {@link MAX_VALIDITY_SLOTS}.
 */
import { PublicKey } from "@solana/web3.js";
import { ByteReader, ByteWriter } from "./borsh.ts";

/**
 * Longest validity window the programs accept, in slots: `expiry_slot - issued_slot` must not
 * exceed it (about one day at 400 ms). Mirrors `MAX_VALIDITY_SLOTS` in both programs.
 */
export const MAX_VALIDITY_SLOTS = 216_000n;

/** The slots an action (or a registry rotation) is valid in, inclusive at both ends. */
export interface ValidityWindow {
  /** Slot the action was signed at; the chain refuses it until then. */
  issuedSlot: bigint;
  /** Last slot it may execute at; at most `issuedSlot + MAX_VALIDITY_SLOTS`. */
  expirySlot: bigint;
}

/**
 * The window rule the programs enforce, for client-side checks: `issuedSlot <= currentSlot`
 * (when given), `expirySlot >= currentSlot` (when given), `issuedSlot <= expirySlot <= issuedSlot +
 * MAX_VALIDITY_SLOTS`. Throws a RangeError naming the failed rule.
 */
export function checkValidityWindow(w: ValidityWindow, currentSlot?: bigint | number): void {
  if (w.issuedSlot < 0n || w.expirySlot < 0n) throw new RangeError("slots must be non-negative");
  if (w.expirySlot < w.issuedSlot) throw new RangeError(`inverted validity window: expiry ${w.expirySlot} is before issued ${w.issuedSlot}`);
  if (w.expirySlot - w.issuedSlot > MAX_VALIDITY_SLOTS) {
    throw new RangeError(`validity window of ${w.expirySlot - w.issuedSlot} slots exceeds MAX_VALIDITY_SLOTS (${MAX_VALIDITY_SLOTS})`);
  }
  if (currentSlot !== undefined) {
    const now = BigInt(currentSlot);
    if (w.issuedSlot > now) throw new RangeError(`issued in the future: slot ${w.issuedSlot} is beyond the current slot ${now}`);
    if (w.expirySlot < now) throw new RangeError(`expired: slot ${w.expirySlot} is before the current slot ${now}`);
  }
}

export type Action =
  | ({ kind: "TransferSol"; to: PublicKey; lamports: bigint } & ValidityWindow)
  | ({ kind: "TransferToken"; mint: PublicKey; to: PublicKey; amount: bigint } & ValidityWindow)
  | ({ kind: "Rotate"; newLmsPubkey: Uint8Array } & ValidityWindow)
  | ({ kind: "Close"; to: PublicKey } & ValidityWindow);

export type ActionKind = Action["kind"];

export const ACTION_INDEX: Readonly<Record<ActionKind, number>> = {
  TransferSol: 0,
  TransferToken: 1,
  Rotate: 2,
  Close: 3,
};

/** The SigBuffer stores at most this many action bytes. */
export const MAX_ACTION_BYTES = 256;

export function encodeAction(a: Action): Uint8Array {
  const w = new ByteWriter().u8(ACTION_INDEX[a.kind]);
  switch (a.kind) {
    case "TransferSol":
      w.pubkey(a.to).u64(a.lamports);
      break;
    case "TransferToken":
      w.pubkey(a.mint).pubkey(a.to).u64(a.amount);
      break;
    case "Rotate":
      w.fixed(a.newLmsPubkey, 56);
      break;
    case "Close":
      w.pubkey(a.to);
      break;
  }
  w.u64(a.issuedSlot).u64(a.expirySlot);
  const bytes = w.bytes();
  if (bytes.length > MAX_ACTION_BYTES) throw new Error("action exceeds 256 bytes");
  return bytes;
}

export function decodeAction(bytes: Uint8Array): Action {
  const r = new ByteReader(bytes);
  const idx = r.u8();
  let a: Action;
  switch (idx) {
    case 0:
      a = { kind: "TransferSol", to: r.pubkey(), lamports: r.u64(), issuedSlot: r.u64(), expirySlot: r.u64() };
      break;
    case 1:
      a = { kind: "TransferToken", mint: r.pubkey(), to: r.pubkey(), amount: r.u64(), issuedSlot: r.u64(), expirySlot: r.u64() };
      break;
    case 2:
      a = { kind: "Rotate", newLmsPubkey: r.fixed(56), issuedSlot: r.u64(), expirySlot: r.u64() };
      break;
    case 3:
      a = { kind: "Close", to: r.pubkey(), issuedSlot: r.u64(), expirySlot: r.u64() };
      break;
    default:
      throw new Error(`unknown Action variant ${idx}`);
  }
  r.finish();
  return a;
}

/** Encoded sizes per variant, for reference and tests. */
export const ACTION_SIZES: Readonly<Record<ActionKind, number>> = {
  TransferSol: 1 + 32 + 8 + 8 + 8,
  TransferToken: 1 + 32 + 32 + 8 + 8 + 8,
  Rotate: 1 + 56 + 8 + 8,
  Close: 1 + 32 + 8 + 8,
};
