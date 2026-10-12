/**
 * The vault's `Action` enum (docs/DESIGN.md, "Actions"), Borsh-encoded:
 *
 *   0 TransferSol   { to: Pubkey, lamports: u64, expiry_slot: u64 }
 *   1 TransferToken { mint: Pubkey, to: Pubkey, amount: u64, expiry_slot: u64 }
 *   2 Rotate        { new_lms_pubkey: [u8;56], expiry_slot: u64 }
 *   3 Close         { to: Pubkey, expiry_slot: u64 }
 *
 * The variant index is one byte, integers are little-endian, Pubkeys and the 56-byte key are raw.
 */
import { PublicKey } from "@solana/web3.js";
import { ByteReader, ByteWriter } from "./borsh.ts";

export type Action =
  | { kind: "TransferSol"; to: PublicKey; lamports: bigint; expirySlot: bigint }
  | { kind: "TransferToken"; mint: PublicKey; to: PublicKey; amount: bigint; expirySlot: bigint }
  | { kind: "Rotate"; newLmsPubkey: Uint8Array; expirySlot: bigint }
  | { kind: "Close"; to: PublicKey; expirySlot: bigint };

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
      w.pubkey(a.to).u64(a.lamports).u64(a.expirySlot);
      break;
    case "TransferToken":
      w.pubkey(a.mint).pubkey(a.to).u64(a.amount).u64(a.expirySlot);
      break;
    case "Rotate":
      w.fixed(a.newLmsPubkey, 56).u64(a.expirySlot);
      break;
    case "Close":
      w.pubkey(a.to).u64(a.expirySlot);
      break;
  }
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
      a = { kind: "TransferSol", to: r.pubkey(), lamports: r.u64(), expirySlot: r.u64() };
      break;
    case 1:
      a = { kind: "TransferToken", mint: r.pubkey(), to: r.pubkey(), amount: r.u64(), expirySlot: r.u64() };
      break;
    case 2:
      a = { kind: "Rotate", newLmsPubkey: r.fixed(56), expirySlot: r.u64() };
      break;
    case 3:
      a = { kind: "Close", to: r.pubkey(), expirySlot: r.u64() };
      break;
    default:
      throw new Error(`unknown Action variant ${idx}`);
  }
  r.finish();
  return a;
}

/** Encoded sizes per variant, for reference and tests. */
export const ACTION_SIZES: Readonly<Record<ActionKind, number>> = {
  TransferSol: 1 + 32 + 8 + 8,
  TransferToken: 1 + 32 + 32 + 8 + 8,
  Rotate: 1 + 56 + 8,
  Close: 1 + 32 + 8,
};
