import { toHex } from "@lamport-robotics/lms";
import { describe, expect, it } from "vitest";
import { ACTION_SIZES, type Action, decodeAction, encodeAction, MAX_ACTION_BYTES } from "../src/action.ts";
import { KAT_H5_PUBKEY, PK_11, PK_22 } from "./fixtures.ts";

const hex11 = "11".repeat(32);
const hex22 = "22".repeat(32);
// u64 little-endian
const LAMPORTS = 1_500_000_000n; // 0x59682F00
const LAMPORTS_LE = "002f6859" + "00000000";
const AMOUNT = 123_456_789_012n; // 0x1CBE991A14
const AMOUNT_LE = "141a99be1c000000";
const EXPIRY = 0x0000_0000_1234_5678n;
const EXPIRY_LE = "78563412" + "00000000";

describe("Action Borsh encoding", () => {
  it("TransferSol is 00 || to || lamports_le || expiry_le", () => {
    const a: Action = { kind: "TransferSol", to: PK_11, lamports: LAMPORTS, expirySlot: EXPIRY };
    const bytes = encodeAction(a);
    expect(bytes.length).toBe(ACTION_SIZES.TransferSol);
    expect(toHex(bytes)).toBe("00" + hex11 + LAMPORTS_LE + EXPIRY_LE);
  });

  it("TransferToken is 01 || mint || to || amount_le || expiry_le", () => {
    const a: Action = { kind: "TransferToken", mint: PK_22, to: PK_11, amount: AMOUNT, expirySlot: EXPIRY };
    const bytes = encodeAction(a);
    expect(bytes.length).toBe(ACTION_SIZES.TransferToken);
    expect(toHex(bytes)).toBe("01" + hex22 + hex11 + AMOUNT_LE + EXPIRY_LE);
  });

  it("Rotate is 02 || new_lms_pubkey[56] || expiry_le", () => {
    const a: Action = { kind: "Rotate", newLmsPubkey: KAT_H5_PUBKEY, expirySlot: EXPIRY };
    const bytes = encodeAction(a);
    expect(bytes.length).toBe(ACTION_SIZES.Rotate);
    expect(toHex(bytes)).toBe("02" + toHex(KAT_H5_PUBKEY) + EXPIRY_LE);
  });

  it("Close is 03 || to || expiry_le", () => {
    const a: Action = { kind: "Close", to: PK_11, expirySlot: EXPIRY };
    const bytes = encodeAction(a);
    expect(bytes.length).toBe(ACTION_SIZES.Close);
    expect(toHex(bytes)).toBe("03" + hex11 + EXPIRY_LE);
  });

  it("encodes u64 maxima and round-trips every variant", () => {
    const max = 0xffffffffffffffffn;
    const actions: Action[] = [
      { kind: "TransferSol", to: PK_11, lamports: max, expirySlot: 0n },
      { kind: "TransferToken", mint: PK_22, to: PK_11, amount: 1n, expirySlot: max },
      { kind: "Rotate", newLmsPubkey: KAT_H5_PUBKEY, expirySlot: 7n },
      { kind: "Close", to: PK_22, expirySlot: 9n },
    ];
    for (const a of actions) {
      const back = decodeAction(encodeAction(a));
      expect(back.kind).toBe(a.kind);
      expect(JSON.stringify(back, bigintAware)).toBe(JSON.stringify(a, bigintAware));
    }
    expect(toHex(encodeAction(actions[0]!).subarray(33, 41))).toBe("ff".repeat(8));
  });

  it("every variant fits the 256-byte SigBuffer limit", () => {
    for (const n of Object.values(ACTION_SIZES)) expect(n).toBeLessThanOrEqual(MAX_ACTION_BYTES);
  });

  it("rejects unknown variants, trailing bytes and short input", () => {
    expect(() => decodeAction(new Uint8Array([4, ...new Uint8Array(40)]))).toThrow(/unknown/);
    expect(() => decodeAction(new Uint8Array([...encodeAction({ kind: "Close", to: PK_11, expirySlot: 1n }), 0]))).toThrow(/trailing/);
    expect(() => decodeAction(new Uint8Array([3, 1, 2]))).toThrow();
    expect(() => encodeAction({ kind: "Rotate", newLmsPubkey: new Uint8Array(55), expirySlot: 1n })).toThrow();
    expect(() => encodeAction({ kind: "TransferSol", to: PK_11, lamports: -1n, expirySlot: 1n })).toThrow(RangeError);
  });
});

function bigintAware(_k: string, v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (v instanceof Uint8Array) return toHex(v);
  return v;
}
