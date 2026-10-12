import { toHex } from "@lamport-robotics/lms";
import { describe, expect, it } from "vitest";
import { ACTION_SIZES, type Action, checkValidityWindow, decodeAction, encodeAction, MAX_ACTION_BYTES, MAX_VALIDITY_SLOTS } from "../src/action.ts";
import { KAT_H5_PUBKEY, PK_11, PK_22 } from "./fixtures.ts";

const hex11 = "11".repeat(32);
const hex22 = "22".repeat(32);
// u64 little-endian
const LAMPORTS = 1_500_000_000n; // 0x59682F00
const LAMPORTS_LE = "002f6859" + "00000000";
const AMOUNT = 123_456_789_012n; // 0x1CBE991A14
const AMOUNT_LE = "141a99be1c000000";
const ISSUED = 0x0000_0000_1234_0000n;
const ISSUED_LE = "00003412" + "00000000";
const EXPIRY = 0x0000_0000_1234_5678n;
const EXPIRY_LE = "78563412" + "00000000";
const WINDOW = { issuedSlot: ISSUED, expirySlot: EXPIRY };
const WINDOW_LE = ISSUED_LE + EXPIRY_LE;

describe("Action Borsh encoding", () => {
  it("TransferSol is 00 || to || lamports_le || issued_le || expiry_le", () => {
    const a: Action = { kind: "TransferSol", to: PK_11, lamports: LAMPORTS, ...WINDOW };
    const bytes = encodeAction(a);
    expect(bytes.length).toBe(ACTION_SIZES.TransferSol);
    expect(ACTION_SIZES.TransferSol).toBe(57);
    expect(toHex(bytes)).toBe("00" + hex11 + LAMPORTS_LE + WINDOW_LE);
  });

  it("TransferToken is 01 || mint || to || amount_le || issued_le || expiry_le", () => {
    const a: Action = { kind: "TransferToken", mint: PK_22, to: PK_11, amount: AMOUNT, ...WINDOW };
    const bytes = encodeAction(a);
    expect(bytes.length).toBe(ACTION_SIZES.TransferToken);
    expect(ACTION_SIZES.TransferToken).toBe(89);
    expect(toHex(bytes)).toBe("01" + hex22 + hex11 + AMOUNT_LE + WINDOW_LE);
  });

  it("Rotate is 02 || new_lms_pubkey[56] || issued_le || expiry_le", () => {
    const a: Action = { kind: "Rotate", newLmsPubkey: KAT_H5_PUBKEY, ...WINDOW };
    const bytes = encodeAction(a);
    expect(bytes.length).toBe(ACTION_SIZES.Rotate);
    expect(ACTION_SIZES.Rotate).toBe(73);
    expect(toHex(bytes)).toBe("02" + toHex(KAT_H5_PUBKEY) + WINDOW_LE);
  });

  it("Close is 03 || to || issued_le || expiry_le", () => {
    const a: Action = { kind: "Close", to: PK_11, ...WINDOW };
    const bytes = encodeAction(a);
    expect(bytes.length).toBe(ACTION_SIZES.Close);
    expect(ACTION_SIZES.Close).toBe(49);
    expect(toHex(bytes)).toBe("03" + hex11 + WINDOW_LE);
  });

  it("the window is the last 16 bytes of every variant, issued before expiry", () => {
    const actions: Action[] = [
      { kind: "TransferSol", to: PK_11, lamports: 1n, ...WINDOW },
      { kind: "TransferToken", mint: PK_22, to: PK_11, amount: 1n, ...WINDOW },
      { kind: "Rotate", newLmsPubkey: KAT_H5_PUBKEY, ...WINDOW },
      { kind: "Close", to: PK_22, ...WINDOW },
    ];
    for (const a of actions) {
      const bytes = encodeAction(a);
      expect(toHex(bytes.subarray(bytes.length - 16))).toBe(WINDOW_LE);
    }
  });

  it("encodes u64 maxima and round-trips every variant", () => {
    const max = 0xffffffffffffffffn;
    const actions: Action[] = [
      { kind: "TransferSol", to: PK_11, lamports: max, issuedSlot: 0n, expirySlot: 0n },
      { kind: "TransferToken", mint: PK_22, to: PK_11, amount: 1n, issuedSlot: max, expirySlot: max },
      { kind: "Rotate", newLmsPubkey: KAT_H5_PUBKEY, issuedSlot: 6n, expirySlot: 7n },
      { kind: "Close", to: PK_22, issuedSlot: 8n, expirySlot: 9n },
    ];
    for (const a of actions) {
      const back = decodeAction(encodeAction(a));
      expect(back.kind).toBe(a.kind);
      expect(JSON.stringify(back, bigintAware)).toBe(JSON.stringify(a, bigintAware));
    }
    expect(toHex(encodeAction(actions[0]!).subarray(33, 41))).toBe("ff".repeat(8));
    // The codec does not judge the window (the chain and checkValidityWindow do).
    expect(decodeAction(encodeAction(actions[1]!)).expirySlot).toBe(max);
  });

  it("every variant fits the 256-byte SigBuffer limit", () => {
    for (const n of Object.values(ACTION_SIZES)) expect(n).toBeLessThanOrEqual(MAX_ACTION_BYTES);
  });

  it("rejects unknown variants, trailing bytes and short input", () => {
    expect(() => decodeAction(new Uint8Array([4, ...new Uint8Array(48)]))).toThrow(/unknown/);
    expect(() => decodeAction(new Uint8Array([...encodeAction({ kind: "Close", to: PK_11, issuedSlot: 0n, expirySlot: 1n }), 0]))).toThrow(/trailing/);
    expect(() => decodeAction(new Uint8Array([3, 1, 2]))).toThrow();
    // the old 41-byte Close (no issued_slot) is short by 8 bytes now
    expect(() => decodeAction(new Uint8Array([3, ...new Uint8Array(32).fill(0x11), ...new Uint8Array(8)]))).toThrow();
    expect(() => encodeAction({ kind: "Rotate", newLmsPubkey: new Uint8Array(55), issuedSlot: 0n, expirySlot: 1n })).toThrow();
    expect(() => encodeAction({ kind: "TransferSol", to: PK_11, lamports: -1n, issuedSlot: 0n, expirySlot: 1n })).toThrow(RangeError);
  });
});

describe("validity window", () => {
  it("MAX_VALIDITY_SLOTS mirrors the programs' constant (about a day)", () => {
    expect(MAX_VALIDITY_SLOTS).toBe(216_000n);
  });

  it("accepts windows up to one day long and rejects inverted or longer ones", () => {
    expect(() => checkValidityWindow({ issuedSlot: 5n, expirySlot: 5n })).not.toThrow();
    expect(() => checkValidityWindow({ issuedSlot: 5n, expirySlot: 5n + MAX_VALIDITY_SLOTS })).not.toThrow();
    expect(() => checkValidityWindow({ issuedSlot: 5n, expirySlot: 6n + MAX_VALIDITY_SLOTS })).toThrow(/MAX_VALIDITY_SLOTS/);
    expect(() => checkValidityWindow({ issuedSlot: 5n, expirySlot: 4n })).toThrow(/inverted/);
    expect(() => checkValidityWindow({ issuedSlot: -1n, expirySlot: 4n })).toThrow(/non-negative/);
    // a far-future expiry on an old signature is unrepresentable
    expect(() => checkValidityWindow({ issuedSlot: 0n, expirySlot: 0xffffffffffffffffn })).toThrow(/MAX_VALIDITY_SLOTS/);
  });

  it("checks the clock when given one", () => {
    const w = { issuedSlot: 100n, expirySlot: 200n };
    expect(() => checkValidityWindow(w, 100)).not.toThrow();
    expect(() => checkValidityWindow(w, 200n)).not.toThrow();
    expect(() => checkValidityWindow(w, 99)).toThrow(/future/);
    expect(() => checkValidityWindow(w, 201)).toThrow(/expired/);
  });
});

function bigintAware(_k: string, v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (v instanceof Uint8Array) return toHex(v);
  return v;
}
