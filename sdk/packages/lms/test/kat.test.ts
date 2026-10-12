/**
 * Known-answer tests against kat/lms_sha256_w4.json, produced by an independent RFC 8554
 * implementation (hsslms). Every public key must be reproduced from SEED/I, every signature must
 * verify, and every signature must be reproduced byte-for-byte when signed with the same C.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { fromHex, toHex } from "../src/bytes.ts";
import { LmsPrivateKey, lmsVerify, parseLmsSignature, serializeLmsPublicKey, parseLmsPublicKey } from "../src/lms.ts";

interface KatSignature {
  q: number;
  message_hex: string;
  signature_hex: string;
}
interface KatVector {
  name: string;
  lms_type: number;
  lmots_type: number;
  height: number;
  seed_hex: string;
  I_hex: string;
  public_key_hex: string;
  signatures: KatSignature[];
}

const katPath = fileURLToPath(new URL("../../../../kat/lms_sha256_w4.json", import.meta.url));
const kat = JSON.parse(readFileSync(katPath, "utf8")) as { source: string; vectors: KatVector[] };

function flipBit(bytes: Uint8Array, bitIndex: number): Uint8Array {
  const out = bytes.slice();
  out[bitIndex >> 3]! ^= 1 << (bitIndex & 7);
  return out;
}

describe.each(kat.vectors)("$name", (vec) => {
  const key = LmsPrivateKey.generate({
    lmsType: vec.lms_type,
    lmotsType: vec.lmots_type,
    seed: fromHex(vec.seed_hex),
    I: fromHex(vec.I_hex),
  });
  const pk = fromHex(vec.public_key_hex);

  it("reproduces the public key from SEED and I", () => {
    expect(toHex(key.publicKey)).toBe(vec.public_key_hex);
    expect(key.lms.h).toBe(vec.height);
  });

  it.each(vec.signatures)("q=$q: signature verifies", (s) => {
    expect(lmsVerify(pk, fromHex(s.message_hex), fromHex(s.signature_hex))).toBe(true);
  });

  it.each(vec.signatures)("q=$q: signing with the vector's C reproduces the exact signature", (s) => {
    const sig = fromHex(s.signature_hex);
    const parsed = parseLmsSignature(sig);
    expect(parsed.q).toBe(s.q);
    const C = parsed.lmotsSignature.subarray(4, 36);
    const mine = key.sign(s.q, fromHex(s.message_hex), { C });
    expect(toHex(mine)).toBe(s.signature_hex);
  });

  it.each(vec.signatures)("q=$q: a flipped bit anywhere in the signature fails", (s) => {
    const sig = fromHex(s.signature_hex);
    const msg = fromHex(s.message_hex);
    const positions = [
      0, // q (only bits that keep q < 2^h matter; bit 0 of byte 3 does)
      31, // q low bit
      4 * 8 + 7, // lmots typecode
      8 * 8, // C
      (8 + 32) * 8 + 5, // y[0]
      (8 + 32 + 66 * 32) * 8 + 200, // y[66]
      (4 + 2180) * 8 + 31, // lms typecode
      (4 + 2180 + 4) * 8 + 3, // path[0]
      sig.length * 8 - 1, // last path byte
    ];
    for (const bit of positions) {
      expect(lmsVerify(pk, msg, flipBit(sig, bit)), `bit ${bit}`).toBe(false);
    }
  });

  it.each(vec.signatures)("q=$q: a flipped bit in the message fails", (s) => {
    const msg = fromHex(s.message_hex);
    const sig = fromHex(s.signature_hex);
    if (msg.length === 0) {
      expect(lmsVerify(pk, new Uint8Array([0]), sig)).toBe(false);
    } else {
      expect(lmsVerify(pk, flipBit(msg, 3), sig)).toBe(false);
    }
  });

  it.each(vec.signatures)("q=$q: the wrong q with an otherwise valid OTS fails", (s) => {
    const sig = fromHex(s.signature_hex);
    const msg = fromHex(s.message_hex);
    const otherQ = (s.q + 1) % 2 ** vec.height;
    const wrong = sig.slice();
    wrong[0] = (otherQ >>> 24) & 0xff;
    wrong[1] = (otherQ >>> 16) & 0xff;
    wrong[2] = (otherQ >>> 8) & 0xff;
    wrong[3] = otherQ & 0xff;
    expect(lmsVerify(pk, msg, wrong)).toBe(false);
  });

  it.each(vec.signatures)("q=$q: a public key with a different I fails", (s) => {
    const parts = parseLmsPublicKey(pk);
    const I = parts.I.slice();
    I[0]! ^= 0x01;
    const wrongPk = serializeLmsPublicKey({ ...parts, I });
    expect(lmsVerify(wrongPk, fromHex(s.message_hex), fromHex(s.signature_hex))).toBe(false);
  });

  it("rejects a signature whose q is out of range for the tree", () => {
    const s = vec.signatures[0]!;
    const sig = fromHex(s.signature_hex);
    const q = 2 ** vec.height;
    sig[0] = (q >>> 24) & 0xff;
    sig[1] = (q >>> 16) & 0xff;
    sig[2] = (q >>> 8) & 0xff;
    sig[3] = q & 0xff;
    expect(lmsVerify(pk, fromHex(s.message_hex), sig)).toBe(false);
  });

  it("rejects truncated and extended signatures", () => {
    const s = vec.signatures[0]!;
    const sig = fromHex(s.signature_hex);
    const msg = fromHex(s.message_hex);
    expect(lmsVerify(pk, msg, sig.subarray(0, sig.length - 1))).toBe(false);
    expect(lmsVerify(pk, msg, new Uint8Array([...sig, 0]))).toBe(false);
    expect(lmsVerify(pk, msg, new Uint8Array(4))).toBe(false);
  });
});

describe("KAT across vectors", () => {
  it("a signature from one key does not verify under the other", () => {
    const [a, b] = kat.vectors;
    if (!a || !b) return;
    expect(lmsVerify(fromHex(b.public_key_hex), fromHex(a.signatures[0]!.message_hex), fromHex(a.signatures[0]!.signature_hex))).toBe(false);
  });
});
