/**
 * RFC 9858 SHA-256/192 known-answer tests against kat/rfc9858_sha256_192.json (Appendix A.1 and
 * A.4, with the single-level HSS wrapper removed). The same file is checked by the Rust crate.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { fromHex, toHex } from "../src/bytes.ts";
import { LmsPrivateKey, lmsVerify, parseLmsPublicKey, parseLmsSignature } from "../src/lms.ts";
import {
  LMOTS_SHA256_N24_W4,
  LMOTS_SHA256_N24_W8,
  LMOTS_SHA256_N32_W4,
  LMS_SHA256_M24_H10,
  LMS_SHA256_M24_H5,
  LMS_SHA256_M32_H5,
  lmsPublicKeyLength,
  lmsSignatureLength,
} from "../src/params.ts";

interface Vector {
  name: string;
  lms_type: number;
  lmots_type: number;
  seed_hex: string;
  I_hex: string;
  public_key_hex: string;
  q: number;
  message_hex: string;
  signature_hex: string;
}

const path = fileURLToPath(new URL("../../../../kat/rfc9858_sha256_192.json", import.meta.url));
const vectors = (JSON.parse(readFileSync(path, "utf8")) as { vectors: Vector[] }).vectors;

describe("RFC 9858 SHA-256/192", () => {
  it("has the W8/H5 and W4/H20 cases", () => {
    expect(vectors.map((v) => [v.lms_type, v.lmots_type])).toEqual([
      [10, 8],
      [13, 7],
    ]);
  });

  for (const v of vectors) {
    it(`${v.name}: verifies, and rejects a changed message`, () => {
      const pk = fromHex(v.public_key_hex);
      const msg = fromHex(v.message_hex);
      const sig = fromHex(v.signature_hex);
      expect(pk.length).toBe(48);
      expect(parseLmsSignature(sig).q).toBe(v.q);
      expect(lmsVerify(pk, msg, sig)).toBe(true);
      const bad = msg.slice();
      bad[0]! ^= 1;
      expect(lmsVerify(pk, bad, sig)).toBe(false);
    });
  }

  it("A.1 reproduces the public key from its 24-byte SEED and the signature from its C", () => {
    const v = vectors[0]!;
    const key = LmsPrivateKey.generate({ lmsType: v.lms_type, lmotsType: v.lmots_type, seed: fromHex(v.seed_hex), I: fromHex(v.I_hex) });
    expect(toHex(key.publicKey)).toBe(v.public_key_hex);
    const sig = fromHex(v.signature_hex);
    const C = parseLmsSignature(sig).lmotsSignature.subarray(4, 28);
    expect(toHex(key.sign(v.q, fromHex(v.message_hex), { C }))).toBe(v.signature_hex);
  });

  it("round-trips W4 and W8 keys from a 32-byte derived seed", () => {
    for (const [lmsType, lmotsType] of [
      [LMS_SHA256_M24_H5, LMOTS_SHA256_N24_W4],
      [LMS_SHA256_M24_H5, LMOTS_SHA256_N24_W8],
    ] as const) {
      const key = LmsPrivateKey.generate({ lmsType, lmotsType, seed: new Uint8Array(32).fill(9), I: new Uint8Array(16).fill(7) });
      expect(key.publicKey.length).toBe(lmsPublicKeyLength(lmsType));
      for (const q of [0, 17, 31]) {
        const sig = key.sign(q, new TextEncoder().encode("lamport-vault/v1 test"));
        expect(sig.length).toBe(lmsSignatureLength(lmsType, lmotsType));
        expect(lmsVerify(key.publicKey, new TextEncoder().encode("lamport-vault/v1 test"), sig)).toBe(true);
      }
    }
  });

  it("a 32-byte seed and its first 24 bytes give the same SHA-256/192 key", () => {
    const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
    const I = new Uint8Array(16).fill(1);
    const a = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M24_H5, lmotsType: LMOTS_SHA256_N24_W8, seed, I });
    const b = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M24_H5, lmotsType: LMOTS_SHA256_N24_W8, seed: seed.slice(0, 24), I });
    expect(toHex(a.publicKey)).toBe(toHex(b.publicKey));
  });

  it("sizes: H10 W4 is 1500 bytes, against 2508 for SHA-256 W4", () => {
    expect(lmsSignatureLength(LMS_SHA256_M24_H10, LMOTS_SHA256_N24_W4)).toBe(1500);
    expect(lmsSignatureLength(LMS_SHA256_M24_H10, LMOTS_SHA256_N24_W8)).toBe(900);
  });

  it("refuses to mix hash lengths between the tree and its leaves", () => {
    expect(() =>
      LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H5, lmotsType: LMOTS_SHA256_N24_W4, seed: new Uint8Array(32), I: new Uint8Array(16) }),
    ).toThrow();
    const key = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M24_H5, lmotsType: LMOTS_SHA256_N24_W4, seed: new Uint8Array(32), I: new Uint8Array(16) });
    const mixed = key.publicKey.slice();
    mixed[7] = LMOTS_SHA256_N32_W4;
    expect(() => parseLmsPublicKey(mixed)).toThrow();
  });
});
