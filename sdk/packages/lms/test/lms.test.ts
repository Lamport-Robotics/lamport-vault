import { randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { equalBytes, toHex } from "../src/bytes.ts";
import {
  LmsPrivateKey,
  lmsVerify,
  nodeHash,
  parseLmsPublicKey,
  parseLmsSignature,
  randomKeyMaterial,
  serializeLmsSignature,
} from "../src/lms.ts";
import { publicKeyHashFromSeed } from "../src/lmots.ts";
import {
  LMOTS_SHA256_N32_W4,
  LMS_SHA256_M32_H10,
  LMS_SHA256_M32_H5,
  lmotsParams,
  lmsSignatureLength,
} from "../src/params.ts";

describe("LMS H5", () => {
  const mat = randomKeyMaterial(LMS_SHA256_M32_H5);
  const key = LmsPrivateKey.generate(mat);

  it("has a 56-byte public key with the right typecodes and I", () => {
    expect(key.publicKey.length).toBe(56);
    const p = parseLmsPublicKey(key.publicKey);
    expect(p.lmsType).toBe(LMS_SHA256_M32_H5);
    expect(p.lmotsType).toBe(LMOTS_SHA256_N32_W4);
    expect(toHex(p.I)).toBe(toHex(mat.I));
  });

  it("builds the tree exactly as Section 5.3 defines it", () => {
    const ots = lmotsParams(LMOTS_SHA256_N32_W4);
    for (const q of [0, 1, 31]) {
      const K = publicKeyHashFromSeed(ots, mat.seed, mat.I, q);
      expect(toHex(key.leaf(q))).toBe(toHex(nodeHash.leaf(mat.I, 32 + q, K)));
    }
    const root = nodeHash.interior(mat.I, 1, key.tree.subarray(64, 96), key.tree.subarray(96, 128));
    expect(toHex(root)).toBe(toHex(key.publicKey.subarray(24)));
  });

  it("signs with every leaf and each signature verifies, with random C each time", () => {
    const msg = new TextEncoder().encode("Lamport Vault: transfer 1 SOL");
    for (let q = 0; q < 32; q++) {
      const sig = key.sign(q, msg);
      expect(sig.length).toBe(lmsSignatureLength(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W4));
      expect(sig.length).toBe(2348);
      expect(lmsVerify(key.publicKey, msg, sig)).toBe(true);
      expect(lmsVerify(key.publicKey, new TextEncoder().encode("Lamport Vault: transfer 2 SOL"), sig)).toBe(false);
    }
  });

  it("two signatures with the same q differ in C (random) but both verify", () => {
    const msg = randomBytes(40);
    const a = key.sign(3, msg);
    const b = key.sign(3, msg);
    expect(toHex(a)).not.toBe(toHex(b));
    expect(lmsVerify(key.publicKey, msg, a)).toBe(true);
    expect(lmsVerify(key.publicKey, msg, b)).toBe(true);
  });

  it("deterministic C gives a deterministic signature", () => {
    const msg = randomBytes(40);
    const C = randomBytes(32);
    expect(toHex(key.sign(9, msg, { C }))).toBe(toHex(key.sign(9, msg, { C })));
  });

  it("parse/serialize round-trips", () => {
    const sig = key.sign(17, new Uint8Array(0));
    const parts = parseLmsSignature(sig);
    expect(parts.q).toBe(17);
    expect(parts.path.length).toBe(5);
    expect(toHex(serializeLmsSignature(parts))).toBe(toHex(sig));
    expect(parts.path.map(toHex)).toEqual(key.authPath(17).map(toHex));
  });

  it("rejects q outside the tree", () => {
    expect(() => key.sign(32, new Uint8Array(0))).toThrow(RangeError);
    expect(() => key.sign(-1, new Uint8Array(0))).toThrow(RangeError);
  });

  it("async builder produces the same key and reports progress", async () => {
    const progress: number[] = [];
    const k2 = await LmsPrivateKey.generateAsync(mat, { leavesPerTick: 8, onProgress: (d) => progress.push(d) });
    expect(toHex(k2.publicKey)).toBe(toHex(key.publicKey));
    expect(progress).toEqual([8, 16, 24, 32]);
  });

  it("restores from a cached tree and rejects a tampered one", () => {
    const restored = LmsPrivateKey.fromTree(mat, key.tree);
    expect(toHex(restored.publicKey)).toBe(toHex(key.publicKey));
    const sig = restored.sign(4, new Uint8Array([1, 2, 3]));
    expect(lmsVerify(key.publicKey, new Uint8Array([1, 2, 3]), sig)).toBe(true);
    const bad = key.tree.slice();
    bad[40 * 32 + 1]! ^= 1; // leaf node 40 of the 32..63 leaf range
    expect(() => LmsPrivateKey.fromTree(mat, bad)).toThrow(/inconsistent/);
  });

  it("a signature does not verify under another key with the same I", () => {
    const other = LmsPrivateKey.generate({ ...mat, seed: randomBytes(32) });
    const msg = randomBytes(10);
    const sig = key.sign(0, msg);
    expect(equalBytes(other.publicKey.subarray(8, 24), key.publicKey.subarray(8, 24))).toBe(true);
    expect(lmsVerify(other.publicKey, msg, sig)).toBe(false);
  });
});

describe("LMS H10", () => {
  it("keygen takes well under 2 s and the key signs/verifies", () => {
    const mat = randomKeyMaterial(LMS_SHA256_M32_H10);
    const t0 = performance.now();
    const key = LmsPrivateKey.generate(mat);
    const ms = performance.now() - t0;
    // eslint-disable-next-line no-console
    console.log(`H10 keygen: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(2000);
    expect(key.leafCount).toBe(1024);
    const msg = randomBytes(64);
    const sig = key.sign(1023, msg);
    expect(sig.length).toBe(2508);
    expect(lmsVerify(key.publicKey, msg, sig)).toBe(true);
  });
});
