import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { concat, equalBytes, fromHex, toHex, u16str, u32str, u8str } from "../src/bytes.ts";
import {
  checksum,
  coef,
  derivePrivateElements,
  lmotsSign,
  publicKeyCandidate,
  publicKeyHash,
  publicKeyHashFromSeed,
} from "../src/lmots.ts";
import { LMOTS_PARAMS, LMOTS_SHA256_N32_W4, lmotsParams } from "../src/params.ts";

const W4 = lmotsParams(LMOTS_SHA256_N32_W4);

describe("coef and checksum", () => {
  it("reproduces the RFC 8554 Section 3.1.3 examples", () => {
    const S = fromHex("1234");
    expect(coef(S, 7, 1)).toBe(0);
    expect(coef(S, 0, 4)).toBe(1);
    expect(coef(S, 1, 4)).toBe(2);
    expect(coef(S, 3, 4)).toBe(4);
    expect(coef(S, 0, 8)).toBe(0x12);
    expect(coef(S, 1, 2)).toBe(1);
    expect(coef(S, 2, 2)).toBe(0);
  });

  it("raises on out-of-range index", () => {
    expect(() => coef(fromHex("1234"), 4, 4)).toThrow();
  });

  it("W4 checksum of all-0xf digits is zero and of all-zero digits is 64*15<<4", () => {
    const ff = new Uint8Array(32).fill(0xff);
    expect(toHex(checksum(ff, W4))).toBe("0000");
    const zero = new Uint8Array(32);
    expect(toHex(checksum(zero, W4))).toBe(toHex(u16str((64 * 15) << 4)));
  });
});

describe("Appendix A private elements", () => {
  it("x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)", () => {
    const seed = randomBytes(32);
    const I = randomBytes(16);
    const q = 777;
    const x = derivePrivateElements(W4, seed, I, q);
    expect(x.length).toBe(67 * 32);
    for (const i of [0, 1, 33, 66]) {
      const want = sha256(concat(I, u32str(q), u16str(i), u8str(0xff), seed));
      expect(toHex(x.subarray(i * 32, i * 32 + 32))).toBe(toHex(want));
    }
  });
});

describe("LM-OTS sign/verify", () => {
  for (const params of Object.values(LMOTS_PARAMS)) {
    it(`${params.name}: public key from seed equals Algorithm 1 over x, and Kc matches`, () => {
      const seed = randomBytes(32);
      const I = randomBytes(16);
      const q = 5;
      const x = derivePrivateElements(params, seed, I, q);
      const K1 = publicKeyHash(params, I, q, x);
      const K2 = publicKeyHashFromSeed(params, seed, I, q);
      expect(toHex(K1)).toBe(toHex(K2));

      const msg = randomBytes(100);
      const C = randomBytes(params.n);
      const sig = lmotsSign(params, I, q, x, msg, C);
      expect(sig.length).toBe(params.sigLen);
      const Kc = publicKeyCandidate(params, I, q, msg, sig);
      expect(Kc && equalBytes(Kc, K1)).toBe(true);

      const other = publicKeyCandidate(params, I, q, randomBytes(100), sig);
      expect(other && equalBytes(other, K1)).toBe(false);
    });
  }

  it("rejects a signature with the wrong typecode or length", () => {
    const seed = randomBytes(32);
    const I = randomBytes(16);
    const x = derivePrivateElements(W4, seed, I, 0);
    const sig = lmotsSign(W4, I, 0, x, new Uint8Array(0), randomBytes(32));
    expect(publicKeyCandidate(W4, I, 0, new Uint8Array(0), sig.subarray(0, sig.length - 1))).toBeNull();
    const bad = sig.slice();
    bad[3] = 4;
    expect(publicKeyCandidate(W4, I, 0, new Uint8Array(0), bad)).toBeNull();
  });
});
