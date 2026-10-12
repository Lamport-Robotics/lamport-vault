/**
 * RFC 8554 Appendix F test cases (kat/rfc8554_appendix_f.json): two-level HSS signatures whose LMS
 * layers are H5/W8, H10/W4 and H5/W8. The HSS envelope is walked here; the package only knows LMS.
 * Test case 2 also publishes SEED and I of both trees, so the signer must reproduce the public
 * keys and, given the RFC's randomizer C, the signatures byte for byte.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { fromHex, toHex } from "../src/bytes.ts";
import { LmsPrivateKey, lmsVerify, parseLmsPublicKey, parseLmsSignature } from "../src/lms.ts";
import { lmsSignatureLength, LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8, LMS_SHA256_M32_H10, LMS_SHA256_M32_H5 } from "../src/params.ts";

interface Layer {
  layer: number;
  public_key_hex: string;
  lms_type: number;
  lmots_type: number;
  I_hex: string;
  message_hex: string;
  q: number;
  signature_hex: string;
}
interface TestCase {
  test_case: number;
  levels: number;
  hss_public_key_hex: string;
  message_hex: string;
  nspk: number;
  private_keys?: { level: number; seed_hex: string; I_hex: string }[];
  lms_layers: Layer[];
  hss_signature_hex: string;
}

const path = fileURLToPath(new URL("../../../../kat/rfc8554_appendix_f.json", import.meta.url));
const rfc = JSON.parse(readFileSync(path, "utf8")) as { test_cases: TestCase[] };

function flip(bytes: Uint8Array, byte: number): Uint8Array {
  const out = bytes.slice();
  out[byte]! ^= 1 << byte % 8;
  return out;
}

/** RFC 8554 Section 6.3 for a key of any number of levels, built on lmsVerify. */
function hssVerify(hssPk: Uint8Array, message: Uint8Array, hssSig: Uint8Array): boolean {
  const u32 = (b: Uint8Array, o: number) => ((b[o]! << 24) | (b[o + 1]! << 16) | (b[o + 2]! << 8) | b[o + 3]!) >>> 0;
  const levels = u32(hssPk, 0);
  const nspk = u32(hssSig, 0);
  if (nspk + 1 !== levels) return false;
  let pk = hssPk.subarray(4);
  let pos = 4;
  for (let i = 0; i < nspk; i++) {
    const { lmsType, lmotsType } = parseLmsPublicKey(pk);
    const sigLen = lmsSignatureLength(lmsType, lmotsType);
    const sig = hssSig.subarray(pos, pos + sigLen);
    const next = hssSig.subarray(pos + sigLen, pos + sigLen + 56);
    if (next.length !== 56 || !lmsVerify(pk, next, sig)) return false;
    pk = next;
    pos += sigLen + 56;
  }
  return lmsVerify(pk, message, hssSig.subarray(pos));
}

describe("RFC 8554 Appendix F", () => {
  it("has the two test cases with the documented parameter sets", () => {
    expect(rfc.test_cases.map((t) => t.test_case)).toEqual([1, 2]);
    expect(rfc.test_cases[0]!.lms_layers.map((l) => [l.lms_type, l.lmots_type])).toEqual([
      [LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8],
      [LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8],
    ]);
    expect(rfc.test_cases[1]!.lms_layers.map((l) => [l.lms_type, l.lmots_type])).toEqual([
      [LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W4],
      [LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8],
    ]);
  });

  describe.each(rfc.test_cases)("test case $test_case", (tc) => {
    it.each(tc.lms_layers)("LMS layer $layer verifies", (l) => {
      const pk = fromHex(l.public_key_hex);
      const parts = parseLmsPublicKey(pk);
      expect(parts.lmsType).toBe(l.lms_type);
      expect(parts.lmotsType).toBe(l.lmots_type);
      expect(toHex(parts.I)).toBe(l.I_hex);
      const sig = fromHex(l.signature_hex);
      expect(sig.length).toBe(lmsSignatureLength(l.lms_type, l.lmots_type));
      const parsed = parseLmsSignature(sig, { lmsType: l.lms_type, lmotsType: l.lmots_type });
      expect(parsed.q).toBe(l.q);
      expect(lmsVerify(pk, fromHex(l.message_hex), sig)).toBe(true);
    });

    it("the HSS envelope verifies end to end and fails on a changed message", () => {
      const pk = fromHex(tc.hss_public_key_hex);
      const msg = fromHex(tc.message_hex);
      const sig = fromHex(tc.hss_signature_hex);
      expect(hssVerify(pk, msg, sig)).toBe(true);
      expect(hssVerify(pk, flip(msg, 0), sig)).toBe(false);
      expect(hssVerify(pk, msg, sig.subarray(0, sig.length - 1))).toBe(false);
      expect(hssVerify(pk, msg, flip(sig, 4 + 8))).toBe(false); // C of sig[0]
    });

    it.each(tc.lms_layers)("layer $layer: flipped signature and message bits fail", (l) => {
      const pk = fromHex(l.public_key_hex);
      const msg = fromHex(l.message_hex);
      const sig = fromHex(l.signature_hex);
      const stride = l.lmots_type === LMOTS_SHA256_N32_W8 ? 7 : 3;
      for (let b = 0; b < sig.length; b += stride) expect(lmsVerify(pk, msg, flip(sig, b)), `sig byte ${b}`).toBe(false);
      for (let b = 0; b < msg.length; b += stride) expect(lmsVerify(pk, flip(msg, b), sig), `msg byte ${b}`).toBe(false);
      expect(lmsVerify(flip(pk, 20), msg, sig)).toBe(false); // I
      expect(lmsVerify(flip(pk, 40), msg, sig)).toBe(false); // T1
    });
  });

  it("test case 2: both trees reproduce from SEED/I and both signatures match byte for byte with the RFC's C", () => {
    const tc = rfc.test_cases[1]!;
    for (const [k, l] of tc.private_keys!.map((k, i) => [k, tc.lms_layers[i]!] as const)) {
      const key = LmsPrivateKey.generate({ lmsType: l.lms_type, lmotsType: l.lmots_type, seed: fromHex(k.seed_hex), I: fromHex(k.I_hex) });
      expect(toHex(key.publicKey)).toBe(l.public_key_hex);
      const theirs = fromHex(l.signature_hex);
      const C = theirs.slice(8, 40);
      const ours = key.sign(l.q, fromHex(l.message_hex), { C });
      expect(toHex(ours)).toBe(l.signature_hex);
      // A fresh random C still verifies and differs.
      const other = key.sign(l.q, fromHex(l.message_hex));
      expect(toHex(other)).not.toBe(l.signature_hex);
      expect(lmsVerify(key.publicKey, fromHex(l.message_hex), other)).toBe(true);
    }
  });
});
