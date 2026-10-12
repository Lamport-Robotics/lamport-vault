/**
 * Vectors from Cisco's hash-sigs C implementation (kat/hashsigs_w4.json, kat/hashsigs_w1w2w8.json):
 * public keys and signatures only (its private key format is not RFC 8554 Appendix A). W4 at
 * H5/H10/H15 and W1/W2/W8 at H5 or H10, each with leaf 0 and the last leaf.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { fromHex, toHex } from "../src/bytes.ts";
import { lmsVerify, parseLmsPublicKey, parseLmsSignature } from "../src/lms.ts";
import { lmotsParams, lmsParams, lmsSignatureLength, LMOTS_SHA256_N32_W4 } from "../src/params.ts";

interface HsVector {
  name: string;
  lms_type: number;
  lmots_type: number;
  height: number;
  I_hex: string;
  public_key_hex: string;
  hss_public_key_hex: string;
  signatures: { q: number; message_hex: string; signature_hex: string }[];
}
interface HsFile {
  commit: string;
  vectors: HsVector[];
}

const HASHSIGS_COMMIT = "cea4dda4f937e56ab42e1a74665f6397473a2838";
const load = (name: string): HsFile =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../../../../kat/${name}`, import.meta.url)), "utf8")) as HsFile;
const w4 = load("hashsigs_w4.json");
const other = load("hashsigs_w1w2w8.json");

function flip(bytes: Uint8Array, byte: number): Uint8Array {
  const out = bytes.slice();
  out[byte]! ^= 1 << byte % 8;
  return out;
}

describe("hash-sigs vectors", () => {
  it("are pinned to the documented commit and cover both ends of every tree", () => {
    expect(w4.commit).toBe(HASHSIGS_COMMIT);
    expect(other.commit).toBe(HASHSIGS_COMMIT);
    expect(w4.vectors.map((v) => v.height).sort((a, b) => a - b)).toEqual([5, 10, 15]);
    expect(w4.vectors.every((v) => v.lmots_type === LMOTS_SHA256_N32_W4)).toBe(true);
    expect([...new Set(other.vectors.map((v) => v.lmots_type))].sort()).toEqual([1, 2, 4]);
    for (const v of [...w4.vectors, ...other.vectors]) {
      const hss = fromHex(v.hss_public_key_hex);
      expect(toHex(hss.subarray(0, 4))).toBe("00000001");
      expect(toHex(hss.subarray(4))).toBe(v.public_key_hex);
      const qs = v.signatures.map((s) => s.q);
      expect(qs).toContain(0);
      expect(qs).toContain(2 ** v.height - 1);
    }
  });

  describe.each([...w4.vectors, ...other.vectors])("$name", (v) => {
    const pk = fromHex(v.public_key_hex);

    it("parses with the declared typecodes", () => {
      const parts = parseLmsPublicKey(pk);
      expect(parts.lmsType).toBe(v.lms_type);
      expect(parts.lmotsType).toBe(v.lmots_type);
      expect(lmsParams(parts.lmsType).h).toBe(v.height);
      expect(toHex(parts.I)).toBe(v.I_hex);
    });

    it.each(v.signatures)("q=$q verifies", (s) => {
      const sig = fromHex(s.signature_hex);
      const ots = lmotsParams(v.lmots_type);
      expect(sig.length).toBe(lmsSignatureLength(v.lms_type, v.lmots_type));
      expect(sig.length).toBe(4 + 4 + 32 * (ots.p + 1) + 4 + 32 * v.height);
      expect(parseLmsSignature(sig, { lmsType: v.lms_type, lmotsType: v.lmots_type }).q).toBe(s.q);
      expect(lmsVerify(pk, fromHex(s.message_hex), sig)).toBe(true);
    });

    it("rejects flipped bits in the signature, message and key", () => {
      const stride = { 1: 32, 2: 16, 3: 8, 4: 8 }[v.lmots_type] ?? 8;
      for (const s of v.signatures) {
        const msg = fromHex(s.message_hex);
        const sig = fromHex(s.signature_hex);
        for (let b = 0; b < sig.length; b += stride) expect(lmsVerify(pk, msg, flip(sig, b)), `q=${s.q} byte ${b}`).toBe(false);
        if (msg.length === 0) expect(lmsVerify(pk, Uint8Array.of(0), sig)).toBe(false);
        else expect(lmsVerify(pk, flip(msg, msg.length >> 1), sig)).toBe(false);
        expect(lmsVerify(flip(pk, 55), msg, sig)).toBe(false);
      }
    });
  });

  it("W8 and W4 signatures of the same height do not cross-verify", () => {
    const w8 = other.vectors.find((v) => v.lmots_type === 4 && v.height === 5)!;
    const w4h5 = w4.vectors.find((v) => v.height === 5)!;
    expect(lmsVerify(fromHex(w4h5.public_key_hex), fromHex(w8.signatures[0]!.message_hex), fromHex(w8.signatures[0]!.signature_hex))).toBe(false);
    expect(lmsVerify(fromHex(w8.public_key_hex), fromHex(w4h5.signatures[0]!.message_hex), fromHex(w4h5.signatures[0]!.signature_hex))).toBe(false);
  });
});
