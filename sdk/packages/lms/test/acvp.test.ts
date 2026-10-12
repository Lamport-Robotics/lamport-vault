/**
 * NIST ACVP LMS vectors (kat/acvp_lms.json). Every group ACVP-Server publishes is a SP 800-208
 * SHA-256/192 set (n = m = 24, typecodes 0x0A/0x0B and 0x05/0x06); there are no RFC 8554 n = 32
 * cases. This package implements n = 32 only, so:
 *
 *  1. the shipped parser/verifier must reject every ACVP key cleanly;
 *  2. a test-only n = 24 instantiation of Algorithms 4b/6a, built on the package's `coef` and
 *     SHA-256, checks that the algorithm as implemented here agrees with NIST on all valid and
 *     deliberately invalid cases, and reproduces the keyGen public keys via Appendix A.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { concat, equalBytes, fromHex, toHex, u16str, u32str, u8str } from "../src/bytes.ts";
import { coef } from "../src/lmots.ts";
import { lmsVerify, parseLmsPublicKey } from "../src/lms.ts";
import { D_INTR, D_LEAF, D_MESG, D_PBLC, D_PRG } from "../src/params.ts";
import { sha256 } from "../src/sha256.ts";

interface LmsSet {
  typecode: number;
  h: number;
  m: number;
}
interface LmotsSet {
  typecode: number;
  w: number;
  n: number;
  p: number;
  ls: number;
}
interface Acvp {
  commit: string;
  parameter_sets: { lms: Record<string, LmsSet>; lmots: Record<string, LmotsSet> };
  sig_ver: { id: string; lms_mode: string; lmots_mode: string; public_key_hex: string; message_hex: string; signature_hex: string; expected_valid: boolean; reason: string }[];
  sig_gen: { id: string; lms_mode: string; lmots_mode: string; public_key_hex: string; message_hex: string; signature_hex: string; q: number }[];
  key_gen: { id: string; lms_mode: string; lmots_mode: string; seed_hex: string; I_hex: string; public_key_hex: string }[];
}

const acvp = JSON.parse(readFileSync(fileURLToPath(new URL("../../../../kat/acvp_lms.json", import.meta.url)), "utf8")) as Acvp;

const h24 = (...parts: Uint8Array[]): Uint8Array => sha256(concat(...parts)).subarray(0, 24);
const u32 = (b: Uint8Array, o: number) => ((b[o]! << 24) | (b[o + 1]! << 16) | (b[o + 2]! << 8) | b[o + 3]!) >>> 0;

function checksum24(Q: Uint8Array, t: LmotsSet): Uint8Array {
  const max = (1 << t.w) - 1;
  let sum = 0;
  for (let i = 0; i < (8 * t.n) / t.w; i++) sum += max - coef(Q, i, t.w);
  return u16str((sum << t.ls) & 0xffff);
}

function otsCandidate24(t: LmotsSet, I: Uint8Array, q: number, C: Uint8Array, y: Uint8Array, message: Uint8Array): Uint8Array {
  const Q = h24(I, u32str(q), u16str(D_MESG), C, message);
  const QC = concat(Q, checksum24(Q, t));
  const max = (1 << t.w) - 1;
  const z: Uint8Array[] = [];
  for (let i = 0; i < t.p; i++) {
    let tmp = y.subarray(i * 24, (i + 1) * 24);
    for (let j = coef(QC, i, t.w); j < max; j++) tmp = h24(I, u32str(q), u16str(i), u8str(j), tmp);
    z.push(tmp);
  }
  return h24(I, u32str(q), u16str(D_PBLC), ...z);
}

type Reason = "ok" | "key" | "ots typecode" | "lms typecode" | "length" | "leaf" | "root";

function verify24(lms: LmsSet, ots: LmotsSet, pk: Uint8Array, message: Uint8Array, sig: Uint8Array): Reason {
  if (pk.length !== 48 || u32(pk, 0) !== lms.typecode || u32(pk, 4) !== ots.typecode) return "key";
  const I = pk.subarray(8, 24);
  const T1 = pk.subarray(24, 48);
  const otsLen = 4 + 24 * (ots.p + 1);
  if (sig.length < 8) return "length";
  const q = u32(sig, 0);
  if (u32(sig, 4) !== ots.typecode) return "ots typecode";
  if (sig.length < 4 + otsLen + 4) return "length";
  if (u32(sig, 4 + otsLen) !== lms.typecode) return "lms typecode";
  if (sig.length !== 4 + otsLen + 4 + 24 * lms.h) return "length";
  if (q >= 2 ** lms.h) return "leaf";
  const Kc = otsCandidate24(ots, I, q, sig.subarray(8, 32), sig.subarray(32, 4 + otsLen), message);
  const path = sig.subarray(8 + otsLen);
  let node = 2 ** lms.h + q;
  let tmp = h24(I, u32str(node), u16str(D_LEAF), Kc);
  for (let i = 0; i < lms.h; i++) {
    const sib = path.subarray(i * 24, (i + 1) * 24);
    const parent = node >>> 1;
    tmp = node % 2 === 1 ? h24(I, u32str(parent), u16str(D_INTR), sib, tmp) : h24(I, u32str(parent), u16str(D_INTR), tmp, sib);
    node = parent;
  }
  return equalBytes(tmp, T1) ? "ok" : "root";
}

const sets = (lmsMode: string, lmotsMode: string) => [acvp.parameter_sets.lms[lmsMode]!, acvp.parameter_sets.lmots[lmotsMode]!] as const;

describe("NIST ACVP LMS vectors", () => {
  it("are the documented SHA-256/192 set", () => {
    expect(acvp.commit).toBe("975de31eb83d87039ec88934fdc47d8c312b892d");
    expect(acvp.sig_ver.length).toBe(16);
    expect(acvp.sig_ver.filter((s) => s.expected_valid).length).toBe(4);
    expect(acvp.sig_gen.length).toBe(62);
    expect(acvp.key_gen.length).toBe(9);
    expect(Object.values(acvp.parameter_sets.lms).every((s) => s.m === 24)).toBe(true);
    expect(Object.values(acvp.parameter_sets.lmots).every((s) => s.n === 24)).toBe(true);
  });

  it("every M24 key is rejected by the shipped n = 32 verifier without throwing", () => {
    for (const s of [...acvp.sig_ver, ...acvp.sig_gen]) {
      const pk = fromHex(s.public_key_hex);
      expect(pk.length).toBe(48);
      expect(() => parseLmsPublicKey(pk)).toThrow();
      expect(lmsVerify(pk, fromHex(s.message_hex), fromHex(s.signature_hex))).toBe(false);
      const padded = new Uint8Array(56);
      padded.set(pk);
      expect(() => parseLmsPublicKey(padded)).toThrow(/unknown LMS typecode/);
      expect(lmsVerify(padded, fromHex(s.message_hex), fromHex(s.signature_hex))).toBe(false);
    }
  });

  it.each(acvp.sig_ver)("sigVer $id ($reason) -> valid=$expected_valid", (s) => {
    const [lms, ots] = sets(s.lms_mode, s.lmots_mode);
    const r = verify24(lms, ots, fromHex(s.public_key_hex), fromHex(s.message_hex), fromHex(s.signature_hex));
    expect(r === "ok").toBe(s.expected_valid);
    if (s.reason === "modify message" || s.reason === "modify signature") expect(r).toBe("root");
    if (s.reason === "modify signature header") expect(["ots typecode", "lms typecode", "leaf", "root"]).toContain(r);
  });

  it("sigGen: all 62 NIST signatures verify and fail on a changed message", () => {
    const lens = new Set<number>();
    for (const s of acvp.sig_gen) {
      const [lms, ots] = sets(s.lms_mode, s.lmots_mode);
      const msg = fromHex(s.message_hex);
      lens.add(msg.length);
      const sig = fromHex(s.signature_hex);
      expect(verify24(lms, ots, fromHex(s.public_key_hex), msg, sig), s.id).toBe("ok");
      expect(u32(sig, 0)).toBe(s.q);
      const bad = msg.slice();
      bad[0]! ^= 1;
      expect(verify24(lms, ots, fromHex(s.public_key_hex), bad, sig)).toBe("root");
    }
    expect(lens.size).toBeGreaterThan(10);
  });

  it.each(acvp.key_gen)("keyGen $id reproduces the public key from SEED/I (Appendix A, n = 24)", (k) => {
    const [lms, ots] = sets(k.lms_mode, k.lmots_mode);
    const seed = fromHex(k.seed_hex);
    const I = fromHex(k.I_hex);
    expect(seed.length).toBe(24);
    const leaves = 2 ** lms.h;
    const max = (1 << ots.w) - 1;
    const nodes: Uint8Array[] = new Array(2 * leaves);
    for (let q = 0; q < leaves; q++) {
      const y: Uint8Array[] = [];
      for (let i = 0; i < ots.p; i++) {
        let tmp = h24(I, u32str(q), u16str(i), u8str(D_PRG), seed);
        for (let j = 0; j < max; j++) tmp = h24(I, u32str(q), u16str(i), u8str(j), tmp);
        y.push(tmp);
      }
      const K = h24(I, u32str(q), u16str(D_PBLC), ...y);
      nodes[leaves + q] = h24(I, u32str(leaves + q), u16str(D_LEAF), K);
    }
    for (let r = leaves - 1; r >= 1; r--) nodes[r] = h24(I, u32str(r), u16str(D_INTR), nodes[2 * r]!, nodes[2 * r + 1]!);
    const pk = concat(u32str(lms.typecode), u32str(ots.typecode), I, nodes[1]!);
    expect(toHex(pk)).toBe(k.public_key_hex);
  });
});
