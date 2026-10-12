/**
 * Writes kat/sdk_signatures.json: signatures made by this SDK with a fixed C, so the Rust
 * verifier (and later the C firmware) can cross-check them. The file has the same shape as
 * kat/lms_sha256_w4.json (plus `C_hex` per signature), so the same loader reads both. Keys are
 * the KAT SEED/I pairs, whose public keys an independent implementation already pinned.
 *
 *   node packages/lms/scripts/write-kat.ts          (from sdk/; Node strips the types itself)
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha2.js";
import { LmsPrivateKey, fromHex, lmsVerify, toHex, utf8 } from "../src/index.ts";

const root = new URL("../../../../", import.meta.url);
const katIn = fileURLToPath(new URL("kat/lms_sha256_w4.json", root));
const katOut = fileURLToPath(new URL("kat/sdk_signatures.json", root));

interface KatVector {
  name: string;
  lms_type: number;
  lmots_type: number;
  height: number;
  seed_hex: string;
  I_hex: string;
  public_key_hex: string;
}
const kat = JSON.parse(readFileSync(katIn, "utf8")) as { vectors: KatVector[] };
const byHeight = new Map(kat.vectors.map((v) => [v.height, v]));

// Fixed randomizers: C = sha256("lamport-vault/kat/C" || u8str(n)), so anyone can regenerate them.
const fixedC = (n: number) => sha256(new Uint8Array([...utf8("lamport-vault/kat/C"), n]));

const plan: { height: number; signatures: { q: number; message: Uint8Array; cIndex: number }[] }[] = [
  {
    height: 5,
    signatures: [
      { q: 3, message: utf8("Lamport Vault SDK vector: H5 leaf 3"), cIndex: 1 },
      { q: 30, message: new Uint8Array(0), cIndex: 2 },
    ],
  },
  {
    height: 10,
    signatures: [{ q: 512, message: fromHex("6c616d706f72742d7661756c742f7631" + "00".repeat(32) + "ff".repeat(8)), cIndex: 3 }],
  },
];

const out = {
  source:
    '@lamport-robotics/lms (this repository). Keys are the kat/lms_sha256_w4.json SEED/I pairs; C is fixed as sha256("lamport-vault/kat/C" || u8str(c_index)) so the signatures are reproducible byte for byte.',
  vectors: plan.map((p) => {
    const v = byHeight.get(p.height);
    if (!v) throw new Error(`no KAT key of height ${p.height}`);
    const key = LmsPrivateKey.generate({ lmsType: v.lms_type, lmotsType: v.lmots_type, seed: fromHex(v.seed_hex), I: fromHex(v.I_hex) });
    if (toHex(key.publicKey) !== v.public_key_hex) throw new Error("public key mismatch against KAT");
    return {
      name: `${v.name} (SDK signatures)`,
      lms_type: v.lms_type,
      lmots_type: v.lmots_type,
      height: v.height,
      seed_hex: v.seed_hex,
      I_hex: v.I_hex,
      public_key_hex: v.public_key_hex,
      signatures: p.signatures.map((s) => {
        const C = fixedC(s.cIndex);
        const sig = key.sign(s.q, s.message, { C });
        if (!lmsVerify(key.publicKey, s.message, sig)) throw new Error("self-verify failed");
        return { q: s.q, c_index: s.cIndex, C_hex: toHex(C), message_hex: toHex(s.message), signature_hex: toHex(sig) };
      }),
    };
  }),
};

writeFileSync(katOut, JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${katOut} (${out.vectors.reduce((n, v) => n + v.signatures.length, 0)} signatures)`);
