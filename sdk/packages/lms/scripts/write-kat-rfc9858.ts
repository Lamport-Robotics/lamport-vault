/**
 * Writes kat/sdk_signatures_sha256_192.json: RFC 9858 SHA-256/192 signatures made by this SDK with
 * a fixed C, for the Rust verifier to cross-check (programs/lms/tests/rfc9858.rs). Keys: the
 * RFC 9858 A.1 key (H5, W8) and a fixed H10/W4 key, the set proposed for vaults.
 *
 *   node packages/lms/scripts/write-kat-rfc9858.ts          (from sdk/)
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  LMOTS_SHA256_N24_W4,
  LMS_SHA256_M24_H10,
  LmsPrivateKey,
  fromHex,
  lmsVerify,
  toHex,
  utf8,
} from "../src/index.ts";

const root = new URL("../../../../", import.meta.url);
const rfc = JSON.parse(readFileSync(fileURLToPath(new URL("kat/rfc9858_sha256_192.json", root)), "utf8")) as {
  vectors: { lms_type: number; lmots_type: number; seed_hex: string; I_hex: string; public_key_hex: string }[];
};

// C = sha256("lamport-vault/kat/C24" || u8str(n))[0..24], so anyone can regenerate them.
const fixedC = (n: number) => sha256(new Uint8Array([...utf8("lamport-vault/kat/C24"), n])).slice(0, 24);

const a1 = rfc.vectors[0]!;
const keys = [
  { name: "RFC 9858 A.1 key, SHA-256/192 H5 W8", lmsType: a1.lms_type, lmotsType: a1.lmots_type, seed: fromHex(a1.seed_hex), I: fromHex(a1.I_hex), pin: a1.public_key_hex },
  {
    name: "SHA-256/192 H10 W4 (proposed vault set)",
    lmsType: LMS_SHA256_M24_H10,
    lmotsType: LMOTS_SHA256_N24_W4,
    seed: sha256(utf8("lamport-vault/kat/seed24")),
    I: sha256(utf8("lamport-vault/kat/I24")).slice(0, 16),
    pin: undefined,
  },
];
const plan = [
  [{ q: 7, message: utf8("Lamport Vault SDK vector: SHA-256/192 H5 leaf 7"), c: 1 }],
  [
    { q: 0, message: new Uint8Array(0), c: 2 },
    { q: 1023, message: fromHex("6c616d706f72742d7661756c742f7631" + "00".repeat(32)), c: 3 },
  ],
];

const out = {
  source:
    '@lamport-robotics/lms (this repository), RFC 9858 SHA-256/192. C is fixed as sha256("lamport-vault/kat/C24" || u8str(c_index))[0..24]; the H10 key\'s SEED is the full sha256("lamport-vault/kat/seed24"), of which SHA-256/192 uses the first 24 bytes.',
  vectors: keys.map((k, i) => {
    const key = LmsPrivateKey.generate({ lmsType: k.lmsType, lmotsType: k.lmotsType, seed: k.seed, I: k.I });
    if (k.pin && toHex(key.publicKey) !== k.pin) throw new Error("public key mismatch against RFC 9858");
    return {
      name: k.name,
      lms_type: k.lmsType,
      lmots_type: k.lmotsType,
      seed_hex: toHex(k.seed),
      I_hex: toHex(k.I),
      public_key_hex: toHex(key.publicKey),
      signatures: plan[i]!.map((s) => {
        const C = fixedC(s.c);
        const sig = key.sign(s.q, s.message, { C });
        if (!lmsVerify(key.publicKey, s.message, sig)) throw new Error("self-verify failed");
        return { q: s.q, c_index: s.c, C_hex: toHex(C), message_hex: toHex(s.message), signature_hex: toHex(sig) };
      }),
    };
  }),
};
writeFileSync(fileURLToPath(new URL("kat/sdk_signatures_sha256_192.json", root)), JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${out.vectors.length} keys`);
