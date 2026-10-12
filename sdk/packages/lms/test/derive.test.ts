import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import { concat, toHex, u32str, utf8 } from "../src/bytes.ts";
import {
  deriveKeyMaterial,
  deriveLmsInputs,
  deriveRegistryKeyMaterial,
  generateMnemonic,
  ID_DOMAIN,
  isValidMnemonic,
  mnemonicToMaster,
  recoverKey,
  REGISTRY_KEY_INDEX,
  SEED_DOMAIN,
} from "../src/derive.ts";
import { LmsPrivateKey } from "../src/lms.ts";
import { LMS_SHA256_M32_H5 } from "../src/params.ts";

// The BIP-39 reference vector (Trezor test vectors, entropy 0x00..00, passphrase "TREZOR").
const REF_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const REF_SEED_TREZOR =
  "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

describe("mnemonic -> master", () => {
  it("matches the BIP-39 reference vector", () => {
    expect(toHex(mnemonicToMaster(REF_MNEMONIC, "TREZOR"))).toBe(REF_SEED_TREZOR);
  });

  it("generates valid 24-word phrases and rejects garbage", () => {
    const m = generateMnemonic();
    expect(m.split(" ").length).toBe(24);
    expect(isValidMnemonic(m)).toBe(true);
    expect(isValidMnemonic("not a mnemonic at all")).toBe(false);
    expect(() => mnemonicToMaster("not a mnemonic at all")).toThrow();
  });
});

describe("SEED_k / I_k", () => {
  const master = mnemonicToMaster(REF_MNEMONIC);

  it("is deterministic and follows the SPEC-DERIVATION formulas", () => {
    for (const k of [0, 1, 2, 65535, REGISTRY_KEY_INDEX]) {
      const a = deriveLmsInputs(master, k);
      const b = deriveLmsInputs(master, k);
      expect(toHex(a.seed)).toBe(toHex(b.seed));
      expect(toHex(a.I)).toBe(toHex(b.I));
      const msg = concat(master, u32str(k));
      expect(toHex(a.seed)).toBe(toHex(hmac(sha256, utf8(SEED_DOMAIN), msg)));
      expect(toHex(a.I)).toBe(toHex(hmac(sha256, utf8(ID_DOMAIN), msg).subarray(0, 16)));
      expect(a.seed.length).toBe(32);
      expect(a.I.length).toBe(16);
    }
  });

  it("differs across k, across passphrases, and from the registry index", () => {
    const seen = new Set<string>();
    for (let k = 0; k < 16; k++) {
      const { seed, I } = deriveLmsInputs(master, k);
      expect(seen.has(toHex(seed))).toBe(false);
      seen.add(toHex(seed));
      expect(seen.has(toHex(I))).toBe(false);
      seen.add(toHex(I));
    }
    const reg = deriveRegistryKeyMaterial(master);
    expect(seen.has(toHex(reg.seed))).toBe(false);
    expect(seen.has(toHex(reg.I))).toBe(false);
    const other = deriveLmsInputs(mnemonicToMaster(REF_MNEMONIC, "TREZOR"), 0);
    expect(toHex(other.seed)).not.toBe(toHex(deriveLmsInputs(master, 0).seed));
  });

  it("pins the v1 vectors for the reference phrase", () => {
    // Pinned once from this implementation; any change here is a derivation break.
    const k0 = deriveLmsInputs(master, 0);
    const k1 = deriveLmsInputs(master, 1);
    const reg = deriveLmsInputs(master, REGISTRY_KEY_INDEX);
    expect({ seed0: toHex(k0.seed), I0: toHex(k0.I), seed1: toHex(k1.seed), I1: toHex(k1.I), seedReg: toHex(reg.seed), IReg: toHex(reg.I) }).toMatchSnapshot();
  });

  it("rejects a master that is not 64 bytes and a k that is not a u32", () => {
    expect(() => deriveLmsInputs(new Uint8Array(32), 0)).toThrow();
    expect(() => deriveLmsInputs(master, -1)).toThrow();
    expect(() => deriveLmsInputs(master, 2 ** 32)).toThrow();
  });
});

describe("recovery", () => {
  it("finds the key index from the words and the vault's lms_pubkey", async () => {
    const master = mnemonicToMaster(REF_MNEMONIC);
    const k3 = LmsPrivateKey.generate(deriveKeyMaterial(master, 3, LMS_SHA256_M32_H5));
    const found = await recoverKey(master, k3.publicKey, { maxIndex: 8 });
    expect(found?.k).toBe(3);
    expect(toHex(found!.key.publicKey)).toBe(toHex(k3.publicKey));
  });

  it("returns null for a key that is not derived from these words", async () => {
    const master = mnemonicToMaster(REF_MNEMONIC);
    const stranger = LmsPrivateKey.generate(deriveKeyMaterial(mnemonicToMaster(REF_MNEMONIC, "x"), 0, LMS_SHA256_M32_H5));
    expect(await recoverKey(master, stranger.publicKey, { maxIndex: 4 })).toBeNull();
  });
});
