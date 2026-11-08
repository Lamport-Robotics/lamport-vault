import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import { concat, fromHex, toHex, u32str, utf8 } from "../src/bytes.ts";
import {
  base58Decode,
  base58Encode,
  CLUSTERS,
  derivationInfo,
  DERIVATION_VERSION,
  deriveKeyMaterial,
  deriveLmsInputs,
  deriveRegistryKeyMaterial,
  generateMnemonic,
  ID_DOMAIN,
  ID_INFO_LABEL,
  isValidMnemonic,
  mnemonicToMaster,
  recoverKey,
  REGISTRY_KEY_INDEX,
  SEED_DOMAIN,
  SEED_INFO_LABEL,
  toBytes32,
} from "../src/derive.ts";
import { LmsPrivateKey } from "../src/lms.ts";
import { LMOTS_SHA256_N32_W4, LMS_SHA256_M32_H5 } from "../src/params.ts";

// The BIP-39 reference vector (Trezor test vectors, entropy 0x00..00, passphrase "TREZOR").
const REF_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const REF_SEED_TREZOR =
  "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

// Program ids as declared in programs/ (the vault package re-exports them; this package has no dependency on it).
const VAULT_PROGRAM_ID = "B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH";
const REGISTRY_PROGRAM_ID = "48J2BtWFjEUbGPYf1yMPBkHxpy4dLo69gK2znQR2q2ad";
const DEVNET = { genesisHash: CLUSTERS.devnet.genesisHash, programId: VAULT_PROGRAM_ID };
const MAINNET = { genesisHash: CLUSTERS.mainnet.genesisHash, programId: VAULT_PROGRAM_ID };

interface DerivationVector {
  name: string;
  master_hex: string;
  genesis_hash: string;
  genesis_hash_hex: string;
  program_id: string;
  program_id_hex: string;
  k: number;
  seed_info_hex: string;
  id_info_hex: string;
  seed_hex: string;
  I_hex: string;
  lms_type: number;
  lmots_type: number;
  public_key_hex: string;
}
const kat = JSON.parse(readFileSync(fileURLToPath(new URL("../../../../kat/derivation_v2.json", import.meta.url)), "utf8")) as {
  version: string;
  formula: { registry_key_index: number; seed_salt_hex: string; id_salt_hex: string };
  vectors: DerivationVector[];
};

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

describe("base58 and scopes", () => {
  it("decodes the cluster genesis hashes to 32 bytes and round-trips", () => {
    for (const c of Object.values(CLUSTERS)) {
      const bytes = base58Decode(c.genesisHash);
      expect(bytes.length).toBe(32);
      expect(base58Encode(bytes)).toBe(c.genesisHash);
    }
    expect(CLUSTERS.devnet.genesisHash).toBe("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG");
    expect(CLUSTERS.mainnet.genesisHash).toBe("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d");
    expect(toHex(base58Decode("11111111111111111111111111111111"))).toBe("00".repeat(32));
    expect(base58Encode(new Uint8Array(32))).toBe("11111111111111111111111111111111");
    expect(() => base58Decode("0OIl")).toThrow(/base58/);
  });

  it("takes a base58 string, raw bytes or a toBytes() object as a scope part", () => {
    const bytes = base58Decode(CLUSTERS.devnet.genesisHash);
    expect(toHex(toBytes32(CLUSTERS.devnet.genesisHash))).toBe(toHex(bytes));
    expect(toHex(toBytes32(bytes))).toBe(toHex(bytes));
    expect(toHex(toBytes32({ toBytes: () => bytes }))).toBe(toHex(bytes));
    expect(() => toBytes32(new Uint8Array(31))).toThrow(/32 bytes/);
    expect(() => deriveLmsInputs(mnemonicToMaster(REF_MNEMONIC), 0, { genesisHash: "abc", programId: VAULT_PROGRAM_ID })).toThrow(/32 bytes/);
  });
});

describe("SEED_k / I_k (v2)", () => {
  const master = mnemonicToMaster(REF_MNEMONIC);

  it("is HKDF-SHA256 over master with the v2 salts and genesis || program || u32be(k) || label as info", () => {
    expect(DERIVATION_VERSION).toBe("v2");
    expect(SEED_DOMAIN).toBe("lamport-vault/lms-seed/v2");
    expect(ID_DOMAIN).toBe("lamport-vault/lms-id/v2");
    const genesis = base58Decode(CLUSTERS.devnet.genesisHash);
    const program = base58Decode(VAULT_PROGRAM_ID);
    for (const k of [0, 1, 2, 65535, REGISTRY_KEY_INDEX]) {
      const a = deriveLmsInputs(master, k, DEVNET);
      const b = deriveLmsInputs(master, k, DEVNET);
      expect(toHex(a.seed)).toBe(toHex(b.seed));
      expect(toHex(a.I)).toBe(toHex(b.I));
      const seedInfo = concat(genesis, program, u32str(k), utf8(SEED_INFO_LABEL));
      const idInfo = concat(genesis, program, u32str(k), utf8(ID_INFO_LABEL));
      expect(toHex(derivationInfo(DEVNET, k, SEED_INFO_LABEL))).toBe(toHex(seedInfo));
      expect(toHex(derivationInfo(DEVNET, k, ID_INFO_LABEL))).toBe(toHex(idInfo));
      expect(seedInfo.length).toBe(32 + 32 + 4 + 4);
      expect(toHex(a.seed)).toBe(toHex(hkdf(sha256, master, utf8(SEED_DOMAIN), seedInfo, 32)));
      expect(toHex(a.I)).toBe(toHex(hkdf(sha256, master, utf8(ID_DOMAIN), idInfo, 16)));
      expect(a.seed.length).toBe(32);
      expect(a.I.length).toBe(16);
    }
  });

  it("differs across k, passphrases, clusters, programs, and from the registry index", () => {
    const seen = new Set<string>();
    const add = (x: Uint8Array) => {
      expect(seen.has(toHex(x))).toBe(false);
      seen.add(toHex(x));
    };
    for (let k = 0; k < 16; k++) {
      const { seed, I } = deriveLmsInputs(master, k, DEVNET);
      add(seed);
      add(I);
    }
    const reg = deriveRegistryKeyMaterial(master, { genesisHash: CLUSTERS.devnet.genesisHash, programId: REGISTRY_PROGRAM_ID });
    add(reg.seed);
    add(reg.I);
    // the registry index under the vault program is yet another key (not what any client derives, but distinct)
    const regUnderVault = deriveLmsInputs(master, REGISTRY_KEY_INDEX, DEVNET);
    add(regUnderVault.seed);
    add(regUnderVault.I);
    const main = deriveLmsInputs(master, 0, MAINNET);
    add(main.seed);
    add(main.I);
    const otherProgram = deriveLmsInputs(master, 0, { genesisHash: CLUSTERS.devnet.genesisHash, programId: REGISTRY_PROGRAM_ID });
    add(otherProgram.seed);
    add(otherProgram.I);
    const other = deriveLmsInputs(mnemonicToMaster(REF_MNEMONIC, "TREZOR"), 0, DEVNET);
    add(other.seed);
    add(other.I);
  });

  it("matches every vector in kat/derivation_v2.json (SEED, I, H5 public key)", () => {
    expect(kat.version).toBe("v2");
    expect(kat.formula.registry_key_index).toBe(REGISTRY_KEY_INDEX);
    expect(kat.formula.seed_salt_hex).toBe(toHex(utf8(SEED_DOMAIN)));
    expect(kat.formula.id_salt_hex).toBe(toHex(utf8(ID_DOMAIN)));
    expect(kat.vectors.length).toBeGreaterThanOrEqual(6);
    const clusters = new Set(kat.vectors.map((v) => v.genesis_hash));
    expect(clusters.has(CLUSTERS.devnet.genesisHash)).toBe(true);
    expect(clusters.has(CLUSTERS.mainnet.genesisHash)).toBe(true);
    expect(kat.vectors.some((v) => v.k === REGISTRY_KEY_INDEX && v.program_id === REGISTRY_PROGRAM_ID)).toBe(true);
    for (const v of kat.vectors) {
      const scope = { genesisHash: v.genesis_hash, programId: v.program_id };
      expect(toHex(base58Decode(v.genesis_hash))).toBe(v.genesis_hash_hex);
      expect(toHex(base58Decode(v.program_id))).toBe(v.program_id_hex);
      expect(toHex(derivationInfo(scope, v.k, SEED_INFO_LABEL))).toBe(v.seed_info_hex);
      expect(toHex(derivationInfo(scope, v.k, ID_INFO_LABEL))).toBe(v.id_info_hex);
      const { seed, I } = deriveLmsInputs(fromHex(v.master_hex), v.k, scope);
      expect(toHex(seed), v.name).toBe(v.seed_hex);
      expect(toHex(I), v.name).toBe(v.I_hex);
      expect(v.lms_type).toBe(LMS_SHA256_M32_H5);
      expect(v.lmots_type).toBe(LMOTS_SHA256_N32_W4);
      const key = LmsPrivateKey.generate({ lmsType: v.lms_type, lmotsType: v.lmots_type, seed, I });
      expect(toHex(key.publicKey), v.name).toBe(v.public_key_hex);
    }
  });

  it("rejects a master that is not 64 bytes and a k that is not a u32", () => {
    expect(() => deriveLmsInputs(new Uint8Array(32), 0, DEVNET)).toThrow();
    expect(() => deriveLmsInputs(master, -1, DEVNET)).toThrow();
    expect(() => deriveLmsInputs(master, 2 ** 32, DEVNET)).toThrow();
  });
});

describe("recovery", () => {
  it("finds the key index from the words, the scope and the vault's lms_pubkey", async () => {
    const master = mnemonicToMaster(REF_MNEMONIC);
    const k3 = LmsPrivateKey.generate(deriveKeyMaterial(master, 3, DEVNET, LMS_SHA256_M32_H5));
    const found = await recoverKey(master, k3.publicKey, DEVNET, { maxIndex: 8 });
    expect(found?.k).toBe(3);
    expect(toHex(found!.key.publicKey)).toBe(toHex(k3.publicKey));
  });

  it("finds a key far past the first few indices with the default limit", async () => {
    const master = mnemonicToMaster(REF_MNEMONIC);
    const k300 = LmsPrivateKey.generate(deriveKeyMaterial(master, 300, DEVNET, LMS_SHA256_M32_H5));
    expect((await recoverKey(master, k300.publicKey, DEVNET))?.k).toBe(300);
  });

  it("returns null for a key that is not derived from these words, or from another cluster or program", async () => {
    const master = mnemonicToMaster(REF_MNEMONIC);
    const stranger = LmsPrivateKey.generate(deriveKeyMaterial(mnemonicToMaster(REF_MNEMONIC, "x"), 0, DEVNET, LMS_SHA256_M32_H5));
    expect(await recoverKey(master, stranger.publicKey, DEVNET, { maxIndex: 4 })).toBeNull();
    const onMainnet = LmsPrivateKey.generate(deriveKeyMaterial(master, 0, MAINNET, LMS_SHA256_M32_H5));
    expect(await recoverKey(master, onMainnet.publicKey, DEVNET, { maxIndex: 4 })).toBeNull();
    expect((await recoverKey(master, onMainnet.publicKey, MAINNET, { maxIndex: 4 }))?.k).toBe(0);
    const underRegistry = LmsPrivateKey.generate(deriveKeyMaterial(master, 0, { ...DEVNET, programId: REGISTRY_PROGRAM_ID }, LMS_SHA256_M32_H5));
    expect(await recoverKey(master, underRegistry.publicKey, DEVNET, { maxIndex: 4 })).toBeNull();
  });
});
