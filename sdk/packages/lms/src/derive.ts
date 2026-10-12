/**
 * Lamport Vault key derivation v2 (docs/SPEC-DERIVATION.md): 24 words -> master -> (SEED_k, I_k),
 * bound to a cluster (its genesis hash) and a program id with HKDF-SHA256.
 *
 *   SEED_k = HKDF-SHA256(ikm = master, salt = "lamport-vault/lms-seed/v2",
 *                        info = genesis_hash[32] || program_id[32] || u32be(k) || "seed")[0..32]
 *   I_k    = HKDF-SHA256(ikm = master, salt = "lamport-vault/lms-id/v2",
 *                        info = genesis_hash[32] || program_id[32] || u32be(k) || "id")[0..16]
 *
 * There is no default cluster or program: every derivation names its {@link DerivationScope}.
 */
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { generateMnemonic as scureGenerate, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { concat, equalBytes, u32str, utf8 } from "./bytes.ts";
import { type LmsKeyMaterial, LmsPrivateKey, parseLmsPublicKey } from "./lms.ts";
import { LMOTS_SHA256_N32_W4, LMS_SHA256_M32_H10 } from "./params.ts";

export const DERIVATION_VERSION = "v2";
/** HKDF salt of `SEED_k`. */
export const SEED_DOMAIN = "lamport-vault/lms-seed/v2";
/** HKDF salt of `I_k`. */
export const ID_DOMAIN = "lamport-vault/lms-id/v2";
/** Trailing label of the HKDF info for `SEED_k`. */
export const SEED_INFO_LABEL = "seed";
/** Trailing label of the HKDF info for `I_k`. */
export const ID_INFO_LABEL = "id";
/** The pq-registry commitment key uses this reserved index so it never collides with a vault key. */
export const REGISTRY_KEY_INDEX = 0xffffffff;
/** Recovery walks k = 0..RECOVERY_MAX_INDEX (inclusive) before giving up. */
export const RECOVERY_MAX_INDEX = 64;

/** A Solana cluster, identified by its genesis hash (base58 of 32 bytes). */
export interface Cluster {
  readonly name: string;
  readonly genesisHash: string;
}

/** The clusters this derivation is defined for. Any other cluster is named by its genesis hash. */
export const CLUSTERS = {
  devnet: { name: "devnet", genesisHash: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG" },
  mainnet: { name: "mainnet-beta", genesisHash: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d" },
} as const satisfies Record<string, Cluster>;

/** Anything that names 32 bytes: a base58 string, the bytes, or an object with `toBytes()` (a web3.js PublicKey). */
export type Bytes32Like = string | Uint8Array | { toBytes(): Uint8Array };

/** What a derived key is bound to: the cluster (genesis hash) and the program the key will own an account under. */
export interface DerivationScope {
  /** The cluster's genesis hash: `CLUSTERS.devnet.genesisHash`, `CLUSTERS.mainnet.genesisHash`, or `getGenesisHash()`. */
  readonly genesisHash: Bytes32Like;
  /** The vault program id for vault keys, the registry program id for the registry key. */
  readonly programId: Bytes32Like;
}

/** A fresh BIP-39 phrase; 256 bits = 24 words (default). */
export function generateMnemonic(strength: 128 | 160 | 192 | 224 | 256 = 256): string {
  return scureGenerate(english, strength);
}

export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic, english);
}

/** The 64-byte BIP-39 seed: PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic" || passphrase. */
export function mnemonicToMaster(mnemonic: string, passphrase = ""): Uint8Array {
  if (!validateMnemonic(mnemonic, english)) throw new Error("invalid BIP-39 mnemonic");
  return mnemonicToSeedSync(mnemonic, passphrase);
}

export interface DerivedLmsInputs {
  /** 32 bytes */
  readonly seed: Uint8Array;
  /** 16 bytes */
  readonly I: Uint8Array;
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Decodes a base58 string (Bitcoin alphabet) into bytes. */
export function base58Decode(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array(0);
  const bytes: number[] = [0];
  for (const ch of s) {
    let carry = B58.indexOf(ch);
    if (carry < 0) throw new Error(`invalid base58 character ${JSON.stringify(ch)}`);
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i]! * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let zeros = 0;
  while (zeros < s.length - 1 && s[zeros] === "1") zeros++;
  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[zeros + i] = bytes[bytes.length - 1 - i]!;
  return out;
}

/** Encodes bytes as base58 (Bitcoin alphabet). */
export function base58Encode(bytes: Uint8Array): string {
  const digits: number[] = [0];
  for (const b of bytes) {
    let carry = b;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i]! << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "";
  for (let i = 0; i < bytes.length - 1 && bytes[i] === 0; i++) out += "1";
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]!];
  return out;
}

/** Normalises a {@link Bytes32Like} to exactly 32 bytes. */
export function toBytes32(x: Bytes32Like, what = "value"): Uint8Array {
  const bytes = typeof x === "string" ? base58Decode(x) : x instanceof Uint8Array ? x : x.toBytes();
  if (bytes.length !== 32) throw new Error(`${what} must be 32 bytes, got ${bytes.length}`);
  return bytes;
}

/** `genesis_hash[32] || program_id[32] || u32be(k) || label`: the HKDF info of one derivation. */
export function derivationInfo(scope: DerivationScope, k: number, label: string): Uint8Array {
  if (!Number.isInteger(k) || k < 0 || k > 0xffffffff) throw new RangeError("k must be a u32");
  return concat(toBytes32(scope.genesisHash, "genesisHash"), toBytes32(scope.programId, "programId"), u32str(k), utf8(label));
}

/**
 * SEED_k = HKDF-SHA256(ikm = master, salt = SEED_DOMAIN, info = genesis || program || u32be(k) || "seed")[0..32]
 * I_k    = HKDF-SHA256(ikm = master, salt = ID_DOMAIN,   info = genesis || program || u32be(k) || "id")[0..16]
 */
export function deriveLmsInputs(master: Uint8Array, k: number, scope: DerivationScope): DerivedLmsInputs {
  if (master.length !== 64) throw new Error("master must be the 64-byte BIP-39 seed");
  const seed = hkdf(sha256, master, utf8(SEED_DOMAIN), derivationInfo(scope, k, SEED_INFO_LABEL), 32);
  const I = hkdf(sha256, master, utf8(ID_DOMAIN), derivationInfo(scope, k, ID_INFO_LABEL), 16);
  return { seed, I };
}

/** Full key material for vault index k under `scope` with the given typecodes (defaults: H10, W4). */
export function deriveKeyMaterial(
  master: Uint8Array,
  k: number,
  scope: DerivationScope,
  lmsType = LMS_SHA256_M32_H10,
  lmotsType = LMOTS_SHA256_N32_W4,
): LmsKeyMaterial {
  const { seed, I } = deriveLmsInputs(master, k, scope);
  return { lmsType, lmotsType, seed, I };
}

/**
 * Key material for the pq-registry commitment key: index `REGISTRY_KEY_INDEX` under `scope`,
 * whose `programId` must be the registry program's.
 */
export function deriveRegistryKeyMaterial(
  master: Uint8Array,
  scope: DerivationScope,
  lmsType = LMS_SHA256_M32_H10,
  lmotsType = LMOTS_SHA256_N32_W4,
): LmsKeyMaterial {
  return deriveKeyMaterial(master, REGISTRY_KEY_INDEX, scope, lmsType, lmotsType);
}

export interface RecoverOptions {
  /** Highest k tried, inclusive. Default 64. */
  maxIndex?: number;
  /** Progress for the tree build of a matching candidate. */
  onProgress?: (done: number, total: number) => void;
}

export interface RecoveredKey {
  readonly k: number;
  readonly key: LmsPrivateKey;
}

/**
 * Recovery (SPEC-DERIVATION.md "Recovery procedure"): for k = 0, 1, ... derive (SEED_k, I_k)
 * under `scope` and compare with the vault's `lms_pubkey`. `I_k` is part of the public key, so a
 * candidate is only expanded into a tree when its I matches; the full build then confirms the
 * root. Returns null if no k up to `maxIndex` matches. A vault on another cluster, or under
 * another program id, is never matched: the scope is part of the key.
 */
export async function recoverKey(
  master: Uint8Array,
  lmsPubkey: Uint8Array,
  scope: DerivationScope,
  opts: RecoverOptions = {},
): Promise<RecoveredKey | null> {
  const pub = parseLmsPublicKey(lmsPubkey);
  const max = opts.maxIndex ?? RECOVERY_MAX_INDEX;
  for (let k = 0; k <= max; k++) {
    const { seed, I } = deriveLmsInputs(master, k, scope);
    if (!equalBytes(I, pub.I)) continue;
    const key = await LmsPrivateKey.generateAsync(
      { lmsType: pub.lmsType, lmotsType: pub.lmotsType, seed, I },
      opts.onProgress ? { onProgress: opts.onProgress } : {},
    );
    if (equalBytes(key.publicKey, lmsPubkey)) return { k, key };
  }
  return null;
}
