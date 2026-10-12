/**
 * Lamport Vault key derivation v1 (docs/SPEC-DERIVATION.md): 24 words -> master -> (SEED_k, I_k).
 */
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { generateMnemonic as scureGenerate, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { concat, equalBytes, u32str, utf8 } from "./bytes.ts";
import { type LmsKeyMaterial, LmsPrivateKey, parseLmsPublicKey } from "./lms.ts";
import { LMOTS_SHA256_N32_W4, LMS_SHA256_M32_H10 } from "./params.ts";

export const DERIVATION_VERSION = "v1";
export const SEED_DOMAIN = "lamport-vault/lms-seed/v1";
export const ID_DOMAIN = "lamport-vault/lms-id/v1";
/** The pq-registry commitment key uses this reserved index so it never collides with a vault key. */
export const REGISTRY_KEY_INDEX = 0xffffffff;
/** Recovery walks k = 0..RECOVERY_MAX_INDEX (inclusive) before giving up. */
export const RECOVERY_MAX_INDEX = 64;

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

/**
 * SEED_k = HMAC-SHA256(key = "lamport-vault/lms-seed/v1", msg = master || u32be(k))
 * I_k    = HMAC-SHA256(key = "lamport-vault/lms-id/v1",   msg = master || u32be(k))[0..16]
 */
export function deriveLmsInputs(master: Uint8Array, k: number): DerivedLmsInputs {
  if (master.length !== 64) throw new Error("master must be the 64-byte BIP-39 seed");
  if (!Number.isInteger(k) || k < 0 || k > 0xffffffff) throw new RangeError("k must be a u32");
  const msg = concat(master, u32str(k));
  const seed = hmac(sha256, utf8(SEED_DOMAIN), msg);
  const I = hmac(sha256, utf8(ID_DOMAIN), msg).slice(0, 16);
  return { seed, I };
}

/** Full key material for vault index k with the given typecodes (defaults: H10, W4). */
export function deriveKeyMaterial(
  master: Uint8Array,
  k: number,
  lmsType = LMS_SHA256_M32_H10,
  lmotsType = LMOTS_SHA256_N32_W4,
): LmsKeyMaterial {
  const { seed, I } = deriveLmsInputs(master, k);
  return { lmsType, lmotsType, seed, I };
}

/** Key material for the pq-registry commitment key (k = 0xFFFFFFFF). */
export function deriveRegistryKeyMaterial(
  master: Uint8Array,
  lmsType = LMS_SHA256_M32_H10,
  lmotsType = LMOTS_SHA256_N32_W4,
): LmsKeyMaterial {
  return deriveKeyMaterial(master, REGISTRY_KEY_INDEX, lmsType, lmotsType);
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
 * Recovery (SPEC-DERIVATION.md Section "Recovery procedure"): for k = 0, 1, ... derive
 * (SEED_k, I_k) and compare with the vault's `lms_pubkey`. `I_k` is part of the public key, so a
 * candidate is only expanded into a tree when its I matches; the full build then confirms the
 * root. Returns null if no k up to `maxIndex` matches.
 */
export async function recoverKey(
  master: Uint8Array,
  lmsPubkey: Uint8Array,
  opts: RecoverOptions = {},
): Promise<RecoveredKey | null> {
  const pub = parseLmsPublicKey(lmsPubkey);
  const max = opts.maxIndex ?? RECOVERY_MAX_INDEX;
  for (let k = 0; k <= max; k++) {
    const { seed, I } = deriveLmsInputs(master, k);
    if (!equalBytes(I, pub.I)) continue;
    const key = await LmsPrivateKey.generateAsync(
      { lmsType: pub.lmsType, lmotsType: pub.lmotsType, seed, I },
      opts.onProgress ? { onProgress: opts.onProgress } : {},
    );
    if (equalBytes(key.publicKey, lmsPubkey)) return { k, key };
  }
  return null;
}
