/**
 * Account layouts behind Anchor's 8-byte account discriminator, matching `programs/lamport-vault/src/state.rs`
 * and `programs/pq-registry/src/lib.rs`. `sig` is a Borsh `Vec<u8>` (u32 length prefix, always `sig_len`).
 * Encoders are provided alongside decoders so tests and mocks can build byte-exact account data.
 */
import { LMS_SHA256_M32_H10, LMS_SHA256_M32_H15, LMS_SHA256_M32_H5, lmsParams, parseLmsPublicKey } from "@lamport-robotics/lms";
import { sha256 } from "@noble/hashes/sha2.js";
import { PublicKey } from "@solana/web3.js";
import { ByteReader, ByteWriter } from "./borsh.ts";
import { ACCOUNT } from "./discriminator.ts";

/** Current `Vault` layout version; the decoder refuses anything else. */
export const VAULT_ACCOUNT_VERSION = 2;
/** Current `Commitment` layout version; the decoder refuses anything else. */
export const COMMITMENT_ACCOUNT_VERSION = 2;
/** A `used_keys` entry is `sha256(pubkey)[0..16]`. */
export const KEY_HASH_LEN = 16;
/** Most past keys a vault remembers; the next Rotate fails with `HistoryFull` (program `MAX_KEY_HISTORY`). */
export const VAULT_MAX_KEY_HISTORY = 128;
/** Most past keys a commitment remembers (registry `MAX_KEY_HISTORY`). */
export const COMMITMENT_MAX_KEY_HISTORY = 32;
/** LMS typecodes a vault accepts: H5, H10, H15 (the H20 bitmap would be 128 KB). */
export const VAULT_LMS_TYPES: readonly number[] = [LMS_SHA256_M32_H5, LMS_SHA256_M32_H10, LMS_SHA256_M32_H15];

export interface VaultAccount {
  version: number;
  bump: number;
  vaultId: Uint8Array;
  lmsPubkey: Uint8Array;
  /** leaves spent under the current key (bits set in `used`) */
  spent: number;
  /** how many times the key was replaced; part of the signed message */
  generation: number;
  createdSlot: bigint;
  /** used-leaf bitmap, 2^h / 8 bytes; bit q (byte q >> 3, bit q & 7) set = leaf q spent */
  used: Uint8Array;
  /** sha256[0..16] of every past LMS public key, oldest first (not the current one) */
  usedKeys: Uint8Array[];
}

/** The `used_keys` entry for a 56-byte public key: sha256(pubkey)[0..16]. */
export function usedKeyHash(pubkey: Uint8Array): Uint8Array {
  if (pubkey.length !== 56) throw new Error("pubkey must be 56 bytes");
  return sha256(pubkey).subarray(0, KEY_HASH_LEN);
}

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * True if `pubkey` is the account's current key or any past one: a Rotate / rotate_pq to it fails
 * with `KeyReused`.
 */
export function hasUsedKey(account: Pick<VaultAccount, "lmsPubkey" | "usedKeys"> | Pick<CommitmentAccount, "pqPubkey" | "usedKeys">, pubkey: Uint8Array): boolean {
  const current = "lmsPubkey" in account ? account.lmsPubkey : account.pqPubkey;
  if (bytesEqual(current, pubkey)) return true;
  const h = usedKeyHash(pubkey);
  return account.usedKeys.some((k) => bytesEqual(k, h));
}

/** Bitmap length for an LMS typecode: 2^h / 8 bytes (H5 4, H10 128, H15 4096). */
export function bitmapLength(lmsType: number): number {
  if (!VAULT_LMS_TYPES.includes(lmsType)) throw new Error(`LMS typecode ${lmsType} is not accepted by the vault`);
  return 2 ** lmsParams(lmsType).h / 8;
}

/** Vault::space: size of a Vault account for a key of `lmsType` with `history` past keys recorded. */
export function vaultAccountSize(lmsType: number, history = 0): number {
  return 8 + 1 + 1 + 32 + 56 + 4 + 4 + 8 + (4 + bitmapLength(lmsType)) + (4 + KEY_HASH_LEN * history);
}

/** Number of leaves of the vault's current key, 2^h. */
export function leafCount(vault: Pick<VaultAccount, "lmsPubkey">): number {
  return 2 ** lmsParams(parseLmsPublicKey(vault.lmsPubkey).lmsType).h;
}

/** Leaves still free under the current key. */
export function freeLeaves(vault: Pick<VaultAccount, "lmsPubkey" | "spent">): number {
  return leafCount(vault) - vault.spent;
}

/** Whether leaf `q` is spent on chain. Leaves outside the tree count as spent. */
export function isLeafUsed(vault: Pick<VaultAccount, "used">, q: number): boolean {
  if (!Number.isInteger(q) || q < 0) throw new RangeError(`bad leaf index ${q}`);
  const byte = vault.used[q >> 3];
  return byte === undefined || (byte & (1 << (q & 7))) !== 0;
}

/**
 * The smallest unspent leaf `q` with `q % lanes === lane`, or `undefined` when the lane is exhausted.
 * Lanes let several signers share one key without coordination: signer k of n only ever uses
 * leaves `q ≡ k (mod n)`. `skip` excludes leaves this process has already reserved.
 */
export function firstFreeLeaf(vault: Pick<VaultAccount, "used">, lane = 0, lanes = 1, skip?: (q: number) => boolean): number | undefined {
  if (!Number.isInteger(lanes) || lanes < 1) throw new RangeError(`lanes must be >= 1, got ${lanes}`);
  if (!Number.isInteger(lane) || lane < 0 || lane >= lanes) throw new RangeError(`lane must be in 0..${lanes - 1}, got ${lane}`);
  const total = vault.used.length * 8;
  for (let q = lane; q < total; q += lanes) {
    if (!isLeafUsed(vault, q) && !skip?.(q)) return q;
  }
  return undefined;
}

export interface SigBufferAccount {
  version: number;
  bump: number;
  vault: PublicKey;
  payer: PublicKey;
  nonce: bigint;
  action: Uint8Array;
  sigLen: number;
  filled: number;
  /** sig_len bytes; only the first `filled` are meaningful */
  sig: Uint8Array;
}

export interface CommitmentAccount {
  version: number;
  bump: number;
  owner: PublicKey;
  scheme: number;
  pqPubkey: Uint8Array;
  nextQ: number;
  /** how many times rotate_pq ran; part of the signed message */
  generation: number;
  createdSlot: bigint;
  updatedSlot: bigint;
  /** sha256[0..16] of every past committed key, oldest first (not the current one) */
  usedKeys: Uint8Array[];
}

/** Commitment::space: size of a Commitment with `history` past keys recorded. */
export function commitmentAccountSize(history = 0): number {
  return 8 + 1 + 1 + 32 + 1 + 56 + 4 + 4 + 8 + 8 + (4 + KEY_HASH_LEN * history);
}
/** Size of a fresh commitment (no past keys). */
export const COMMITMENT_ACCOUNT_SIZE = commitmentAccountSize(0);
export const SCHEME_LMS_SHA256 = 1;

/** Registry staging buffer for `rotate_pq` (`PqSigBuffer`). */
export interface PqSigBufferAccount {
  version: number;
  bump: number;
  owner: PublicKey;
  payer: PublicKey;
  nonce: bigint;
  newPqPubkey: Uint8Array;
  sigLen: number;
  filled: number;
  sig: Uint8Array;
}

function checkDiscriminator(r: ByteReader, want: Uint8Array, name: string): void {
  const got = r.fixed(8);
  for (let i = 0; i < 8; i++) {
    if (got[i] !== want[i]) throw new Error(`not a ${name} account (discriminator mismatch)`);
  }
}

function checkVersion(got: number, want: number, name: string): void {
  if (got !== want) throw new Error(`${name} layout version ${got} is not supported (want ${want})`);
}

/** Borsh `Vec<[u8;16]>`: u32 count then the entries; at most `max`. */
function readUsedKeys(r: ByteReader, name: string, max: number): Uint8Array[] {
  const n = r.u32();
  if (n > max) throw new Error(`${name}: used_keys has ${n} entries (max ${max})`);
  const out: Uint8Array[] = [];
  for (let i = 0; i < n; i++) out.push(r.fixed(KEY_HASH_LEN));
  return out;
}

function writeUsedKeys(w: ByteWriter, keys: Uint8Array[], max: number): ByteWriter {
  if (keys.length > max) throw new RangeError(`used_keys must hold at most ${max} entries`);
  w.u32(keys.length);
  for (const k of keys) w.fixed(k, KEY_HASH_LEN);
  return w;
}

export function decodeVault(data: Uint8Array): VaultAccount {
  const r = new ByteReader(data);
  checkDiscriminator(r, ACCOUNT.vault, "Vault");
  const version = r.u8();
  checkVersion(version, VAULT_ACCOUNT_VERSION, "Vault");
  const v: VaultAccount = {
    version,
    bump: r.u8(),
    vaultId: r.fixed(32),
    lmsPubkey: r.fixed(56),
    spent: r.u32(),
    generation: r.u32(),
    createdSlot: r.u64(),
    used: r.vecU8(),
    usedKeys: readUsedKeys(r, "Vault", VAULT_MAX_KEY_HISTORY),
  };
  r.finish();
  const want = bitmapLength(parseLmsPublicKey(v.lmsPubkey).lmsType);
  if (v.used.length !== want) throw new Error(`Vault: bitmap is ${v.used.length} bytes, want ${want} for this key`);
  return v;
}

export function encodeVault(v: VaultAccount): Uint8Array {
  if (v.used.length !== bitmapLength(parseLmsPublicKey(v.lmsPubkey).lmsType)) throw new RangeError("used bitmap length does not match the key's height");
  const w = new ByteWriter()
    .raw(ACCOUNT.vault)
    .u8(v.version)
    .u8(v.bump)
    .fixed(v.vaultId, 32)
    .fixed(v.lmsPubkey, 56)
    .u32(v.spent)
    .u32(v.generation)
    .u64(v.createdSlot)
    .vecU8(v.used);
  return writeUsedKeys(w, v.usedKeys, VAULT_MAX_KEY_HISTORY).bytes();
}

export function decodeSigBuffer(data: Uint8Array): SigBufferAccount {
  const r = new ByteReader(data);
  checkDiscriminator(r, ACCOUNT.sigBuffer, "SigBuffer");
  const version = r.u8();
  const bump = r.u8();
  const vault = r.pubkey();
  const payer = r.pubkey();
  const nonce = r.u64();
  const action = r.vecU8();
  const sigLen = r.u16();
  const filled = r.u16();
  const sig = r.vecU8();
  if (sig.length !== sigLen) throw new Error("SigBuffer: sig vector length differs from sig_len");
  return { version, bump, vault, payer, nonce, action, sigLen, filled, sig };
}

export function encodeSigBuffer(b: SigBufferAccount): Uint8Array {
  if (b.sig.length !== b.sigLen) throw new Error("sig must be sig_len bytes");
  return new ByteWriter()
    .raw(ACCOUNT.sigBuffer)
    .u8(b.version)
    .u8(b.bump)
    .pubkey(b.vault)
    .pubkey(b.payer)
    .u64(b.nonce)
    .vecU8(b.action)
    .u16(b.sigLen)
    .u16(b.filled)
    .vecU8(b.sig)
    .bytes();
}

/** Space a SigBuffer needs for an action of `actionLen` bytes and a signature of `sigLen` bytes. */
export function sigBufferSize(actionLen: number, sigLen: number): number {
  return 8 + 1 + 1 + 32 + 32 + 8 + (4 + actionLen) + 2 + 2 + (4 + sigLen);
}

export function decodeCommitment(data: Uint8Array): CommitmentAccount {
  const r = new ByteReader(data);
  checkDiscriminator(r, ACCOUNT.commitment, "Commitment");
  const version = r.u8();
  checkVersion(version, COMMITMENT_ACCOUNT_VERSION, "Commitment");
  const c: CommitmentAccount = {
    version,
    bump: r.u8(),
    owner: r.pubkey(),
    scheme: r.u8(),
    pqPubkey: r.fixed(56),
    nextQ: r.u32(),
    generation: r.u32(),
    createdSlot: r.u64(),
    updatedSlot: r.u64(),
    usedKeys: readUsedKeys(r, "Commitment", COMMITMENT_MAX_KEY_HISTORY),
  };
  r.finish();
  return c;
}

export function encodeCommitment(c: CommitmentAccount): Uint8Array {
  const w = new ByteWriter()
    .raw(ACCOUNT.commitment)
    .u8(c.version)
    .u8(c.bump)
    .pubkey(c.owner)
    .u8(c.scheme)
    .fixed(c.pqPubkey, 56)
    .u32(c.nextQ)
    .u32(c.generation)
    .u64(c.createdSlot)
    .u64(c.updatedSlot);
  return writeUsedKeys(w, c.usedKeys, COMMITMENT_MAX_KEY_HISTORY).bytes();
}

export function decodePqSigBuffer(data: Uint8Array): PqSigBufferAccount {
  const r = new ByteReader(data);
  checkDiscriminator(r, ACCOUNT.pqSigBuffer, "PqSigBuffer");
  const version = r.u8();
  const bump = r.u8();
  const owner = r.pubkey();
  const payer = r.pubkey();
  const nonce = r.u64();
  const newPqPubkey = r.fixed(56);
  const sigLen = r.u16();
  const filled = r.u16();
  const sig = r.vecU8();
  if (sig.length !== sigLen) throw new Error("PqSigBuffer: sig vector length differs from sig_len");
  return { version, bump, owner, payer, nonce, newPqPubkey, sigLen, filled, sig };
}

export function encodePqSigBuffer(b: PqSigBufferAccount): Uint8Array {
  if (b.sig.length !== b.sigLen) throw new Error("sig must be sig_len bytes");
  return new ByteWriter()
    .raw(ACCOUNT.pqSigBuffer)
    .u8(b.version)
    .u8(b.bump)
    .pubkey(b.owner)
    .pubkey(b.payer)
    .u64(b.nonce)
    .fixed(b.newPqPubkey, 56)
    .u16(b.sigLen)
    .u16(b.filled)
    .vecU8(b.sig)
    .bytes();
}

/** Space a PqSigBuffer needs for a signature of `sigLen` bytes (PqSigBuffer::space). */
export function pqSigBufferSize(sigLen: number): number {
  return 8 + 1 + 1 + 32 + 32 + 8 + 56 + 2 + 2 + (4 + sigLen);
}
