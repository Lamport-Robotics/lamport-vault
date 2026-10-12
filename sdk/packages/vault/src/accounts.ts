/**
 * Account layouts behind Anchor's 8-byte account discriminator, matching `programs/lamport-vault/src/state.rs`
 * and `programs/pq-registry/src/lib.rs`. `sig` is a Borsh `Vec<u8>` (u32 length prefix, always `sig_len`).
 * Encoders are provided alongside decoders so tests and mocks can build byte-exact account data.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { PublicKey } from "@solana/web3.js";
import { ByteReader, ByteWriter } from "./borsh.ts";
import { ACCOUNT } from "./discriminator.ts";

/** Current `Vault` layout version; the decoder refuses anything else. */
export const VAULT_ACCOUNT_VERSION = 2;
/** Current `Commitment` layout version; the decoder refuses anything else. */
export const COMMITMENT_ACCOUNT_VERSION = 2;
/** Most entries `used_keys` can hold (initial key + 255 rotations) in either account. */
export const MAX_USED_KEYS = 256;

export interface VaultAccount {
  version: number;
  bump: number;
  vaultId: Uint8Array;
  lmsPubkey: Uint8Array;
  nextQ: number;
  rotations: number;
  createdSlot: bigint;
  /** sha256 of every LMS public key the vault has had, oldest first; `usedKeys[0]` is the vault id */
  usedKeys: Uint8Array[];
}

/** The `used_keys` entry for a 56-byte LMS public key. */
export function usedKeyHash(lmsPubkey: Uint8Array): Uint8Array {
  if (lmsPubkey.length !== 56) throw new Error("lms_pubkey must be 56 bytes");
  return sha256(lmsPubkey);
}

/** True if `usedKeys` lists `lmsPubkey` (a Rotate to it would fail with KeyReused). */
export function hasUsedKey(usedKeys: Uint8Array[], lmsPubkey: Uint8Array): boolean {
  const h = usedKeyHash(lmsPubkey);
  return usedKeys.some((k) => k.length === 32 && k.every((b, i) => b === h[i]));
}

/** Vault::space(n): size of a Vault account holding `usedKeysCount` entries. */
export function vaultAccountSize(usedKeysCount: number): number {
  return 8 + 1 + 1 + 32 + 56 + 4 + 4 + 8 + 4 + 32 * usedKeysCount;
}
/** Size of a fresh vault (one used key). */
export const VAULT_ACCOUNT_SIZE = vaultAccountSize(1);

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
  /** sha256 of every key ever committed, oldest first */
  usedKeys: Uint8Array[];
}

/** Commitment::space(n): size of a Commitment holding `usedKeysCount` entries. */
export function commitmentAccountSize(usedKeysCount: number): number {
  return 8 + 1 + 1 + 32 + 1 + 56 + 4 + 4 + 8 + 8 + 4 + 32 * usedKeysCount;
}
/** Size of a fresh commitment (one used key). */
export const COMMITMENT_ACCOUNT_SIZE = commitmentAccountSize(1);
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

/** Borsh `Vec<[u8;32]>`: u32 count then the entries; at most MAX_USED_KEYS. */
function readUsedKeys(r: ByteReader, name: string): Uint8Array[] {
  const n = r.u32();
  if (n === 0 || n > MAX_USED_KEYS) throw new Error(`${name}: used_keys has ${n} entries (want 1..${MAX_USED_KEYS})`);
  const out: Uint8Array[] = [];
  for (let i = 0; i < n; i++) out.push(r.fixed(32));
  return out;
}

function writeUsedKeys(w: ByteWriter, keys: Uint8Array[]): ByteWriter {
  if (keys.length === 0 || keys.length > MAX_USED_KEYS) throw new RangeError(`used_keys must hold 1..${MAX_USED_KEYS} entries`);
  w.u32(keys.length);
  for (const k of keys) w.fixed(k, 32);
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
    nextQ: r.u32(),
    rotations: r.u32(),
    createdSlot: r.u64(),
    usedKeys: readUsedKeys(r, "Vault"),
  };
  r.finish();
  return v;
}

export function encodeVault(v: VaultAccount): Uint8Array {
  const w = new ByteWriter()
    .raw(ACCOUNT.vault)
    .u8(v.version)
    .u8(v.bump)
    .fixed(v.vaultId, 32)
    .fixed(v.lmsPubkey, 56)
    .u32(v.nextQ)
    .u32(v.rotations)
    .u64(v.createdSlot);
  return writeUsedKeys(w, v.usedKeys).bytes();
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
    usedKeys: readUsedKeys(r, "Commitment"),
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
  return writeUsedKeys(w, c.usedKeys).bytes();
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
