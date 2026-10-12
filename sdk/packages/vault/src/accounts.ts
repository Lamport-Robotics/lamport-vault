/**
 * Account layouts behind Anchor's 8-byte account discriminator, matching `programs/lamport-vault/src/state.rs`
 * and `programs/pq-registry/src/lib.rs`. `sig` is a Borsh `Vec<u8>` (u32 length prefix, always `sig_len`).
 * Encoders are provided alongside decoders so tests and mocks can build byte-exact account data.
 */
import { PublicKey } from "@solana/web3.js";
import { ByteReader, ByteWriter } from "./borsh.ts";
import { ACCOUNT } from "./discriminator.ts";

export interface VaultAccount {
  version: number;
  bump: number;
  vaultId: Uint8Array;
  lmsPubkey: Uint8Array;
  nextQ: number;
  rotations: number;
  createdSlot: bigint;
}

export const VAULT_ACCOUNT_SIZE = 8 + 1 + 1 + 32 + 56 + 4 + 4 + 8;

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
  createdSlot: bigint;
  updatedSlot: bigint;
}

export const COMMITMENT_ACCOUNT_SIZE = 8 + 1 + 1 + 32 + 1 + 56 + 4 + 8 + 8;
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

export function decodeVault(data: Uint8Array): VaultAccount {
  const r = new ByteReader(data);
  checkDiscriminator(r, ACCOUNT.vault, "Vault");
  const v: VaultAccount = {
    version: r.u8(),
    bump: r.u8(),
    vaultId: r.fixed(32),
    lmsPubkey: r.fixed(56),
    nextQ: r.u32(),
    rotations: r.u32(),
    createdSlot: r.u64(),
  };
  return v;
}

export function encodeVault(v: VaultAccount): Uint8Array {
  return new ByteWriter()
    .raw(ACCOUNT.vault)
    .u8(v.version)
    .u8(v.bump)
    .fixed(v.vaultId, 32)
    .fixed(v.lmsPubkey, 56)
    .u32(v.nextQ)
    .u32(v.rotations)
    .u64(v.createdSlot)
    .bytes();
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
  return {
    version: r.u8(),
    bump: r.u8(),
    owner: r.pubkey(),
    scheme: r.u8(),
    pqPubkey: r.fixed(56),
    nextQ: r.u32(),
    createdSlot: r.u64(),
    updatedSlot: r.u64(),
  };
}

export function encodeCommitment(c: CommitmentAccount): Uint8Array {
  return new ByteWriter()
    .raw(ACCOUNT.commitment)
    .u8(c.version)
    .u8(c.bump)
    .pubkey(c.owner)
    .u8(c.scheme)
    .fixed(c.pqPubkey, 56)
    .u32(c.nextQ)
    .u64(c.createdSlot)
    .u64(c.updatedSlot)
    .bytes();
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
