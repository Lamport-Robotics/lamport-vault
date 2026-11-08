/**
 * Instruction builders for `pq-registry`, following `programs/pq-registry/src/lib.rs`.
 *
 * `commit(pq_pubkey)` is a plain classical-signer instruction. `rotate_pq` needs a 2.3-2.8 KB LMS
 * signature, which no single transaction can carry, so it is staged in a `PqSigBuffer` PDA
 * `["pqsig", owner, payer, nonce_le_u64]` like the vault's SigBuffer (without a first chunk in `open`):
 *
 *   commit(pq_pubkey)                            owner(s) payer(ws) commitment(w) system_program
 *   open_pq_buffer(nonce, new_pq_pubkey, sig_len, issued_slot, expiry_slot)
 *                                                payer(ws) commitment buffer(w) system_program
 *   write_pq_sig(offset, chunk)                  payer(s) buffer(w)
 *   close_pq_buffer()                            payer(ws) buffer(w)
 *   rotate_pq()                                  commitment(w) buffer(w) payer(w)
 */
import { ComputeBudgetProgram, PublicKey, SystemProgram, TransactionInstruction, type AccountMeta } from "@solana/web3.js";
import { checkValidityWindow, type ValidityWindow } from "./action.ts";
import { ByteWriter } from "./borsh.ts";
import { chunkSignature, MAX_CHUNK_BYTES, type SigChunk } from "./chunk.ts";
import { IX } from "./discriminator.ts";
import { EXECUTE_COMPUTE_UNITS } from "./instructions.ts";
import { findCommitmentPda, findPqSigBufferPda } from "./pda.ts";

const w = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: false, isWritable: true });
const ws = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: true, isWritable: true });
const s = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: true, isWritable: false });
const r = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: false, isWritable: false });

export function commitInstruction(p: { programId: PublicKey; owner: PublicKey; payer?: PublicKey; pqPubkey: Uint8Array }): {
  instruction: TransactionInstruction;
  commitment: PublicKey;
} {
  if (p.pqPubkey.length !== 56) throw new Error("pq_pubkey must be 56 bytes");
  const commitment = findCommitmentPda(p.programId, p.owner).address;
  const payer = p.payer ?? p.owner;
  const data = new ByteWriter().raw(IX.commit).fixed(p.pqPubkey, 56).bytes();
  return {
    commitment,
    instruction: new TransactionInstruction({
      programId: p.programId,
      keys: [payer.equals(p.owner) ? ws(p.owner) : s(p.owner), ws(payer), w(commitment), r(SystemProgram.programId)],
      data: Buffer.from(data),
    }),
  };
}

export interface OpenPqBufferParams {
  programId: PublicKey;
  owner: PublicKey;
  payer: PublicKey;
  nonce: bigint;
  newPqPubkey: Uint8Array;
  sigLen: number;
  /** The validity window the LMS signature covers (part of the registry message). */
  window: ValidityWindow;
}

export function openPqBufferInstruction(p: OpenPqBufferParams): { instruction: TransactionInstruction; buffer: PublicKey; commitment: PublicKey } {
  if (p.newPqPubkey.length !== 56) throw new Error("pq_pubkey must be 56 bytes");
  checkValidityWindow(p.window);
  const commitment = findCommitmentPda(p.programId, p.owner).address;
  const buffer = findPqSigBufferPda(p.programId, p.owner, p.payer, p.nonce).address;
  const data = new ByteWriter()
    .raw(IX.openPqBuffer)
    .u64(p.nonce)
    .fixed(p.newPqPubkey, 56)
    .u16(p.sigLen)
    .u64(p.window.issuedSlot)
    .u64(p.window.expirySlot)
    .bytes();
  return {
    buffer,
    commitment,
    instruction: new TransactionInstruction({
      programId: p.programId,
      keys: [ws(p.payer), r(commitment), w(buffer), r(SystemProgram.programId)],
      data: Buffer.from(data),
    }),
  };
}

export function writePqSigInstruction(p: { programId: PublicKey; buffer: PublicKey; payer: PublicKey; offset: number; chunk: Uint8Array }): TransactionInstruction {
  if (p.chunk.length === 0 || p.chunk.length > MAX_CHUNK_BYTES) throw new Error(`chunk must be 1..${MAX_CHUNK_BYTES} bytes`);
  const data = new ByteWriter().raw(IX.writePqSig).u16(p.offset).vecU8(p.chunk).bytes();
  return new TransactionInstruction({
    programId: p.programId,
    keys: [s(p.payer), w(p.buffer)],
    data: Buffer.from(data),
  });
}

export function closePqBufferInstruction(p: { programId: PublicKey; buffer: PublicKey; payer: PublicKey }): TransactionInstruction {
  return new TransactionInstruction({
    programId: p.programId,
    keys: [ws(p.payer), w(p.buffer)],
    data: Buffer.from(IX.closePqBuffer),
  });
}

export function rotatePqInstruction(p: { programId: PublicKey; commitment: PublicKey; buffer: PublicKey; payer: PublicKey }): TransactionInstruction {
  return new TransactionInstruction({
    programId: p.programId,
    keys: [w(p.commitment), w(p.buffer), w(p.payer)],
    data: Buffer.from(IX.rotatePq),
  });
}

export interface StagedRotatePq {
  commitment: PublicKey;
  buffer: PublicKey;
  open: TransactionInstruction;
  writes: TransactionInstruction[];
  chunks: SigChunk[];
  rotate: TransactionInstruction[];
  /** One entry per transaction, in order: [open], [write]..., [compute budget, rotate_pq]. */
  transactions: TransactionInstruction[][];
}

export function buildStagedRotatePq(p: {
  programId: PublicKey;
  owner: PublicKey;
  payer: PublicKey;
  nonce: bigint;
  newPqPubkey: Uint8Array;
  /** The window the signature was made over. */
  window: ValidityWindow;
  signature: Uint8Array;
  chunkSize?: number;
  computeUnits?: number;
}): StagedRotatePq {
  const { instruction: open, buffer, commitment } = openPqBufferInstruction({
    programId: p.programId,
    owner: p.owner,
    payer: p.payer,
    nonce: p.nonce,
    newPqPubkey: p.newPqPubkey,
    sigLen: p.signature.length,
    window: p.window,
  });
  const chunks = chunkSignature(p.signature, p.chunkSize ?? MAX_CHUNK_BYTES);
  const writes = chunks.map((c) => writePqSigInstruction({ programId: p.programId, buffer, payer: p.payer, offset: c.offset, chunk: c.bytes }));
  const rotate = [
    ComputeBudgetProgram.setComputeUnitLimit({ units: p.computeUnits ?? EXECUTE_COMPUTE_UNITS }),
    rotatePqInstruction({ programId: p.programId, commitment, buffer, payer: p.payer }),
  ];
  return { commitment, buffer, open, writes, chunks, rotate, transactions: [[open], ...writes.map((ix) => [ix]), rotate] };
}
