/** Anchor's 8-byte discriminators: sha256("global:<ix>")[0..8] and sha256("account:<Name>")[0..8]. */
import { sha256 } from "@noble/hashes/sha2.js";

const enc = new TextEncoder();

export function instructionDiscriminator(name: string): Uint8Array {
  return sha256(enc.encode(`global:${name}`)).slice(0, 8);
}

export function accountDiscriminator(name: string): Uint8Array {
  return sha256(enc.encode(`account:${name}`)).slice(0, 8);
}

export const IX = {
  // lamport-vault
  createVault: instructionDiscriminator("create_vault"),
  openSigBuffer: instructionDiscriminator("open_sig_buffer"),
  writeSig: instructionDiscriminator("write_sig"),
  closeSigBuffer: instructionDiscriminator("close_sig_buffer"),
  execute: instructionDiscriminator("execute"),
  // pq-registry
  commit: instructionDiscriminator("commit"),
  openPqBuffer: instructionDiscriminator("open_pq_buffer"),
  writePqSig: instructionDiscriminator("write_pq_sig"),
  closePqBuffer: instructionDiscriminator("close_pq_buffer"),
  rotatePq: instructionDiscriminator("rotate_pq"),
} as const;

export const ACCOUNT = {
  vault: accountDiscriminator("Vault"),
  sigBuffer: accountDiscriminator("SigBuffer"),
  commitment: accountDiscriminator("Commitment"),
  pqSigBuffer: accountDiscriminator("PqSigBuffer"),
} as const;
