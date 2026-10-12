/**
 * LM-OTS (RFC 8554 Section 4) with Appendix A pseudorandom private keys.
 *
 * Every function here takes the parameter set explicitly so W1/W2/W8 work the same way as W4.
 */
import { concat, u16str, u32str, writeU16, writeU32 } from "./bytes.ts";
import { D_MESG, D_PBLC, D_PRG, type LmotsParams } from "./params.ts";
import { padSingleBlock, sha256, sha256SingleBlock } from "./sha256.ts";

/** coef(S, i, w) from Section 3.1.3. */
export function coef(S: Uint8Array, i: number, w: number): number {
  const byteIndex = Math.floor((i * w) / 8);
  if (byteIndex >= S.length) throw new RangeError("coef: index out of range");
  const shift = 8 - (w * (i % (8 / w)) + w);
  return ((1 << w) - 1) & (S[byteIndex]! >>> shift);
}

/** Cksm(S) from Section 4.4, as a two-byte big-endian string. */
export function checksum(S: Uint8Array, params: LmotsParams): Uint8Array {
  const { n, w, ls } = params;
  let sum = 0;
  const count = (n * 8) / w;
  for (let i = 0; i < count; i++) sum += (1 << w) - 1 - coef(S, i, w);
  return u16str((sum << ls) & 0xffff);
}

/** Q = H(I || u32str(q) || u16str(D_MESG) || C || message), truncated to n bytes. */
export function messageHash(I: Uint8Array, q: number, C: Uint8Array, message: Uint8Array, n: 24 | 32 = 32): Uint8Array {
  return sha256(concat(I, u32str(q), u16str(D_MESG), C, message)).subarray(0, n);
}

/**
 * A 64-byte block laid out as `I(16) || q(4) || i(2) || j(1) || value(n)` plus padding, the
 * input to every chain-step hash and every Appendix A derivation. `value` sits at offset 23 and the
 * digest (truncated to n) is written straight back over it, so one chain step is one compression call.
 */
export const CHAIN_VALUE_OFFSET = 23;

export function newChainBlock(I: Uint8Array, q: number, n: 24 | 32 = 32): Uint8Array {
  if (I.length !== 16) throw new RangeError("I must be 16 bytes");
  const block = new Uint8Array(64);
  block.set(I, 0);
  writeU32(block, 16, q);
  padSingleBlock(block, CHAIN_VALUE_OFFSET + n);
  return block;
}

/** Write `tmp = H(I || q || i || j || tmp)` into the block value slot, repeated for j in [from, to). */
function chain(block: Uint8Array, i: number, from: number, to: number, n: 24 | 32): void {
  writeU16(block, 20, i);
  for (let j = from; j < to; j++) {
    block[22] = j;
    sha256SingleBlock(block, block, CHAIN_VALUE_OFFSET, n);
  }
}

/**
 * The n-byte SEED used by Appendix A. Vault key derivation yields 32 bytes; a SHA-256/192 key
 * uses the first 24 (RFC 9858 keys carry an n-byte SEED). An exact n-byte seed is accepted too.
 */
export function seedForParams(params: LmotsParams, seed: Uint8Array): Uint8Array {
  if (seed.length !== 32 && seed.length !== params.n) throw new RangeError(`SEED must be 32 or ${params.n} bytes`);
  return seed.subarray(0, params.n);
}

/** Appendix A: x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED), for all i, as one p*n buffer. */
export function derivePrivateElements(params: LmotsParams, seed: Uint8Array, I: Uint8Array, q: number): Uint8Array {
  const { n, p } = params;
  const s = seedForParams(params, seed);
  const x = new Uint8Array(p * n);
  const block = newChainBlock(I, q, n);
  block[22] = D_PRG;
  for (let i = 0; i < p; i++) {
    writeU16(block, 20, i);
    block.set(s, CHAIN_VALUE_OFFSET);
    sha256SingleBlock(block, x, i * n, n);
  }
  return x;
}

/** K = H(I || u32str(q) || u16str(D_PBLC) || y[0] || ... || y[p-1]) over a prepared buffer. */
function publicHash(params: LmotsParams, I: Uint8Array, q: number, y: Uint8Array): Uint8Array {
  const buf = new Uint8Array(22 + params.p * params.n);
  buf.set(I, 0);
  writeU32(buf, 16, q);
  writeU16(buf, 20, D_PBLC);
  buf.set(y, 22);
  return sha256(buf).subarray(0, params.n);
}

/**
 * Algorithm 1 (K only) computed directly from SEED and I: derive each x[i], walk the full chain,
 * hash the ends. This is the per-leaf cost of key generation: p * 2^w hash calls plus one.
 */
export function publicKeyHashFromSeed(params: LmotsParams, seed: Uint8Array, I: Uint8Array, q: number): Uint8Array {
  const { n, p, w } = params;
  const s = seedForParams(params, seed);
  const steps = (1 << w) - 1;
  const y = new Uint8Array(p * n);
  const block = newChainBlock(I, q, n);
  for (let i = 0; i < p; i++) {
    writeU16(block, 20, i);
    block[22] = D_PRG;
    block.set(s, CHAIN_VALUE_OFFSET);
    sha256SingleBlock(block, block, CHAIN_VALUE_OFFSET, n);
    chain(block, i, 0, steps, n);
    y.set(block.subarray(CHAIN_VALUE_OFFSET, CHAIN_VALUE_OFFSET + n), i * n);
  }
  return publicHash(params, I, q, y);
}

/** Algorithm 1 from explicit private elements x (p*n bytes). */
export function publicKeyHash(params: LmotsParams, I: Uint8Array, q: number, x: Uint8Array): Uint8Array {
  const { n, p, w } = params;
  if (x.length !== p * n) throw new RangeError("x has wrong length");
  const steps = (1 << w) - 1;
  const y = new Uint8Array(p * n);
  const block = newChainBlock(I, q, n);
  for (let i = 0; i < p; i++) {
    block.set(x.subarray(i * n, (i + 1) * n), CHAIN_VALUE_OFFSET);
    chain(block, i, 0, steps, n);
    y.set(block.subarray(CHAIN_VALUE_OFFSET, CHAIN_VALUE_OFFSET + n), i * n);
  }
  return publicHash(params, I, q, y);
}

/**
 * Algorithm 3: sign `message` with the private elements x for leaf q, using randomizer C.
 * Returns u32str(type) || C || y[0..p).
 */
export function lmotsSign(
  params: LmotsParams,
  I: Uint8Array,
  q: number,
  x: Uint8Array,
  message: Uint8Array,
  C: Uint8Array,
): Uint8Array {
  const { n, p, w } = params;
  if (C.length !== n) throw new RangeError(`C must be ${n} bytes`);
  if (x.length !== p * n) throw new RangeError("x has wrong length");
  const Q = messageHash(I, q, C, message, n);
  const QC = concat(Q, checksum(Q, params));
  const sig = new Uint8Array(params.sigLen);
  writeU32(sig, 0, params.typecode);
  sig.set(C, 4);
  const block = newChainBlock(I, q, n);
  for (let i = 0; i < p; i++) {
    const a = coef(QC, i, w);
    block.set(x.subarray(i * n, (i + 1) * n), CHAIN_VALUE_OFFSET);
    chain(block, i, 0, a, n);
    sig.set(block.subarray(CHAIN_VALUE_OFFSET, CHAIN_VALUE_OFFSET + n), 4 + n + i * n);
  }
  return sig;
}

/** Sign straight from SEED/I (Appendix A), the usual path for a vault key. */
export function lmotsSignFromSeed(
  params: LmotsParams,
  seed: Uint8Array,
  I: Uint8Array,
  q: number,
  message: Uint8Array,
  C: Uint8Array,
): Uint8Array {
  return lmotsSign(params, I, q, derivePrivateElements(params, seed, I, q), message, C);
}

export interface LmotsSignature {
  readonly typecode: number;
  readonly C: Uint8Array;
  /** p*n bytes */
  readonly y: Uint8Array;
}

/** Parse an LM-OTS signature; returns null when the typecode or length is wrong. */
export function parseLmotsSignature(sig: Uint8Array, expectedType: number, params: LmotsParams): LmotsSignature | null {
  if (sig.length < 4) return null;
  const typecode = ((sig[0]! << 24) | (sig[1]! << 16) | (sig[2]! << 8) | sig[3]!) >>> 0;
  if (typecode !== expectedType) return null;
  if (sig.length !== params.sigLen) return null;
  return { typecode, C: sig.subarray(4, 4 + params.n), y: sig.subarray(4 + params.n) };
}

/**
 * Algorithm 4b: the public key candidate Kc from a signature and message. Returns null if the
 * signature is malformed for `params`.
 */
export function publicKeyCandidate(
  params: LmotsParams,
  I: Uint8Array,
  q: number,
  message: Uint8Array,
  signature: Uint8Array,
): Uint8Array | null {
  const parsed = parseLmotsSignature(signature, params.typecode, params);
  if (!parsed) return null;
  const { n, p, w } = params;
  const steps = (1 << w) - 1;
  const Q = messageHash(I, q, parsed.C, message, n);
  const QC = concat(Q, checksum(Q, params));
  const z = new Uint8Array(p * n);
  const block = newChainBlock(I, q, n);
  for (let i = 0; i < p; i++) {
    const a = coef(QC, i, w);
    block.set(parsed.y.subarray(i * n, (i + 1) * n), CHAIN_VALUE_OFFSET);
    chain(block, i, a, steps, n);
    z.set(block.subarray(CHAIN_VALUE_OFFSET, CHAIN_VALUE_OFFSET + n), i * n);
  }
  return publicHash(params, I, q, z);
}
