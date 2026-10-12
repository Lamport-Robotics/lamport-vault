/**
 * SHA-256 for LMS.
 *
 * General-purpose hashing goes through `@noble/hashes`. The hot paths of key generation
 * (Appendix A private-key elements and the Winternitz chains) are all hashes of exactly
 * 55 bytes: `I(16) || u32str(q) || u16str(i) || u8str(j) || 32 bytes`. That fits one
 * padded SHA-256 block, so `sha256SingleBlock` below runs the compression function once
 * on a pre-padded 64-byte buffer with no allocation. It is checked against noble in the
 * tests on random inputs of every length it accepts.
 */
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

export const sha256 = nobleSha256;

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const W = new Uint32Array(64);

/** Largest message that fits a single SHA-256 block together with its padding. */
export const SINGLE_BLOCK_MAX = 55;

/**
 * Prepare a 64-byte block for `sha256SingleBlock`: writes the 0x80 terminator and the
 * bit length for a message of `len` bytes. The caller fills bytes `[0, len)`.
 */
export function padSingleBlock(block: Uint8Array, len: number): void {
  if (block.length !== 64) throw new RangeError("padSingleBlock: block must be 64 bytes");
  if (len > SINGLE_BLOCK_MAX) throw new RangeError("padSingleBlock: message too long for one block");
  block.fill(0, len);
  block[len] = 0x80;
  const bits = len * 8;
  block[62] = (bits >>> 8) & 0xff;
  block[63] = bits & 0xff;
}

/**
 * SHA-256 compression of one already-padded block with the standard IV; the first `outLen`
 * digest bytes (32, or 24 for SHA-256/192) are written to `out[outOffset..outOffset+outLen)`.
 * `out` may alias `block`: the block is read into the schedule before anything is written.
 */
export function sha256SingleBlock(block: Uint8Array, out: Uint8Array, outOffset = 0, outLen = 32): void {
  for (let i = 0; i < 16; i++) {
    const j = i * 4;
    W[i] = (block[j]! << 24) | (block[j + 1]! << 16) | (block[j + 2]! << 8) | block[j + 3]!;
  }
  for (let i = 16; i < 64; i++) {
    const w15 = W[i - 15]!;
    const w2 = W[i - 2]!;
    const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
    const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
    W[i] = (W[i - 16]! + s0 + W[i - 7]! + s1) | 0;
  }
  let a = 0x6a09e667;
  let b = 0xbb67ae85;
  let c = 0x3c6ef372;
  let d = 0xa54ff53a;
  let e = 0x510e527f;
  let f = 0x9b05688c;
  let g = 0x1f83d9ab;
  let h = 0x5be0cd19;
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const ch = (e & f) ^ (~e & g);
    const t1 = (h + S1 + ch + K[i]! + W[i]!) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + maj) | 0;
    h = g;
    g = f;
    f = e;
    e = (d + t1) | 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) | 0;
  }
  a = (a + 0x6a09e667) | 0;
  b = (b + 0xbb67ae85) | 0;
  c = (c + 0x3c6ef372) | 0;
  d = (d + 0xa54ff53a) | 0;
  e = (e + 0x510e527f) | 0;
  f = (f + 0x9b05688c) | 0;
  g = (g + 0x1f83d9ab) | 0;
  h = (h + 0x5be0cd19) | 0;
  if (outLen !== 32) {
    // Truncated output (RFC 9858 SHA-256/192): never write past outLen, which may be padding.
    const words = [a, b, c, d, e, f, g, h];
    for (let i = 0; i < outLen; i++) out[outOffset + i] = words[i >> 2]! >>> (24 - 8 * (i & 3));
    return;
  }
  const o = outOffset;
  out[o] = a >>> 24; out[o + 1] = a >>> 16; out[o + 2] = a >>> 8; out[o + 3] = a;
  out[o + 4] = b >>> 24; out[o + 5] = b >>> 16; out[o + 6] = b >>> 8; out[o + 7] = b;
  out[o + 8] = c >>> 24; out[o + 9] = c >>> 16; out[o + 10] = c >>> 8; out[o + 11] = c;
  out[o + 12] = d >>> 24; out[o + 13] = d >>> 16; out[o + 14] = d >>> 8; out[o + 15] = d;
  out[o + 16] = e >>> 24; out[o + 17] = e >>> 16; out[o + 18] = e >>> 8; out[o + 19] = e;
  out[o + 20] = f >>> 24; out[o + 21] = f >>> 16; out[o + 22] = f >>> 8; out[o + 23] = f;
  out[o + 24] = g >>> 24; out[o + 25] = g >>> 16; out[o + 26] = g >>> 8; out[o + 27] = g;
  out[o + 28] = h >>> 24; out[o + 29] = h >>> 16; out[o + 30] = h >>> 8; out[o + 31] = h;
}

const scratch = new Uint8Array(64);

/** SHA-256 of a message of at most 55 bytes, via the single-block path. */
export function sha256Short(msg: Uint8Array): Uint8Array {
  scratch.set(msg, 0);
  padSingleBlock(scratch, msg.length);
  const out = new Uint8Array(32);
  sha256SingleBlock(scratch, out, 0);
  return out;
}
