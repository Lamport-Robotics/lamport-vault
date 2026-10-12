/**
 * RFC 8554 parameter sets (Tables 1 and 2: SHA-256, n = m = 32) and the SHA-256/192 rows of
 * RFC 9858 (Tables 1 and 2: SHA-256 truncated to its first 24 bytes, n = m = 24). RFC 9858's
 * SHAKE256 rows are not implemented: the on-chain verifier only has a SHA-256 syscall.
 */

export const LMOTS_SHA256_N32_W1 = 1;
export const LMOTS_SHA256_N32_W2 = 2;
export const LMOTS_SHA256_N32_W4 = 3;
export const LMOTS_SHA256_N32_W8 = 4;
export const LMOTS_SHA256_N24_W1 = 5;
export const LMOTS_SHA256_N24_W2 = 6;
export const LMOTS_SHA256_N24_W4 = 7;
export const LMOTS_SHA256_N24_W8 = 8;

export const LMS_SHA256_M32_H5 = 5;
export const LMS_SHA256_M32_H10 = 6;
export const LMS_SHA256_M32_H15 = 7;
export const LMS_SHA256_M32_H20 = 8;
export const LMS_SHA256_M32_H25 = 9;
export const LMS_SHA256_M24_H5 = 10;
export const LMS_SHA256_M24_H10 = 11;
export const LMS_SHA256_M24_H15 = 12;
export const LMS_SHA256_M24_H20 = 13;
export const LMS_SHA256_M24_H25 = 14;

/** Domain separators (RFC 8554 Section 7.1). */
export const D_PBLC = 0x8080;
export const D_MESG = 0x8181;
export const D_LEAF = 0x8282;
export const D_INTR = 0x8383;
/** Appendix A: the `j` byte used when deriving private key elements. */
export const D_PRG = 0xff;

export interface LmotsParams {
  readonly typecode: number;
  readonly name: string;
  /** hash output length in bytes: 32 (SHA-256) or 24 (SHA-256/192) */
  readonly n: 24 | 32;
  /** Winternitz width in bits */
  readonly w: 1 | 2 | 4 | 8;
  /** number of chains */
  readonly p: number;
  /** checksum left shift */
  readonly ls: number;
  /** 4 + n * (p + 1) */
  readonly sigLen: number;
}

export interface LmsParams {
  readonly typecode: number;
  readonly name: string;
  /** node length in bytes: 32 (SHA-256) or 24 (SHA-256/192) */
  readonly m: 24 | 32;
  /** tree height */
  readonly h: number;
}

const lmots = (typecode: number, name: string, w: 1 | 2 | 4 | 8, p: number, ls: number, n: 24 | 32 = 32): LmotsParams => ({
  typecode,
  name,
  n,
  w,
  p,
  ls,
  sigLen: 4 + n * (p + 1),
});

export const LMOTS_PARAMS: Readonly<Record<number, LmotsParams>> = {
  [LMOTS_SHA256_N32_W1]: lmots(LMOTS_SHA256_N32_W1, "LMOTS_SHA256_N32_W1", 1, 265, 7),
  [LMOTS_SHA256_N32_W2]: lmots(LMOTS_SHA256_N32_W2, "LMOTS_SHA256_N32_W2", 2, 133, 6),
  [LMOTS_SHA256_N32_W4]: lmots(LMOTS_SHA256_N32_W4, "LMOTS_SHA256_N32_W4", 4, 67, 4),
  [LMOTS_SHA256_N32_W8]: lmots(LMOTS_SHA256_N32_W8, "LMOTS_SHA256_N32_W8", 8, 34, 0),
  [LMOTS_SHA256_N24_W1]: lmots(LMOTS_SHA256_N24_W1, "LMOTS_SHA256_N24_W1", 1, 200, 8, 24),
  [LMOTS_SHA256_N24_W2]: lmots(LMOTS_SHA256_N24_W2, "LMOTS_SHA256_N24_W2", 2, 101, 6, 24),
  [LMOTS_SHA256_N24_W4]: lmots(LMOTS_SHA256_N24_W4, "LMOTS_SHA256_N24_W4", 4, 51, 4, 24),
  [LMOTS_SHA256_N24_W8]: lmots(LMOTS_SHA256_N24_W8, "LMOTS_SHA256_N24_W8", 8, 26, 0, 24),
};

const lms = (typecode: number, name: string, h: number, m: 24 | 32 = 32): LmsParams => ({ typecode, name, m, h });

export const LMS_PARAMS: Readonly<Record<number, LmsParams>> = {
  [LMS_SHA256_M32_H5]: lms(LMS_SHA256_M32_H5, "LMS_SHA256_M32_H5", 5),
  [LMS_SHA256_M32_H10]: lms(LMS_SHA256_M32_H10, "LMS_SHA256_M32_H10", 10),
  [LMS_SHA256_M32_H15]: lms(LMS_SHA256_M32_H15, "LMS_SHA256_M32_H15", 15),
  [LMS_SHA256_M32_H20]: lms(LMS_SHA256_M32_H20, "LMS_SHA256_M32_H20", 20),
  [LMS_SHA256_M32_H25]: lms(LMS_SHA256_M32_H25, "LMS_SHA256_M32_H25", 25),
  [LMS_SHA256_M24_H5]: lms(LMS_SHA256_M24_H5, "LMS_SHA256_M24_H5", 5, 24),
  [LMS_SHA256_M24_H10]: lms(LMS_SHA256_M24_H10, "LMS_SHA256_M24_H10", 10, 24),
  [LMS_SHA256_M24_H15]: lms(LMS_SHA256_M24_H15, "LMS_SHA256_M24_H15", 15, 24),
  [LMS_SHA256_M24_H20]: lms(LMS_SHA256_M24_H20, "LMS_SHA256_M24_H20", 20, 24),
  [LMS_SHA256_M24_H25]: lms(LMS_SHA256_M24_H25, "LMS_SHA256_M24_H25", 25, 24),
};

export function lmotsParams(typecode: number): LmotsParams {
  const p = LMOTS_PARAMS[typecode];
  if (!p) throw new Error(`unknown LM-OTS typecode ${typecode}`);
  return p;
}

export function lmsParams(typecode: number): LmsParams {
  const p = LMS_PARAMS[typecode];
  if (!p) throw new Error(`unknown LMS typecode ${typecode}`);
  return p;
}

export function isLmotsTypecode(typecode: number): boolean {
  return typecode in LMOTS_PARAMS;
}

export function isLmsTypecode(typecode: number): boolean {
  return typecode in LMS_PARAMS;
}

/** Length in bytes of an LMS signature for the given typecodes: 4 + lmots_sig + 4 + m*h. */
export function lmsSignatureLength(lmsType: number, lmotsType: number): number {
  const lp = lmsParams(lmsType);
  return 4 + lmotsParams(lmotsType).sigLen + 4 + lp.m * lp.h;
}

/** A SHA-256 LMS public key: u32 type || u32 otstype || I[16] || T[1][32]. */
export const LMS_PUBLIC_KEY_LENGTH = 56;

/** Public key length for an LMS typecode: 24 + m (56 for SHA-256, 48 for SHA-256/192). */
export function lmsPublicKeyLength(lmsType: number): number {
  return 24 + lmsParams(lmsType).m;
}

/** RFC 9858 Section 5: the LMS tree and its LM-OTS leaves use the same hash and length. */
export function checkHashLengths(lmsType: number, lmotsType: number): void {
  if (lmsParams(lmsType).m !== lmotsParams(lmotsType).n) throw new Error("LMS and LM-OTS typecodes use different hash lengths");
}
