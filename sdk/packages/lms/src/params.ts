/** RFC 8554 parameter sets (Tables 1 and 2). SHA-256 only, n = m = 32. */

export const LMOTS_SHA256_N32_W1 = 1;
export const LMOTS_SHA256_N32_W2 = 2;
export const LMOTS_SHA256_N32_W4 = 3;
export const LMOTS_SHA256_N32_W8 = 4;

export const LMS_SHA256_M32_H5 = 5;
export const LMS_SHA256_M32_H10 = 6;
export const LMS_SHA256_M32_H15 = 7;
export const LMS_SHA256_M32_H20 = 8;
export const LMS_SHA256_M32_H25 = 9;

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
  /** hash output length in bytes */
  readonly n: 32;
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
  /** node length in bytes */
  readonly m: 32;
  /** tree height */
  readonly h: number;
}

const lmots = (typecode: number, name: string, w: 1 | 2 | 4 | 8, p: number, ls: number): LmotsParams => ({
  typecode,
  name,
  n: 32,
  w,
  p,
  ls,
  sigLen: 4 + 32 * (p + 1),
});

export const LMOTS_PARAMS: Readonly<Record<number, LmotsParams>> = {
  [LMOTS_SHA256_N32_W1]: lmots(LMOTS_SHA256_N32_W1, "LMOTS_SHA256_N32_W1", 1, 265, 7),
  [LMOTS_SHA256_N32_W2]: lmots(LMOTS_SHA256_N32_W2, "LMOTS_SHA256_N32_W2", 2, 133, 6),
  [LMOTS_SHA256_N32_W4]: lmots(LMOTS_SHA256_N32_W4, "LMOTS_SHA256_N32_W4", 4, 67, 4),
  [LMOTS_SHA256_N32_W8]: lmots(LMOTS_SHA256_N32_W8, "LMOTS_SHA256_N32_W8", 8, 34, 0),
};

const lms = (typecode: number, name: string, h: number): LmsParams => ({ typecode, name, m: 32, h });

export const LMS_PARAMS: Readonly<Record<number, LmsParams>> = {
  [LMS_SHA256_M32_H5]: lms(LMS_SHA256_M32_H5, "LMS_SHA256_M32_H5", 5),
  [LMS_SHA256_M32_H10]: lms(LMS_SHA256_M32_H10, "LMS_SHA256_M32_H10", 10),
  [LMS_SHA256_M32_H15]: lms(LMS_SHA256_M32_H15, "LMS_SHA256_M32_H15", 15),
  [LMS_SHA256_M32_H20]: lms(LMS_SHA256_M32_H20, "LMS_SHA256_M32_H20", 20),
  [LMS_SHA256_M32_H25]: lms(LMS_SHA256_M32_H25, "LMS_SHA256_M32_H25", 25),
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

/** Length in bytes of an LMS signature for the given typecodes: 4 + lmots_sig + 4 + 32*h. */
export function lmsSignatureLength(lmsType: number, lmotsType: number): number {
  return 4 + lmotsParams(lmotsType).sigLen + 4 + 32 * lmsParams(lmsType).h;
}

/** An LMS public key is always u32 type || u32 otstype || I[16] || T[1][32]. */
export const LMS_PUBLIC_KEY_LENGTH = 56;
