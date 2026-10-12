/**
 * LMS (RFC 8554 Section 5): key generation from (SEED, I), signing with an authentication path
 * taken from a stored tree (Appendix D), verification (Algorithms 6 and 6a).
 */
import { randomBytes } from "@noble/hashes/utils.js";
import { equalBytes, strTou32, u16str, u32str, writeU16, writeU32 } from "./bytes.ts";
import {
  derivePrivateElements,
  lmotsSign,
  publicKeyCandidate,
  publicKeyHashFromSeed,
} from "./lmots.ts";
import {
  D_INTR,
  D_LEAF,
  LMOTS_SHA256_N32_W4,
  LMS_PUBLIC_KEY_LENGTH,
  LMS_SHA256_M32_H10,
  type LmotsParams,
  type LmsParams,
  lmotsParams,
  lmsParams,
  lmsSignatureLength,
} from "./params.ts";
import { padSingleBlock, sha256, sha256SingleBlock } from "./sha256.ts";

/** Everything needed to rebuild an LMS private key: typecodes plus the Appendix A inputs. */
export interface LmsKeyMaterial {
  readonly lmsType: number;
  readonly lmotsType: number;
  /** 32 bytes */
  readonly seed: Uint8Array;
  /** 16 bytes */
  readonly I: Uint8Array;
}

export interface LmsPublicKeyParts {
  readonly lmsType: number;
  readonly lmotsType: number;
  readonly I: Uint8Array;
  readonly T1: Uint8Array;
}

export interface LmsSignatureParts {
  readonly q: number;
  readonly lmotsType: number;
  /** u32str(type) || C || y, lmots sigLen bytes */
  readonly lmotsSignature: Uint8Array;
  readonly lmsType: number;
  /** h entries of 32 bytes */
  readonly path: Uint8Array[];
}

export interface TreeBuildOptions {
  /** Called after each batch of leaves with (leavesDone, leavesTotal). */
  onProgress?: (done: number, total: number) => void;
  /** Leaves computed between yields to the event loop (async builder only). Default 64. */
  leavesPerTick?: number;
}

export function parseLmsPublicKey(pk: Uint8Array): LmsPublicKeyParts {
  if (pk.length !== LMS_PUBLIC_KEY_LENGTH) throw new Error(`LMS public key must be ${LMS_PUBLIC_KEY_LENGTH} bytes`);
  const lmsType = strTou32(pk, 0);
  const lmotsType = strTou32(pk, 4);
  lmsParams(lmsType);
  lmotsParams(lmotsType);
  return { lmsType, lmotsType, I: pk.slice(8, 24), T1: pk.slice(24, 56) };
}

export function serializeLmsPublicKey(parts: LmsPublicKeyParts): Uint8Array {
  if (parts.I.length !== 16 || parts.T1.length !== 32) throw new Error("bad public key parts");
  const out = new Uint8Array(LMS_PUBLIC_KEY_LENGTH);
  writeU32(out, 0, parts.lmsType);
  writeU32(out, 4, parts.lmotsType);
  out.set(parts.I, 8);
  out.set(parts.T1, 24);
  return out;
}

/**
 * Parse an LMS signature. When `expected` typecodes are given the parse enforces them (as a
 * verifier must); otherwise the typecodes carried in the signature are trusted for layout.
 * Throws with a reason on malformed input.
 */
export function parseLmsSignature(
  sig: Uint8Array,
  expected?: { lmsType: number; lmotsType: number },
): LmsSignatureParts {
  if (sig.length < 8) throw new Error("signature shorter than 8 bytes");
  const q = strTou32(sig, 0);
  const lmotsType = strTou32(sig, 4);
  if (expected && lmotsType !== expected.lmotsType) throw new Error("LM-OTS typecode does not match public key");
  const ots = lmotsParams(lmotsType);
  const otsEnd = 4 + ots.sigLen;
  if (sig.length < otsEnd + 4) throw new Error("signature too short for LM-OTS signature and LMS typecode");
  const lmsType = strTou32(sig, otsEnd);
  if (expected && lmsType !== expected.lmsType) throw new Error("LMS typecode does not match public key");
  const lp = lmsParams(lmsType);
  if (q >= 2 ** lp.h) throw new Error(`q=${q} is not below 2^${lp.h}`);
  const want = lmsSignatureLength(lmsType, lmotsType);
  if (sig.length !== want) throw new Error(`signature must be ${want} bytes, got ${sig.length}`);
  const path: Uint8Array[] = [];
  let o = otsEnd + 4;
  for (let i = 0; i < lp.h; i++) {
    path.push(sig.slice(o, o + 32));
    o += 32;
  }
  return { q, lmotsType, lmotsSignature: sig.slice(4, otsEnd), lmsType, path };
}

export function serializeLmsSignature(parts: LmsSignatureParts): Uint8Array {
  const out = new Uint8Array(lmsSignatureLength(parts.lmsType, parts.lmotsType));
  writeU32(out, 0, parts.q);
  out.set(parts.lmotsSignature, 4);
  let o = 4 + parts.lmotsSignature.length;
  writeU32(out, o, parts.lmsType);
  o += 4;
  for (const node of parts.path) {
    out.set(node, o);
    o += 32;
  }
  if (o !== out.length) throw new Error("path length does not match LMS typecode");
  return out;
}

/** T[r] for a leaf: H(I || u32str(r) || u16str(D_LEAF) || K), a 54-byte single-block hash. */
function leafNode(block: Uint8Array, r: number, K: Uint8Array, out: Uint8Array, outOffset: number): void {
  writeU32(block, 16, r);
  writeU16(block, 20, D_LEAF);
  block.set(K, 22);
  sha256SingleBlock(block, out, outOffset);
}

/** T[r] for an interior node: H(I || u32str(r) || u16str(D_INTR) || left || right). */
function interiorNode(I: Uint8Array, r: number, left: Uint8Array, right: Uint8Array): Uint8Array {
  const buf = new Uint8Array(16 + 4 + 2 + 64);
  buf.set(I, 0);
  writeU32(buf, 16, r);
  writeU16(buf, 20, D_INTR);
  buf.set(left, 22);
  buf.set(right, 54);
  return sha256(buf);
}

function newLeafBlock(I: Uint8Array): Uint8Array {
  const block = new Uint8Array(64);
  block.set(I, 0);
  padSingleBlock(block, 54);
  return block;
}

/** Fill the interior nodes of a tree whose leaves (nodes 2^h .. 2^(h+1)-1) are already present. */
function fillInterior(tree: Uint8Array, I: Uint8Array, h: number): void {
  for (let r = 2 ** h - 1; r >= 1; r--) {
    const node = interiorNode(I, r, tree.subarray(2 * r * 32, 2 * r * 32 + 32), tree.subarray((2 * r + 1) * 32, (2 * r + 2) * 32));
    tree.set(node, r * 32);
  }
}

function computeLeafRange(tree: Uint8Array, mat: LmsKeyMaterial, ots: LmotsParams, h: number, from: number, to: number, block: Uint8Array): void {
  const leaves = 2 ** h;
  for (let q = from; q < to; q++) {
    const K = publicKeyHashFromSeed(ots, mat.seed, mat.I, q);
    leafNode(block, leaves + q, K, tree, (leaves + q) * 32);
  }
}

/**
 * An LMS private key with its full node array T[1..2^(h+1)) in memory (32 bytes per node), so
 * signing is one LM-OTS signature plus a copy of h nodes (Appendix D).
 *
 * Leaf state (`q`) is intentionally NOT tracked here: the vault account holds the used-leaf bitmap and the
 * caller chooses q from it. See `VaultSigner` in `@lamport-robotics/vault`.
 */
export class LmsPrivateKey {
  readonly lms: LmsParams;
  readonly lmots: LmotsParams;
  readonly publicKey: Uint8Array;
  readonly material: LmsKeyMaterial;
  /** T[0] unused; T[r] at bytes [32r, 32r+32). */
  readonly tree: Uint8Array;

  private constructor(material: LmsKeyMaterial, tree: Uint8Array) {
    this.material = material;
    this.tree = tree;
    this.lms = lmsParams(material.lmsType);
    this.lmots = lmotsParams(material.lmotsType);
    this.publicKey = serializeLmsPublicKey({
      lmsType: material.lmsType,
      lmotsType: material.lmotsType,
      I: material.I,
      T1: tree.slice(32, 64),
    });
  }

  /** Number of leaves, 2^h. */
  get leafCount(): number {
    return 2 ** this.lms.h;
  }

  /** Build the whole tree synchronously. H10 takes a fraction of a second in Node. */
  static generate(material: LmsKeyMaterial, opts: Pick<TreeBuildOptions, "onProgress"> = {}): LmsPrivateKey {
    checkMaterial(material);
    const lp = lmsParams(material.lmsType);
    const ots = lmotsParams(material.lmotsType);
    const leaves = 2 ** lp.h;
    const tree = new Uint8Array(2 * leaves * 32);
    const block = newLeafBlock(material.I);
    const batch = 64;
    for (let q = 0; q < leaves; q += batch) {
      const to = Math.min(leaves, q + batch);
      computeLeafRange(tree, material, ots, lp.h, q, to, block);
      opts.onProgress?.(to, leaves);
    }
    fillInterior(tree, material.I, lp.h);
    return new LmsPrivateKey(material, tree);
  }

  /** Build the tree in batches, yielding to the event loop between batches (for browsers/UI). */
  static async generateAsync(material: LmsKeyMaterial, opts: TreeBuildOptions = {}): Promise<LmsPrivateKey> {
    checkMaterial(material);
    const lp = lmsParams(material.lmsType);
    const ots = lmotsParams(material.lmotsType);
    const leaves = 2 ** lp.h;
    const tree = new Uint8Array(2 * leaves * 32);
    const block = newLeafBlock(material.I);
    const batch = Math.max(1, opts.leavesPerTick ?? 64);
    for (let q = 0; q < leaves; q += batch) {
      const to = Math.min(leaves, q + batch);
      computeLeafRange(tree, material, ots, lp.h, q, to, block);
      opts.onProgress?.(to, leaves);
      await yieldToEventLoop();
    }
    fillInterior(tree, material.I, lp.h);
    return new LmsPrivateKey(material, tree);
  }

  /**
   * Restore from a cached node array (as returned by `.tree`) without recomputing leaves. The
   * cache is checked against a fresh root computation only if `verify` is true (cheap: 2^h - 1
   * interior hashes, no chains); a tampered leaf would otherwise produce signatures that fail
   * to verify rather than anything worse, since interior nodes are public data.
   */
  static fromTree(material: LmsKeyMaterial, tree: Uint8Array, verify = true): LmsPrivateKey {
    checkMaterial(material);
    const lp = lmsParams(material.lmsType);
    const leaves = 2 ** lp.h;
    if (tree.length !== 2 * leaves * 32) throw new Error("tree has wrong length for this LMS typecode");
    const copy = tree.slice();
    if (verify) {
      const root = copy.slice(32, 64);
      fillInterior(copy, material.I, lp.h);
      if (!equalBytes(root, copy.subarray(32, 64))) throw new Error("tree cache is inconsistent");
    }
    return new LmsPrivateKey(material, copy);
  }

  /** path[i] = T[(2^h + q) >> i ^ 1], Appendix D. */
  authPath(q: number): Uint8Array[] {
    this.checkQ(q);
    const path: Uint8Array[] = [];
    let r = this.leafCount + q;
    for (let i = 0; i < this.lms.h; i++) {
      const sibling = r ^ 1;
      path.push(this.tree.slice(sibling * 32, sibling * 32 + 32));
      r >>>= 1;
    }
    return path;
  }

  /** The leaf hash T[2^h + q] (public data). */
  leaf(q: number): Uint8Array {
    this.checkQ(q);
    const r = this.leafCount + q;
    return this.tree.slice(r * 32, r * 32 + 32);
  }

  /**
   * Sign `message` with leaf `q`. `C` defaults to 32 fresh random bytes; pass a fixed `C` only for
   * test vectors. Never sign two different messages with the same q: the vault's used-leaf bitmap is the
   * guard for that, read it before choosing q.
   */
  sign(q: number, message: Uint8Array, opts: { C?: Uint8Array } = {}): Uint8Array {
    this.checkQ(q);
    const C = opts.C ?? randomBytes(32);
    const x = derivePrivateElements(this.lmots, this.material.seed, this.material.I, q);
    const ots = lmotsSign(this.lmots, this.material.I, q, x, message, C);
    x.fill(0);
    return serializeLmsSignature({
      q,
      lmotsType: this.lmots.typecode,
      lmotsSignature: ots,
      lmsType: this.lms.typecode,
      path: this.authPath(q),
    });
  }

  private checkQ(q: number): void {
    if (!Number.isInteger(q) || q < 0 || q >= this.leafCount) throw new RangeError(`q=${q} out of range for h=${this.lms.h}`);
  }
}

function checkMaterial(m: LmsKeyMaterial): void {
  lmsParams(m.lmsType);
  lmotsParams(m.lmotsType);
  if (m.seed.length !== 32) throw new Error("SEED must be 32 bytes");
  if (m.I.length !== 16) throw new Error("I must be 16 bytes");
}

function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/** Fresh random key material for the given typecodes (defaults: H10, W4). */
export function randomKeyMaterial(lmsType = LMS_SHA256_M32_H10, lmotsType = LMOTS_SHA256_N32_W4): LmsKeyMaterial {
  lmsParams(lmsType);
  lmotsParams(lmotsType);
  return { lmsType, lmotsType, seed: randomBytes(32), I: randomBytes(16) };
}

/**
 * Algorithm 6a: the root candidate Tc from a parsed signature, or null when the LM-OTS part is
 * malformed.
 */
export function lmsRootCandidate(pub: LmsPublicKeyParts, message: Uint8Array, sig: LmsSignatureParts): Uint8Array | null {
  const ots = lmotsParams(pub.lmotsType);
  const lp = lmsParams(pub.lmsType);
  const Kc = publicKeyCandidate(ots, pub.I, sig.q, message, sig.lmotsSignature);
  if (!Kc) return null;
  let nodeNum = 2 ** lp.h + sig.q;
  const block = newLeafBlock(pub.I);
  let tmp: Uint8Array = new Uint8Array(32);
  leafNode(block, nodeNum, Kc, tmp, 0);
  let i = 0;
  while (nodeNum > 1) {
    const sibling = sig.path[i]!;
    tmp = nodeNum % 2 === 1 ? interiorNode(pub.I, nodeNum >>> 1, sibling, tmp) : interiorNode(pub.I, nodeNum >>> 1, tmp, sibling);
    nodeNum >>>= 1;
    i++;
  }
  return tmp;
}

/** Algorithm 6: true iff `signature` is a valid LMS signature over `message` under `publicKey`. */
export function lmsVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  let pub: LmsPublicKeyParts;
  let sig: LmsSignatureParts;
  try {
    pub = parseLmsPublicKey(publicKey);
    sig = parseLmsSignature(signature, { lmsType: pub.lmsType, lmotsType: pub.lmotsType });
  } catch {
    return false;
  }
  const Tc = lmsRootCandidate(pub, message, sig);
  return Tc !== null && equalBytes(Tc, pub.T1);
}

/** The RFC's own leaf-and-interior node hashes, exported for tests and other implementations. */
export const nodeHash = {
  leaf(I: Uint8Array, r: number, K: Uint8Array): Uint8Array {
    return sha256(new Uint8Array([...I, ...u32str(r), ...u16str(D_LEAF), ...K]));
  },
  interior(I: Uint8Array, r: number, left: Uint8Array, right: Uint8Array): Uint8Array {
    return interiorNode(I, r, left, right);
  },
};
