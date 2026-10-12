// Shared test helpers: an LMS signer backed by the Rust crate (`lms-tool`),
// Borsh encoding of the vault's `Action`, PDAs, staging, and error matching.

import * as anchor from "@coral-xyz/anchor";
import { BN } from "@coral-xyz/anchor";
import type { AccountMeta } from "@solana/web3.js";
import {
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { execFileSync } from "child_process";
import { createHash, randomBytes } from "crypto";
import * as path from "path";
import { expect } from "chai";

export const LMS_TOOL = path.resolve(__dirname, "..", "target", "release", "lms-tool");

export const LMOTS_W4 = 3;
export const LMS_H5 = 5;
export const LMS_H10 = 6;
export const OTS_SIG_LEN = 4 + 32 * (67 + 1); // 2180

export function sha256(...parts: Buffer[]): Buffer {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

export function heightOf(lmsType: number): number {
  return { 5: 5, 6: 10, 7: 15, 8: 20 }[lmsType]!;
}

export function sigLenFor(lmsType: number): number {
  return 4 + OTS_SIG_LEN + 4 + 32 * heightOf(lmsType);
}

function tool(args: string[]): string {
  return execFileSync(LMS_TOOL, args, { encoding: "utf8", maxBuffer: 1 << 26 }).trim();
}

/** An LMS private key (SEED, I, typecodes) whose operations run in `lms-tool`. */
export class LmsKey {
  readonly seed: Buffer;
  readonly i: Buffer;
  readonly lmsType: number;
  readonly lmotsType: number;
  private cachedPub?: Buffer;

  constructor(seed: Buffer, i: Buffer, lmsType: number, lmotsType: number = LMOTS_W4) {
    this.seed = seed;
    this.i = i;
    this.lmsType = lmsType;
    this.lmotsType = lmotsType;
  }

  static random(lmsType: number): LmsKey {
    return new LmsKey(randomBytes(32), randomBytes(16), lmsType);
  }

  get height(): number {
    return heightOf(this.lmsType);
  }
  get leafCount(): number {
    return 1 << this.height;
  }
  get sigLen(): number {
    return sigLenFor(this.lmsType);
  }

  private common(): string[] {
    return [
      "--seed",
      this.seed.toString("hex"),
      "--i",
      this.i.toString("hex"),
      "--lms-type",
      String(this.lmsType),
      "--lmots-type",
      String(this.lmotsType),
    ];
  }

  /** 56-byte public key. */
  pubkey(): Buffer {
    if (!this.cachedPub) {
      this.cachedPub = Buffer.from(tool(["keygen", ...this.common()]), "hex");
      expect(this.cachedPub.length).to.eq(56);
    }
    return this.cachedPub;
  }

  /** LMS signature of `message` with leaf `q`. */
  sign(q: number, message: Buffer): Buffer {
    const sig = Buffer.from(
      tool(["sign", ...this.common(), "--q", String(q), "--msg", message.toString("hex")]),
      "hex",
    );
    expect(sig.length).to.eq(this.sigLen);
    return sig;
  }
}

/** An action's validity window: `issued_slot <= slot <= expiry_slot`, at most MAX_VALIDITY_SLOTS wide. */
export interface Window {
  issued: BN | number;
  expiry: BN | number;
}

/** `u64le(issued) || u64le(expiry)`, the tail of every Action. */
export function windowBytes(w: Window): Buffer {
  return Buffer.concat([new BN(w.issued).toArrayLike(Buffer, "le", 8), new BN(w.expiry).toArrayLike(Buffer, "le", 8)]);
}

/** Borsh encoding of `lamport_vault::Action`; every variant ends in the window. */
export const Action = {
  transferSol(to: PublicKey, lamports: BN | number, w: Window): Buffer {
    return Buffer.concat([Buffer.from([0]), to.toBuffer(), new BN(lamports).toArrayLike(Buffer, "le", 8), windowBytes(w)]);
  },
  transferToken(mint: PublicKey, to: PublicKey, amount: BN | number, w: Window): Buffer {
    return Buffer.concat([
      Buffer.from([1]),
      mint.toBuffer(),
      to.toBuffer(),
      new BN(amount).toArrayLike(Buffer, "le", 8),
      windowBytes(w),
    ]);
  },
  rotate(newLmsPubkey: Buffer, w: Window): Buffer {
    expect(newLmsPubkey.length).to.eq(56);
    return Buffer.concat([Buffer.from([2]), newLmsPubkey, windowBytes(w)]);
  },
  close(to: PublicKey, w: Window): Buffer {
    return Buffer.concat([Buffer.from([3]), to.toBuffer(), windowBytes(w)]);
  },
};

export function u32le(x: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(x);
  return b;
}

/** sha256("lamport-vault/v1" || program_id || vault || u32le(generation) || action_bytes) */
export function vaultMessage(programId: PublicKey, vault: PublicKey, generation: number, actionBytes: Buffer): Buffer {
  return sha256(Buffer.from("lamport-vault/v1"), programId.toBuffer(), vault.toBuffer(), u32le(generation), actionBytes);
}

/** sha256("pq-registry/v1" || program_id || owner || u32le(generation) || new_pq_pubkey || u64le(issued) || u64le(expiry)) */
export function registryMessage(programId: PublicKey, owner: PublicKey, generation: number, newPqPubkey: Buffer, w: Window): Buffer {
  return sha256(Buffer.from("pq-registry/v1"), programId.toBuffer(), owner.toBuffer(), u32le(generation), newPqPubkey, windowBytes(w));
}

/** sha256(pubkey)[0..16]: a `used_keys` entry. */
export function keyHash(pubkey: Buffer): Buffer {
  return sha256(pubkey).subarray(0, 16);
}

/** Bit q of a used-leaf bitmap. */
export function leafUsed(used: Uint8Array | number[], q: number): boolean {
  return ((used[q >> 3] ?? 0xff) & (1 << (q & 7))) !== 0;
}

export function vaultPda(programId: PublicKey, lmsPubkey: Buffer): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from("vault"), sha256(lmsPubkey)], programId);
}

export function sigBufferPda(
  programId: PublicKey,
  vault: PublicKey,
  payer: PublicKey,
  nonce: BN,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("sig"), vault.toBuffer(), payer.toBuffer(), nonce.toArrayLike(Buffer, "le", 8)],
    programId,
  );
}

export function commitmentPda(programId: PublicKey, owner: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from("pq"), owner.toBuffer()], programId);
}

export function rotationBufferPda(
  programId: PublicKey,
  owner: PublicKey,
  payer: PublicKey,
  nonce: BN,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("pqsig"), owner.toBuffer(), payer.toBuffer(), nonce.toArrayLike(Buffer, "le", 8)],
    programId,
  );
}

export function randomNonce(): BN {
  return new BN(randomBytes(8), "le");
}

/**
 * Staging layout. For the vault the first chunk rides in `open_sig_buffer`
 * next to the action and fits a 1232-byte transaction with two signers; later
 * chunks are 900 bytes, so H10 (2508 bytes) is exactly 708 + 900 + 900: three
 * transactions. The registry's `open_pq_buffer` takes no chunk; its signature
 * goes entirely through 900-byte `write_pq_sig` calls.
 */
export const FIRST_CHUNK = 708;
export const CHUNK = 900;

/**
 * Provider with `confirmed` commitment. Anchor's default `processed` lets the
 * preflight simulation race the blockhash on a fresh local validator.
 */
export function provider(): anchor.AnchorProvider {
  const url = process.env.ANCHOR_PROVIDER_URL ?? "http://127.0.0.1:8899";
  const connection = new anchor.web3.Connection(url, "confirmed");
  const wallet = anchor.Wallet.local();
  const p = new anchor.AnchorProvider(connection, wallet, {
    commitment: "confirmed",
    preflightCommitment: "confirmed",
  });
  anchor.setProvider(p);
  return p;
}

export const COMPUTE_BUDGET_IX = ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 });

export async function fund(provider: anchor.AnchorProvider, to: PublicKey, sol: number): Promise<void> {
  // A validator that just started can answer "Blockhash not found" for a few
  // hundred milliseconds; retry instead of failing the whole suite.
  for (let attempt = 0; ; attempt++) {
    try {
      const tx = new Transaction().add(
        SystemProgram.transfer({
          fromPubkey: provider.wallet.publicKey,
          toPubkey: to,
          lamports: Math.round(sol * LAMPORTS_PER_SOL),
        }),
      );
      await provider.sendAndConfirm(tx, [], { commitment: "confirmed" });
      return;
    } catch (e) {
      if (attempt >= 5 || !/Blockhash not found/.test(String((e as Error).message))) throw e;
      await new Promise((r) => setTimeout(r, 500));
    }
  }
}

export async function currentSlot(provider: anchor.AnchorProvider): Promise<number> {
  return provider.connection.getSlot("confirmed");
}

/** A window issued now and open for `slots` more slots (default 5 000, well inside the one-day cap). */
export async function window(provider: anchor.AnchorProvider, slots = 5000): Promise<Window> {
  const slot = await currentSlot(provider);
  return { issued: slot, expiry: slot + slots };
}

/** A window that closed before the current slot (and was issued before that). */
export async function expiredWindow(provider: anchor.AnchorProvider): Promise<Window> {
  const slot = await currentSlot(provider);
  return { issued: Math.max(0, slot - 2), expiry: Math.max(0, slot - 1) };
}

export function meta(pubkey: PublicKey, isWritable: boolean, isSigner = false): AccountMeta {
  return { pubkey, isWritable, isSigner };
}

/** Pulls the compute units a program consumed out of a confirmed transaction's logs. */
export async function consumedUnits(
  provider: anchor.AnchorProvider,
  signature: string,
  programId: PublicKey,
): Promise<number> {
  const tx = await provider.connection.getTransaction(signature, {
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
  });
  const logs = tx?.meta?.logMessages ?? [];
  const re = new RegExp(`^Program ${programId.toBase58()} consumed (\\d+) of (\\d+) compute units`);
  for (const line of logs) {
    const m = re.exec(line);
    if (m) return Number(m[1]);
  }
  throw new Error(`no compute log for ${programId.toBase58()} in ${JSON.stringify(logs)}`);
}

/** Extracts an Anchor error code name (or a generic reason) from a rejected rpc(). */
export function errorCode(e: any): string {
  const code = e?.error?.errorCode?.code;
  if (code) return code;
  const text = String(e?.message ?? e) + "\n" + (e?.logs ?? e?.transactionLogs ?? []).join("\n");
  const m = /Error Code: (\w+)/.exec(text);
  if (m) return m[1];
  if (/already in use/.test(text)) return "AlreadyInUse";
  if (/custom program error: 0x0\b/.test(text)) return "AlreadyInUse";
  return text;
}

export async function expectError(p: Promise<unknown>, code: string): Promise<void> {
  let failed = false;
  try {
    await p;
  } catch (e) {
    failed = true;
    const got = errorCode(e);
    expect(got, `expected ${code}, got ${got}`).to.eq(code);
  }
  expect(failed, `expected ${code}, but the transaction succeeded`).to.eq(true);
}

/**
 * The TypeScript SDK (`sdk/`), built and loaded from its ESM `dist` (Node 22.12+ `require(esm)`).
 * `tsc -b` is incremental, so this is instant when the build is current. Untyped on purpose:
 * the test asserts behaviour against the chain, not the SDK's types.
 */
export function loadSdk(): { vault: any; lms: any } {
  const sdkDir = path.resolve(__dirname, "..", "sdk");
  execFileSync("npm", ["run", "build"], { cwd: sdkDir, stdio: "pipe" });
  return {
    vault: require(path.join(sdkDir, "packages", "vault", "dist", "index.js")),
    lms: require(path.join(sdkDir, "packages", "lms", "dist", "index.js")),
  };
}

export async function expectRejects(p: Promise<unknown>, re: RegExp): Promise<void> {
  let failed = false;
  try {
    await p;
  } catch (e) {
    failed = true;
    const msg = String((e as Error).message ?? e);
    expect(msg, `expected an error matching ${re}, got: ${msg}`).to.match(re);
  }
  expect(failed, `expected an error matching ${re}, but the promise resolved`).to.eq(true);
}

export { Keypair, PublicKey, BN };
