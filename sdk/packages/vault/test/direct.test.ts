/**
 * execute_direct + transaction v1: instruction layout, the v1 bytes (decoded back through kit's
 * own codec), signature assembly, and VaultSigner's modes against a mock RPC that either accepts
 * v1 bytes (decoding and verifying both the ed25519 and the LMS signature) or rejects them.
 */
import {
  address,
  decompileTransactionMessage,
  getBase58Decoder,
  getCompiledTransactionMessageDecoder,
  getPublicKeyFromAddress,
  verifySignature,
} from "@solana/kit";
import { Keypair, PublicKey, SystemProgram, Transaction, type AccountInfo } from "@solana/web3.js";
import { fromHex, LMS_SHA256_M32_H10, LMS_SHA256_M32_H15, LMS_SHA256_M32_H5, LmsPrivateKey, lmsVerify, toHex } from "@lamport-robotics/lms";
import { describe, expect, it } from "vitest";
import { encodeVault, type VaultAccount } from "../src/accounts.ts";
import { decodeAction, encodeAction } from "../src/action.ts";
import { ByteReader } from "../src/borsh.ts";
import {
  assembleV1Transaction,
  buildDirectV1Transaction,
  DEFAULT_LOADED_ACCOUNTS_DATA_SIZE,
  DirectV1Error,
  executeDirectInstruction,
  isV1Rejection,
  keypairV1Signer,
  V1_MAX_TRANSACTION_BYTES,
  V1_VERSION_BYTE,
  v1TransactionSignature,
} from "../src/direct.ts";
import { IX } from "../src/discriminator.ts";
import { vaultMessage } from "../src/message.ts";
import { findVaultPdaForKey, vaultId } from "../src/pda.ts";
import { LAMPORT_VAULT_PROGRAM_ID } from "../src/programIds.ts";
import { type Rpc, VaultSigner } from "../src/signer.ts";
import { KAT_H10_PUBKEY, PK_11, PK_22, PK_33 } from "./fixtures.ts";

const KAT_SEED = fromHex("784bd340367baa20a90c48bf5623171cba34eb7b4022f11ecca2cc1a893cb506");
const KAT_I = fromHex("00112233445566778899aabbccddeeff");
const key = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H5, lmotsType: 3, seed: KAT_SEED, I: KAT_I });
const payer = Keypair.generate();
const BLOCKHASH = Keypair.generate().publicKey.toBase58();

const bogusSig = (n: number) => new Uint8Array(n).fill(0xab);

describe("execute_direct instruction", () => {
  it("data = disc || vec<u8> action || vec<u8> signature; accounts vault(w) payer(ws) system + remaining", () => {
    const action = { kind: "TransferSol" as const, to: PK_33, lamports: 5n, issuedSlot: 0n, expirySlot: 9n };
    const sig = bogusSig(2508);
    const ix = executeDirectInstruction({ programId: LAMPORT_VAULT_PROGRAM_ID, vault: PK_11, payer: PK_22, action, signature: sig });
    const r = new ByteReader(new Uint8Array(ix.data));
    expect(toHex(r.fixed(8))).toBe(toHex(IX.executeDirect));
    expect(toHex(r.vecU8())).toBe(toHex(encodeAction(action)));
    expect(toHex(r.vecU8())).toBe(toHex(sig));
    r.finish();
    expect(ix.keys.map((k) => [k.pubkey.toBase58(), k.isSigner, k.isWritable])).toEqual([
      [PK_11.toBase58(), false, true],
      [PK_22.toBase58(), true, true],
      [SystemProgram.programId.toBase58(), false, false],
      [PK_33.toBase58(), false, true],
    ]);
  });
});

describe("v1 transaction builder", () => {
  const base = { programId: LAMPORT_VAULT_PROGRAM_ID, vault: PK_11, payer: payer.publicKey, blockhash: BLOCKHASH };

  it("H10 TransferSol: version 0x81, header, config in the header, one instruction, under 4096 bytes", () => {
    const action = { kind: "TransferSol" as const, to: PK_33, lamports: 5n, issuedSlot: 0n, expirySlot: 9n };
    const built = buildDirectV1Transaction({ ...base, action, signature: bogusSig(2508) });
    const m = built.messageBytes;
    expect(m[0]).toBe(V1_VERSION_BYTE);
    // LegacyHeader: 1 required signature (the payer), 0 readonly signed, readonly unsigned = system + program.
    expect([m[1], m[2], m[3]]).toEqual([1, 0, 2]);
    expect(built.size).toBe(m.length + 64);
    expect(built.size).toBeLessThan(V1_MAX_TRANSACTION_BYTES);
    expect(built.unsignedTransaction.length).toBe(built.size);
    expect(toHex(built.unsignedTransaction.subarray(m.length))).toBe(toHex(new Uint8Array(64)));

    const compiled = getCompiledTransactionMessageDecoder().decode(m);
    expect(compiled.version).toBe(1);
    const decompiled = decompileTransactionMessage(compiled);
    expect(decompiled.version).toBe(1);
    if (decompiled.version !== 1) throw new Error("unreachable");
    expect(decompiled.config).toEqual({ computeUnitLimit: 400_000, loadedAccountsDataSizeLimit: DEFAULT_LOADED_ACCOUNTS_DATA_SIZE, priorityFeeLamports: 0n });
    expect(decompiled.feePayer.address).toBe(payer.publicKey.toBase58());
    expect(decompiled.instructions).toHaveLength(1);
    const ix = decompiled.instructions[0]!;
    expect(ix.programAddress).toBe(LAMPORT_VAULT_PROGRAM_ID.toBase58());
    expect(ix.data?.length).toBe(8 + 4 + 57 + 4 + 2508);
    expect(ix.accounts?.map((a) => a.address)).toEqual([PK_11, payer.publicKey, SystemProgram.programId, PK_33].map((k) => k.toBase58()));
    // Bits [0,1] priority fee, [2] compute-unit limit, [3] loaded accounts data size.
    if (compiled.version !== 1) throw new Error("unreachable");
    expect(compiled.configMask).toBe(0b1111);
  });

  it("priority fee and limits pass through; config values are LE in the header", () => {
    const action = { kind: "Rotate" as const, newLmsPubkey: KAT_H10_PUBKEY, issuedSlot: 0n, expirySlot: 9n };
    const built = buildDirectV1Transaction({ ...base, action, signature: bogusSig(2508), computeUnitLimit: 250_000, priorityFeeLamports: 12_345n, loadedAccountsDataSizeLimit: 1 << 20 });
    expect(built.config).toEqual({ computeUnitLimit: 250_000, priorityFeeLamports: 12_345n, loadedAccountsDataSizeLimit: 1 << 20 });
    const decompiled = decompileTransactionMessage(getCompiledTransactionMessageDecoder().decode(built.messageBytes));
    if (decompiled.version !== 1) throw new Error("unreachable");
    expect(decompiled.config).toEqual(built.config);
    // ConfigValues follow the addresses: 4 addresses (payer, vault, system, program) after the 1+3+4+32+1+1 fixed bytes.
    const off = 1 + 3 + 4 + 32 + 1 + 1 + 4 * 32;
    const r = new ByteReader(built.messageBytes.subarray(off, off + 16));
    expect(r.u64()).toBe(12_345n);
    expect(r.u32()).toBe(250_000);
    expect(r.u32()).toBe(1 << 20);
  });

  it("every parameter set and action fits: the largest (H15 TransferToken) stays under 4096", () => {
    const sizes: Record<string, number> = {};
    for (const [label, sigLen] of [["H5", 2348], ["H10", 2508], ["H15", 2668]] as const) {
      const token = { kind: "TransferToken" as const, mint: PK_22, to: PK_33, amount: 1n, issuedSlot: 0n, expirySlot: 9n };
      sizes[label] = buildDirectV1Transaction({ ...base, action: token, signature: bogusSig(sigLen) }).size;
      expect(sizes[label]).toBeLessThan(V1_MAX_TRANSACTION_BYTES);
    }
    expect(sizes["H15"]! - sizes["H5"]!).toBe(2668 - 2348);
    // Four signatures would not fit; the builder refuses instead of producing bytes the cluster drops.
    expect(() => buildDirectV1Transaction({ ...base, action: { kind: "Close", to: PK_33, issuedSlot: 0n, expirySlot: 9n }, signature: bogusSig(4000) })).toThrow(/4096/);
  });

  it("assembleV1Transaction appends exactly num_required_signatures 64-byte signatures", () => {
    const built = buildDirectV1Transaction({ ...base, action: { kind: "Close", to: PK_33, issuedSlot: 0n, expirySlot: 9n }, signature: bogusSig(2348) });
    const sig = new Uint8Array(64).fill(7);
    const wire = assembleV1Transaction(built.messageBytes, [sig]);
    expect(wire.length).toBe(built.size);
    expect(toHex(wire.subarray(0, built.messageBytes.length))).toBe(toHex(built.messageBytes));
    expect(toHex(wire.subarray(built.messageBytes.length))).toBe(toHex(sig));
    expect(v1TransactionSignature(wire)).toBe(getBase58Decoder().decode(sig));
    expect(() => assembleV1Transaction(built.messageBytes, [])).toThrow(/needs 1 signatures/);
    expect(() => assembleV1Transaction(built.messageBytes, [new Uint8Array(63)])).toThrow(/64 bytes/);
    expect(() => assembleV1Transaction(new Uint8Array([0x80, 1]), [sig])).toThrow(/0x81/);
  });

  it("keypairV1Signer produces an ed25519 signature the payer's public key verifies", async () => {
    const built = buildDirectV1Transaction({ ...base, action: { kind: "Close", to: PK_33, issuedSlot: 0n, expirySlot: 9n }, signature: bogusSig(2348) });
    const sig = await keypairV1Signer(payer.secretKey)(built.messageBytes);
    expect(sig.length).toBe(64);
    const pub = await getPublicKeyFromAddress(address(payer.publicKey.toBase58()));
    expect(await verifySignature(pub, sig as never, built.messageBytes)).toBe(true);
    expect(await verifySignature(pub, sig as never, built.messageBytes.map((b) => b ^ 1))).toBe(false);
    expect(() => keypairV1Signer(new Uint8Array(32))).toThrow(/64-byte/);
  });
});

/** A mock cluster that takes legacy bytes (web3.js) and, when `acceptV1`, v1 bytes (kit). */
class MockRpc implements Rpc {
  accounts = new Map<string, Uint8Array>();
  sent: { version: "legacy" | 1; bytes: Uint8Array }[] = [];
  acceptV1 = true;
  /** When set, sendRawTransaction of a v1 transaction throws this message instead. */
  v1SendError: string | null = null;

  async getAccountInfo(pk: PublicKey): Promise<AccountInfo<Buffer> | null> {
    const data = this.accounts.get(pk.toBase58());
    return data ? { data: Buffer.from(data), executable: false, lamports: 1, owner: LAMPORT_VAULT_PROGRAM_ID } : null;
  }
  async getLatestBlockhash() {
    return { blockhash: BLOCKHASH, lastValidBlockHeight: 10 };
  }
  async sendRawTransaction(raw: Buffer | Uint8Array | number[]): Promise<string> {
    const bytes = Uint8Array.from(raw as Uint8Array);
    if (bytes[0] === V1_VERSION_BYTE) {
      if (this.v1SendError) throw new Error(this.v1SendError);
      if (!this.acceptV1) throw new Error("failed to deserialize solana_transaction::versioned::VersionedTransaction: invalid value: continue signal on byte-three, expected a terminal signal on or before byte-three");
      const compiled = getCompiledTransactionMessageDecoder().decode(bytes);
      const msgLen = bytes.length - 64 * compiled.header.numSignerAccounts;
      const pub = await getPublicKeyFromAddress(compiled.staticAccounts[0]!);
      if (!(await verifySignature(pub, bytes.subarray(msgLen, msgLen + 64) as never, bytes.subarray(0, msgLen)))) throw new Error("bad v1 signature");
      this.sent.push({ version: 1, bytes });
    } else {
      const tx = Transaction.from(Buffer.from(bytes));
      if (!tx.verifySignatures()) throw new Error("bad signature");
      this.sent.push({ version: "legacy", bytes });
    }
    return "sig" + this.sent.length;
  }
  async confirmTransaction() {
    return { value: { err: null } };
  }
  async getSlot(): Promise<number> {
    return 1000;
  }
}

function vaultAccount(spentLeaves: number[], extra: Partial<VaultAccount> = {}): Uint8Array {
  const used = new Uint8Array(4);
  for (const q of spentLeaves) used[q >> 3]! |= 1 << (q & 7);
  return encodeVault({ version: 2, bump: 0, vaultId: vaultId(key.publicKey), lmsPubkey: key.publicKey, spent: spentLeaves.length, generation: 0, createdSlot: 1n, used, usedKeys: [], ...extra });
}

/** Decodes the `execute_direct` instruction out of a sent v1 transaction. */
function directInstruction(bytes: Uint8Array): { action: ReturnType<typeof decodeAction>; signature: Uint8Array; accounts: string[] } {
  const compiled = getCompiledTransactionMessageDecoder().decode(bytes);
  const m = decompileTransactionMessage(compiled);
  const ix = m.instructions[0]!;
  const r = new ByteReader(new Uint8Array(ix.data!));
  expect(toHex(r.fixed(8))).toBe(toHex(IX.executeDirect));
  const action = decodeAction(r.vecU8());
  const signature = r.vecU8();
  r.finish();
  return { action, signature, accounts: ix.accounts!.map((a) => a.address as string) };
}

describe("VaultSigner modes", () => {
  const vault = findVaultPdaForKey(LAMPORT_VAULT_PROGRAM_ID, key.publicKey).address;
  const to = PK_33;

  it("direct-v1: one v1 transaction whose LMS signature verifies over the bound message", async () => {
    const rpc = new MockRpc();
    rpc.accounts.set(vault.toBase58(), vaultAccount([0, 1]));
    const signer = new VaultSigner({ rpc, key, payer, mode: "direct-v1", v1Config: { priorityFeeLamports: 1_000n } });
    const seen: number[] = [];
    const res = await signer.execute({ kind: "TransferSol", to, lamports: 7n }, { onTransaction: (i) => seen.push(i) });
    expect(res.mode).toBe("direct-v1");
    expect(res.q).toBe(2);
    expect(res.signatures).toEqual(["sig1"]);
    expect(seen).toEqual([0]);
    expect(rpc.sent).toHaveLength(1);
    expect(rpc.sent[0]!.version).toBe(1);
    if (res.mode !== "direct-v1") throw new Error("unreachable");
    expect(toHex(res.transactionBytes)).toBe(toHex(rpc.sent[0]!.bytes));
    const { action, signature, accounts } = directInstruction(rpc.sent[0]!.bytes);
    expect(action).toEqual(res.action);
    expect(toHex(signature)).toBe(toHex(res.lmsSignature));
    expect(accounts).toEqual([vault, payer.publicKey, SystemProgram.programId, to].map((k) => k.toBase58()));
    expect(lmsVerify(key.publicKey, vaultMessage(vault, 0, encodeAction(action)), signature)).toBe(true);
    const m = decompileTransactionMessage(getCompiledTransactionMessageDecoder().decode(rpc.sent[0]!.bytes));
    if (m.version !== 1) throw new Error("unreachable");
    expect(m.config?.priorityFeeLamports).toBe(1_000n);
    expect(m.config?.computeUnitLimit).toBe(400_000);
  });

  it("auto: falls back to the staged flow with the same leaf when the RPC rejects v1 bytes", async () => {
    const rpc = new MockRpc();
    rpc.acceptV1 = false;
    rpc.accounts.set(vault.toBase58(), vaultAccount([]));
    const signer = new VaultSigner({ rpc, key, payer, mode: "auto" });
    const fallbacks: unknown[] = [];
    const res = await signer.execute({ kind: "TransferSol", to, lamports: 7n }, { nonce: 5n, onFallback: (e) => fallbacks.push(e) });
    expect(res.mode).toBe("staged");
    expect(res.q).toBe(0);
    expect(fallbacks).toHaveLength(1);
    expect(fallbacks[0]).toBeInstanceOf(DirectV1Error);
    expect((fallbacks[0] as DirectV1Error).stage).toBe("send");
    // H5: open (708) + 900 + 740, then execute: 4 legacy transactions, nothing else went out.
    expect(res.signatures).toEqual(["sig1", "sig2", "sig3", "sig4"]);
    expect(rpc.sent.map((t) => t.version)).toEqual(["legacy", "legacy", "legacy", "legacy"]);
    expect(res.sigBuffer).toBeInstanceOf(PublicKey);
    // Only one leaf was reserved: the direct attempt and the staged flow carried the same signature.
    expect(await signer.nextQ()).toBe(1);
  });

  it("auto: a transaction that ran and failed is not a v1 rejection; it propagates", async () => {
    const rpc = new MockRpc();
    rpc.v1SendError = "Transaction simulation failed: Error processing Instruction 0: custom program error: 0x177c";
    rpc.accounts.set(vault.toBase58(), vaultAccount([]));
    const signer = new VaultSigner({ rpc, key, payer, mode: "auto" });
    await expect(signer.execute({ kind: "TransferSol", to, lamports: 7n })).rejects.toThrow(/0x177c/);
    expect(rpc.sent).toHaveLength(0);
  });

  it("direct-v1 never falls back; a wallet refusing to sign counts as a rejection in auto", async () => {
    const rpc = new MockRpc();
    rpc.acceptV1 = false;
    rpc.accounts.set(vault.toBase58(), vaultAccount([]));
    const strict = new VaultSigner({ rpc, key, payer, mode: "direct-v1" });
    await expect(strict.execute({ kind: "TransferSol", to, lamports: 7n })).rejects.toBeInstanceOf(DirectV1Error);
    expect(rpc.sent).toHaveLength(0);

    const refusing = new VaultSigner({ rpc, key, payer, mode: "auto", v1Signer: async () => { throw new Error("wallet: unsupported transaction version"); } });
    const res = await refusing.execute({ kind: "TransferSol", to, lamports: 7n });
    expect(res.mode).toBe("staged");
    expect(rpc.sent).toHaveLength(4);
  });

  it("default mode is staged; a per-call mode overrides the signer's", async () => {
    const rpc = new MockRpc();
    rpc.accounts.set(vault.toBase58(), vaultAccount([]));
    const signer = new VaultSigner({ rpc, key, payer });
    const staged = await signer.execute({ kind: "TransferSol", to, lamports: 7n });
    expect(staged.mode).toBe("staged");
    const direct = await signer.execute({ kind: "TransferSol", to, lamports: 7n }, { mode: "direct-v1" });
    expect(direct.mode).toBe("direct-v1");
    expect(direct.q).toBe(1);
    expect(rpc.sent.map((t) => t.version)).toEqual(["legacy", "legacy", "legacy", "legacy", 1]);
  });

  it("isV1Rejection: only sign failures and non-execution send failures", () => {
    expect(isV1Rejection(new DirectV1Error("sign", new Error("nope")))).toBe(true);
    expect(isV1Rejection(new DirectV1Error("send", new Error("failed to deserialize")))).toBe(true);
    expect(isV1Rejection(new DirectV1Error("send", new Error("invalid transaction: unsupported version")))).toBe(true);
    expect(isV1Rejection(new DirectV1Error("send", new Error("Error processing Instruction 0: custom program error: 0x1778")))).toBe(false);
    expect(isV1Rejection(new DirectV1Error("confirm", new Error("failed")))).toBe(false);
    expect(isV1Rejection(new Error("failed to deserialize"))).toBe(false);
  });

  it("H10 and H15 vaults build direct transactions too", () => {
    for (const lmsType of [LMS_SHA256_M32_H10, LMS_SHA256_M32_H15]) {
      const sigLen = { [LMS_SHA256_M32_H10]: 2508, [LMS_SHA256_M32_H15]: 2668 }[lmsType]!;
      const built = buildDirectV1Transaction({ programId: LAMPORT_VAULT_PROGRAM_ID, vault, payer: payer.publicKey, blockhash: BLOCKHASH, action: { kind: "TransferSol", to, lamports: 1n, issuedSlot: 0n, expirySlot: 1n }, signature: bogusSig(sigLen) });
      expect(built.size).toBeLessThan(V1_MAX_TRANSACTION_BYTES);
    }
  });
});
