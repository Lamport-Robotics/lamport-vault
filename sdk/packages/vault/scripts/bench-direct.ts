/**
 * Devnet benchmark: the one-transaction `execute_direct` path (transaction v1) against the
 * staged `open_sig_buffer` / `write_sig` / `execute` path, on a fresh H10 vault.
 *
 *   node packages/vault/scripts/bench-direct.ts        (from sdk/)
 *
 * Environment: BENCH_RPC (default https://api.devnet.solana.com), BENCH_KEYPAIR (default
 * ~/.config/solana/pith-dev.json, pays everything). The vault is closed at the end, so the run
 * costs fees, rent of the temporary token accounts and whatever lands in the recipient.
 *
 * For every measured execution it prints: transactions sent, bytes on the wire (v1: the one
 * transaction; staged: the sum), compute units consumed, fee in lamports and wall-clock from the
 * first send to the last confirmation. Bytes, compute and fees are read back from the chain
 * with getTransaction (maxSupportedTransactionVersion 1 for v1, encoding base64).
 */
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { performance } from "node:perf_hooks";
import { createSolanaRpc, signature as asSignature } from "@solana/kit";
import { createMint, getOrCreateAssociatedTokenAccount, mintTo } from "@solana/spl-token";
import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram, Transaction, type TransactionInstruction } from "@solana/web3.js";
import { LMS_SHA256_M32_H10, LmsPrivateKey } from "../../lms/src/index.ts";
import type { Action } from "../src/action.ts";
import { keypairV1Signer, sendDirectV1 } from "../src/direct.ts";
import { buildStagedExecution, type CloseTokenAccount } from "../src/instructions.ts";
import { LAMPORT_VAULT_PROGRAM_ID } from "../src/programIds.ts";
import { randomNonce, sendAndConfirm, type SignedAction, VaultSigner } from "../src/signer.ts";

const RPC = process.env.BENCH_RPC ?? "https://api.devnet.solana.com";
const KEYPAIR = process.env.BENCH_KEYPAIR ?? `${homedir()}/.config/solana/pith-dev.json`;
const COMMITMENT = "confirmed" as const;

const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(KEYPAIR, "utf8"))));
const connection = new Connection(RPC, COMMITMENT);
const kit = createSolanaRpc(RPC);

interface Measured {
  path: "direct-v1" | "staged";
  action: string;
  transactions: number;
  bytes: number;
  computeUnits: number;
  feeLamports: number;
  wallClockMs: number;
  signatures: string[];
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The public devnet RPC rate-limits bursts (HTTP 429); wait and retry those. */
async function withRateLimitRetry<T>(call: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await call();
    } catch (e) {
      const status = (e as { context?: { statusCode?: number } })?.context?.statusCode;
      if (status !== 429 || attempt >= 10) throw e;
      await sleep(5_000);
    }
  }
}

/** Bytes, compute units and fee of a confirmed transaction, read back from the cluster. */
async function stats(sig: string, version: 0 | 1): Promise<{ bytes: number; cu: number; fee: number }> {
  for (let attempt = 0; ; attempt++) {
    const tx = await withRateLimitRetry(() =>
      kit.getTransaction(asSignature(sig), { commitment: COMMITMENT, encoding: "base64", maxSupportedTransactionVersion: version }).send(),
    );
    if (tx?.meta) {
      if (tx.meta.err) throw new Error(`${sig} failed on chain: ${JSON.stringify(tx.meta.err)}`);
      return { bytes: Buffer.from(tx.transaction[0], "base64").length, cu: Number(tx.meta.computeUnitsConsumed ?? 0), fee: Number(tx.meta.fee) };
    }
    if (attempt >= 20) throw new Error(`getTransaction(${sig}) still empty after ${attempt} attempts`);
    await sleep(1000);
  }
}

async function measureDirect(signer: VaultSigner, label: string, signed: SignedAction, extra: { closeTokenAccounts?: CloseTokenAccount[] } = {}): Promise<Measured> {
  const t0 = performance.now();
  const res = await sendDirectV1(connection, keypairV1Signer(payer.secretKey), {
    programId: signer.programId,
    vault: signer.vault,
    payer: payer.publicKey,
    action: signed.action,
    signature: signed.lmsSignature,
    commitment: COMMITMENT,
    ...extra,
  });
  const wallClockMs = performance.now() - t0;
  const s = await stats(res.signature, 1);
  if (s.bytes !== res.transactionBytes.length) throw new Error(`wire size mismatch: sent ${res.transactionBytes.length}, chain says ${s.bytes}`);
  return { path: "direct-v1", action: label, transactions: 1, bytes: s.bytes, computeUnits: s.cu, feeLamports: s.fee, wallClockMs, signatures: [res.signature] };
}

async function measureStaged(signer: VaultSigner, label: string, signed: SignedAction): Promise<Measured> {
  const staged = buildStagedExecution({ programId: signer.programId, vault: signer.vault, payer: payer.publicKey, nonce: randomNonce(), action: signed.action, signature: signed.lmsSignature });
  const t0 = performance.now();
  const signatures: string[] = [];
  for (const ixs of staged.transactions) signatures.push(await sendAndConfirm(connection, [payer], ixs as TransactionInstruction[], { commitment: COMMITMENT }));
  const wallClockMs = performance.now() - t0;
  let bytes = 0, cu = 0, fee = 0;
  for (const sig of signatures) {
    const s = await stats(sig, 0);
    bytes += s.bytes;
    cu += s.cu;
    fee += s.fee;
  }
  return { path: "staged", action: label, transactions: signatures.length, bytes, computeUnits: cu, feeLamports: fee, wallClockMs, signatures };
}

function row(m: Measured): string {
  return `| ${m.path} | ${m.action} | ${m.transactions} | ${m.bytes} | ${m.computeUnits} | ${m.feeLamports} | ${Math.round(m.wallClockMs)} |`;
}

async function main(): Promise<void> {
  console.log(`rpc ${RPC}`);
  console.log(`payer ${payer.publicKey.toBase58()} balance ${(await connection.getBalance(payer.publicKey)) / LAMPORTS_PER_SOL} SOL`);
  console.log(`cluster ${(await connection.getVersion())["solana-core"]}`);

  console.log("generating H10 keys A and B (tree construction)...");
  const keyA = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H10, lmotsType: 3, seed: Keypair.generate().secretKey.subarray(0, 32), I: Keypair.generate().secretKey.subarray(0, 16) });
  const keyB = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H10, lmotsType: 3, seed: Keypair.generate().secretKey.subarray(0, 32), I: Keypair.generate().secretKey.subarray(0, 16) });
  const signerA = new VaultSigner({ rpc: connection, key: keyA, payer, commitment: COMMITMENT });
  const { vault, signature: createSig } = await signerA.createVault();
  console.log(`vault ${vault.toBase58()} created in ${createSig}`);

  const deposit = 0.02 * LAMPORTS_PER_SOL;
  await sendAndConfirm(connection, [payer], [SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: vault, lamports: deposit })], { commitment: COMMITMENT });
  console.log(`deposited ${deposit / LAMPORTS_PER_SOL} SOL`);

  const recipient = Keypair.generate().publicKey;
  const results: Measured[] = [];

  // 1. TransferSol, direct v1.
  const transfer: Omit<Extract<Action, { kind: "TransferSol" }>, "expirySlot"> = { kind: "TransferSol", to: recipient, lamports: BigInt(0.002 * LAMPORTS_PER_SOL) };
  results.push(await measureDirect(signerA, "TransferSol", await signerA.sign(transfer)));
  console.log(row(results.at(-1)!));

  // 2. TransferSol, staged.
  results.push(await measureStaged(signerA, "TransferSol", await signerA.sign(transfer)));
  console.log(row(results.at(-1)!));

  // 3. TransferToken, direct v1 (Token program; the vault's ATA is emptied so Close can reclaim it).
  const mint = await createMint(connection, payer, payer.publicKey, null, 6, undefined, { commitment: COMMITMENT });
  const vaultAta = await getOrCreateAssociatedTokenAccount(connection, payer, mint, vault, true, COMMITMENT);
  const payerAta = await getOrCreateAssociatedTokenAccount(connection, payer, mint, payer.publicKey, false, COMMITMENT);
  const amount = 1_000_000n;
  await mintTo(connection, payer, mint, vaultAta.address, payer, amount, [], { commitment: COMMITMENT });
  console.log(`mint ${mint.toBase58()}, vault token account ${vaultAta.address.toBase58()} holds ${amount}`);
  results.push(await measureDirect(signerA, "TransferToken", await signerA.sign({ kind: "TransferToken", mint, to: payerAta.address, amount })));
  console.log(row(results.at(-1)!));

  // 4. Rotate to key B, direct v1 (payer pays the 16-byte rent delta).
  const vaultBefore = await connection.getBalance(vault, COMMITMENT);
  results.push(await measureDirect(signerA, "Rotate", await signerA.sign({ kind: "Rotate", newLmsPubkey: keyB.publicKey })));
  console.log(row(results.at(-1)!));
  const vaultAfter = await connection.getBalance(vault, COMMITMENT);
  const v = await new VaultSigner({ rpc: connection, key: keyB, payer, vault, commitment: COMMITMENT }).fetchVault();
  console.log(`after Rotate: generation ${v.generation}, spent ${v.spent}, history ${v.usedKeys.length}, vault lamports +${vaultAfter - vaultBefore} (rent for 16 bytes)`);

  // 5. Close, direct v1, with the now-empty token account; everything back to the payer.
  const signerB = new VaultSigner({ rpc: connection, key: keyB, payer, vault, commitment: COMMITMENT });
  results.push(
    await measureDirect(signerB, "Close", await signerB.sign({ kind: "Close", to: payer.publicKey }), { closeTokenAccounts: [{ account: vaultAta.address }] }),
  );
  console.log(row(results.at(-1)!));
  if (await connection.getAccountInfo(vault, COMMITMENT)) throw new Error("vault still exists after Close");

  console.log("\n| path | action | transactions | bytes on the wire | compute units | fee (lamports) | wall-clock (ms) |");
  console.log("|---|---|---|---|---|---|---|");
  for (const m of results) console.log(row(m));
  console.log("\nsignatures:");
  for (const m of results) console.log(`  ${m.path} ${m.action}: ${m.signatures.join(", ")}`);
  console.log(`\npayer balance ${(await connection.getBalance(payer.publicKey)) / LAMPORTS_PER_SOL} SOL`);
  console.log(JSON.stringify({ rpc: RPC, program: LAMPORT_VAULT_PROGRAM_ID.toBase58(), vault: vault.toBase58(), results }, (_, x) => (typeof x === "bigint" ? x.toString() : x), 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
