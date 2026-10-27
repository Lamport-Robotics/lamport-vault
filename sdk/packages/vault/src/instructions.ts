/**
 * Instruction builders for `lamport-vault`. Data = Anchor discriminator || Borsh args. Account
 * order follows the `#[derive(Accounts)]` structs in `programs/lamport-vault/src/lib.rs`:
 *
 *   create_vault(vault_id, lms_pubkey)                payer(ws) vault(w) system_program
 *   open_sig_buffer(nonce, action, sig_len, first_chunk)  payer(ws) vault sig_buffer(w) system_program
 *   write_sig(offset, chunk)                          payer(s) sig_buffer(w)
 *   close_sig_buffer()                                payer(ws) sig_buffer(w)
 *   execute()                                         vault(w) sig_buffer(w) payer(w) + per-action remaining accounts
 *   sweep_closed()                                    payer(ws) tombstone heir(w) heir_token_account(w) vault_token_account(w)
 *                                                     mint token_program system_program associated_token_program
 */
import {
  ComputeBudgetProgram,
  PACKET_DATA_SIZE,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  type AccountMeta,
} from "@solana/web3.js";
import { type Action, encodeAction } from "./action.ts";
import { ByteWriter } from "./borsh.ts";
import { chunkSignature, MAX_CHUNK_BYTES, type SigChunk } from "./chunk.ts";
import { IX } from "./discriminator.ts";
import { ASSOCIATED_TOKEN_PROGRAM_ID, associatedTokenAddress, findSigBufferPda, findVaultPda, TOKEN_PROGRAM_ID, vaultId } from "./pda.ts";

/** Compute budget requested for `execute` (docs/DESIGN.md Section 6). */
export const EXECUTE_COMPUTE_UNITS = 400_000;

const w = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: false, isWritable: true });
const ws = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: true, isWritable: true });
const s = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: true, isWritable: false });
const r = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: false, isWritable: false });

export interface CreateVaultParams {
  programId: PublicKey;
  payer: PublicKey;
  /** 56-byte LMS public key; the vault address is derived from it */
  lmsPubkey: Uint8Array;
}

export function createVaultInstruction(p: CreateVaultParams): { instruction: TransactionInstruction; vault: PublicKey } {
  if (p.lmsPubkey.length !== 56) throw new Error("lms_pubkey must be 56 bytes");
  const id = vaultId(p.lmsPubkey);
  const vault = findVaultPda(p.programId, id).address;
  // vault_id travels explicitly (the program re-derives and checks it) so the PDA seed is a plain argument.
  const data = new ByteWriter().raw(IX.createVault).fixed(id, 32).fixed(p.lmsPubkey, 56).bytes();
  return {
    vault,
    instruction: new TransactionInstruction({
      programId: p.programId,
      keys: [ws(p.payer), w(vault), r(SystemProgram.programId)],
      data: Buffer.from(data),
    }),
  };
}

export interface OpenSigBufferParams {
  programId: PublicKey;
  vault: PublicKey;
  payer: PublicKey;
  nonce: bigint;
  /** Borsh-encoded Action, 1..256 bytes */
  action: Uint8Array;
  sigLen: number;
  /** First signature bytes, written at offset 0 in the same transaction. Empty by default. */
  firstChunk?: Uint8Array;
}

export function openSigBufferInstruction(p: OpenSigBufferParams): { instruction: TransactionInstruction; sigBuffer: PublicKey } {
  if (p.action.length === 0 || p.action.length > 256) throw new Error("action must be 1..256 bytes");
  const first = p.firstChunk ?? new Uint8Array(0);
  if (first.length > p.sigLen) throw new Error("first_chunk longer than sig_len");
  const sigBuffer = findSigBufferPda(p.programId, p.vault, p.payer, p.nonce).address;
  const data = new ByteWriter().raw(IX.openSigBuffer).u64(p.nonce).vecU8(p.action).u16(p.sigLen).vecU8(first).bytes();
  return {
    sigBuffer,
    instruction: new TransactionInstruction({
      programId: p.programId,
      keys: [ws(p.payer), r(p.vault), w(sigBuffer), r(SystemProgram.programId)],
      data: Buffer.from(data),
    }),
  };
}

/**
 * How many signature bytes fit in `open_sig_buffer`'s `first_chunk` while the transaction stays
 * under the packet limit. Measured by serializing the instruction with an empty chunk; a few
 * bytes of margin cover the compact-u16 length growth.
 */
export function openSigBufferFirstChunkCapacity(p: Omit<OpenSigBufferParams, "firstChunk">): number {
  const { instruction } = openSigBufferInstruction({ ...p, firstChunk: new Uint8Array(0) });
  const tx = new Transaction({ feePayer: p.payer, blockhash: PublicKey.default.toBase58(), lastValidBlockHeight: 0 }).add(instruction);
  const size = tx.serialize({ requireAllSignatures: false, verifySignatures: false }).length;
  const margin = 4;
  return Math.max(0, Math.min(p.sigLen, MAX_CHUNK_BYTES, PACKET_DATA_SIZE - size - margin));
}

export interface WriteSigParams {
  programId: PublicKey;
  sigBuffer: PublicKey;
  payer: PublicKey;
  offset: number;
  chunk: Uint8Array;
}

export function writeSigInstruction(p: WriteSigParams): TransactionInstruction {
  if (p.chunk.length === 0 || p.chunk.length > MAX_CHUNK_BYTES) throw new Error(`chunk must be 1..${MAX_CHUNK_BYTES} bytes`);
  const data = new ByteWriter().raw(IX.writeSig).u16(p.offset).vecU8(p.chunk).bytes();
  return new TransactionInstruction({
    programId: p.programId,
    keys: [s(p.payer), w(p.sigBuffer)],
    data: Buffer.from(data),
  });
}

/** One `write_sig` instruction per chunk of `signature` starting at `startOffset`. */
export function writeSigInstructions(
  p: Omit<WriteSigParams, "offset" | "chunk"> & { signature: Uint8Array; startOffset?: number; chunkSize?: number },
): { chunks: SigChunk[]; instructions: TransactionInstruction[] } {
  const start = p.startOffset ?? 0;
  const chunks = chunkSignature(p.signature.subarray(start), p.chunkSize ?? MAX_CHUNK_BYTES).map((c) => ({
    offset: c.offset + start,
    bytes: c.bytes,
  }));
  return {
    chunks,
    instructions: chunks.map((c) =>
      writeSigInstruction({ programId: p.programId, sigBuffer: p.sigBuffer, payer: p.payer, offset: c.offset, chunk: c.bytes }),
    ),
  };
}

export interface CloseSigBufferParams {
  programId: PublicKey;
  sigBuffer: PublicKey;
  payer: PublicKey;
}

export function closeSigBufferInstruction(p: CloseSigBufferParams): TransactionInstruction {
  return new TransactionInstruction({
    programId: p.programId,
    keys: [ws(p.payer), w(p.sigBuffer)],
    data: Buffer.from(IX.closeSigBuffer),
  });
}

/** An empty vault-owned token account to close along with the vault (`Close` action). */
export interface CloseTokenAccount {
  account: PublicKey;
  tokenProgram?: PublicKey;
}

export interface ExecuteParams {
  programId: PublicKey;
  vault: PublicKey;
  sigBuffer: PublicKey;
  /** the buffer's rent payer, receives the refund */
  payer: PublicKey;
  /** the action the buffer was opened with; decides the remaining accounts */
  action: Action;
  /** Token program for TransferToken (Token or Token-2022). Default: Token. */
  tokenProgram?: PublicKey;
  /** For `Close`: empty token accounts owned by the vault to close to `to` in the same instruction. */
  closeTokenAccounts?: CloseTokenAccount[];
  /** For `TransferToken`: the vault-owned token account to draw from. Default: the vault's associated token account. */
  source?: PublicKey;
  /** For `TransferToken` on a Token-2022 mint with a transfer hook: the hook program and its extra account metas, passed through to the token program. */
  extraAccounts?: AccountMeta[];
}

/** Remaining accounts `execute` needs for an action (docs/DESIGN.md "Actions", program `execute` doc). */
export function executeRemainingAccounts(
  vault: PublicKey,
  action: Action,
  tokenProgram = TOKEN_PROGRAM_ID,
  closeTokenAccounts: CloseTokenAccount[] = [],
  source?: PublicKey,
  extraAccounts: AccountMeta[] = [],
): AccountMeta[] {
  switch (action.kind) {
    case "TransferSol":
      return [w(action.to)];
    case "TransferToken":
      return [w(source ?? associatedTokenAddress(vault, action.mint, tokenProgram)), w(action.to), r(action.mint), r(tokenProgram), ...extraAccounts];
    case "Rotate":
      return [];
    case "Close":
      return [w(action.to), ...closeTokenAccounts.flatMap((t) => [w(t.account), r(t.tokenProgram ?? TOKEN_PROGRAM_ID)])];
    case "TransferTokenFrom":
      // the signature names the source; a different `source` here would only fail on chain (WrongSource)
      if (source && !source.equals(action.from)) throw new Error(`source ${source.toBase58()} differs from the signed action's from ${action.from.toBase58()}`);
      return [w(action.from), w(action.to), r(action.mint), r(tokenProgram), ...extraAccounts];
  }
}

export function executeInstruction(p: ExecuteParams): TransactionInstruction {
  return new TransactionInstruction({
    programId: p.programId,
    keys: [w(p.vault), w(p.sigBuffer), w(p.payer), ...executeRemainingAccounts(p.vault, p.action, p.tokenProgram, p.closeTokenAccounts, p.source, p.extraAccounts)],
    data: Buffer.from(IX.execute),
  });
}

/** `execute` preceded by the compute-budget request; put both in one transaction, in this order. */
export function executeInstructions(p: ExecuteParams, computeUnits = EXECUTE_COMPUTE_UNITS): TransactionInstruction[] {
  return [ComputeBudgetProgram.setComputeUnitLimit({ units: computeUnits }), executeInstruction(p)];
}

/** The instruction set for one full staged execution: open (with first chunk), writes, execute. */
export interface StagedExecution {
  sigBuffer: PublicKey;
  actionBytes: Uint8Array;
  /** bytes carried by `open_sig_buffer` */
  firstChunk: Uint8Array;
  open: TransactionInstruction;
  writes: TransactionInstruction[];
  chunks: SigChunk[];
  execute: TransactionInstruction[];
  /** One entry per transaction, in order: [open], [write]..., [compute budget, execute]. */
  transactions: TransactionInstruction[][];
}

export interface StagedExecutionParams {
  programId: PublicKey;
  vault: PublicKey;
  payer: PublicKey;
  nonce: bigint;
  action: Action;
  signature: Uint8Array;
  /** Bytes to put in `open_sig_buffer`; default: as many as fit ("auto"); 0 for none. */
  firstChunkSize?: number | "auto";
  chunkSize?: number;
  tokenProgram?: PublicKey;
  closeTokenAccounts?: CloseTokenAccount[];
  /** TransferToken: the vault-owned token account to draw from. Default: the vault's associated token account. */
  source?: PublicKey;
  computeUnits?: number;
}

export function buildStagedExecution(p: StagedExecutionParams): StagedExecution {
  const actionBytes = encodeAction(p.action);
  const base = { programId: p.programId, vault: p.vault, payer: p.payer, nonce: p.nonce, action: actionBytes, sigLen: p.signature.length };
  const firstLen = p.firstChunkSize === undefined || p.firstChunkSize === "auto" ? openSigBufferFirstChunkCapacity(base) : p.firstChunkSize;
  if (firstLen < 0 || firstLen > p.signature.length) throw new RangeError("firstChunkSize out of range");
  const firstChunk = p.signature.slice(0, firstLen);
  const { instruction: open, sigBuffer } = openSigBufferInstruction({ ...base, firstChunk });
  const { chunks, instructions: writes } =
    firstLen < p.signature.length
      ? writeSigInstructions({
          programId: p.programId,
          sigBuffer,
          payer: p.payer,
          signature: p.signature,
          startOffset: firstLen,
          ...(p.chunkSize !== undefined ? { chunkSize: p.chunkSize } : {}),
        })
      : { chunks: [], instructions: [] };
  const execute = executeInstructions(
    {
      programId: p.programId,
      vault: p.vault,
      sigBuffer,
      payer: p.payer,
      action: p.action,
      ...(p.tokenProgram ? { tokenProgram: p.tokenProgram } : {}),
      ...(p.closeTokenAccounts ? { closeTokenAccounts: p.closeTokenAccounts } : {}),
      ...(p.source ? { source: p.source } : {}),
    },
    p.computeUnits ?? EXECUTE_COMPUTE_UNITS,
  );
  return { sigBuffer, actionBytes, firstChunk, open, writes, chunks, execute, transactions: [[open], ...writes.map((ix) => [ix]), execute] };
}

export interface SweepClosedParams {
  programId: PublicKey;
  /** Pays for the heir's associated token account if it has to be created; any key. */
  payer: PublicKey;
  /** The closed vault's address (its `Tombstone`). */
  vault: PublicKey;
  /** The tombstone's `heir`; the program refuses any other account (`WrongHeir`). */
  heir: PublicKey;
  mint: PublicKey;
  /** A token account for `mint` still owned by the closed vault. */
  vaultTokenAccount: PublicKey;
  /** Token or Token-2022: the program that owns `mint`. Default: Token. */
  tokenProgram?: PublicKey;
  /** A Token-2022 transfer hook's program and extra account metas, passed through to the token program. */
  extraAccounts?: AccountMeta[];
}

/**
 * `sweep_closed`: moves the whole balance of `vaultTokenAccount` to the heir's associated token
 * account for the mint (created in the same instruction when missing, rent from `payer`) and closes
 * the vault's token account, its rent to the heir. Permissionless; the destination is fixed by the
 * tombstone. Fails `VaultNotClosed` on a live vault.
 */
export interface SweepClosedSolParams {
  programId: PublicKey;
  /** the closed vault's address (the tombstone) */
  vault: PublicKey;
  /** must be the tombstone's heir; the program checks */
  heir: PublicKey;
}

/**
 * `sweep_closed_sol`: SOL that landed on a closed vault's address after the `Close` goes to the heir
 * named by the tombstone. Permissionless; the tombstone keeps its rent. Fails `WrongHeir` on any other
 * destination and `VaultNotClosed` on a live vault.
 */
export function sweepClosedSolInstruction(p: SweepClosedSolParams): TransactionInstruction {
  return new TransactionInstruction({ programId: p.programId, keys: [w(p.vault), w(p.heir)], data: Buffer.from(IX.sweepClosedSol) });
}

export function sweepClosedInstruction(p: SweepClosedParams): { instruction: TransactionInstruction; heirTokenAccount: PublicKey } {
  const tokenProgram = p.tokenProgram ?? TOKEN_PROGRAM_ID;
  const heirTokenAccount = associatedTokenAddress(p.heir, p.mint, tokenProgram);
  return {
    heirTokenAccount,
    instruction: new TransactionInstruction({
      programId: p.programId,
      keys: [
        ws(p.payer),
        r(p.vault),
        w(p.heir),
        w(heirTokenAccount),
        w(p.vaultTokenAccount),
        r(p.mint),
        r(tokenProgram),
        r(SystemProgram.programId),
        r(ASSOCIATED_TOKEN_PROGRAM_ID),
        ...(p.extraAccounts ?? []),
      ],
      data: Buffer.from(IX.sweepClosed),
    }),
  };
}
