/**
 * The one-transaction path. `execute_direct` carries the action and the whole LMS signature in
 * its instruction data, which only fits a **transaction v1** (SIMD-0385 / SIMD-0296): 4096 bytes
 * on the wire, version byte 0x81, the compute-unit limit, priority fee and loaded-accounts-data
 * limit in the message header instead of ComputeBudget instructions, no address lookup tables,
 * signatures appended after the message.
 *
 * Serialisation is delegated to `@solana/kit` 8.x (`createTransactionMessage({ version: 1 })`,
 * `compileTransaction`); the signature envelope is assembled here because it is one
 * concatenation. `@solana/web3.js` 1.x can neither build nor parse v1, so it only serves as the
 * transport (`Rpc.sendRawTransaction` forwards bytes untouched) and as the key type used by the
 * rest of this package.
 */
import {
  AccountRole,
  address,
  appendTransactionMessageInstructions,
  blockhash as asBlockhash,
  compileTransaction,
  createKeyPairFromBytes,
  createTransactionMessage,
  getBase58Decoder,
  type Instruction,
  pipe,
  setTransactionMessageConfig,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  signBytes,
} from "@solana/kit";
import { type Commitment, PublicKey, SystemProgram, TransactionInstruction, type AccountMeta } from "@solana/web3.js";
import { type Action, encodeAction } from "./action.ts";
import { ByteWriter } from "./borsh.ts";
import { IX } from "./discriminator.ts";
import { type CloseTokenAccount, EXECUTE_COMPUTE_UNITS, executeRemainingAccounts } from "./instructions.ts";
import type { Rpc } from "./signer.ts";

/** First byte of every v1 transaction / message (SIMD-0385). */
export const V1_VERSION_BYTE = 0x81;
/** Largest v1 transaction, signatures included (SIMD-0296). */
export const V1_MAX_TRANSACTION_BYTES = 4096;
/**
 * Default `loadedAccountsDataSizeLimit` for a direct execution. A v1 transaction that leaves
 * this unset is budgeted zero bytes and fails to load its accounts; `execute_direct` loads the
 * vault program (about 310 KB) plus, for TransferToken, Token or Token-2022. 2 MiB covers all
 * of it with room to spare.
 */
export const DEFAULT_LOADED_ACCOUNTS_DATA_SIZE = 2 * 1024 * 1024;

const w = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: false, isWritable: true });
const ws = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: true, isWritable: true });
const r = (pubkey: PublicKey): AccountMeta => ({ pubkey, isSigner: false, isWritable: false });

export interface ExecuteDirectParams {
  programId: PublicKey;
  vault: PublicKey;
  /** Signs the transaction; on `Rotate` also pays the vault's 16-byte rent delta. */
  payer: PublicKey;
  action: Action;
  /** The LMS signature over `vaultMessage(vault, generation, encodeAction(action))`. */
  signature: Uint8Array;
  /** Token program for TransferToken (Token or Token-2022). Default: Token. */
  tokenProgram?: PublicKey;
  /** For `Close`: empty token accounts owned by the vault to close to `to` in the same instruction. */
  closeTokenAccounts?: CloseTokenAccount[];
  /** For `TransferToken`: the vault-owned token account to draw from. Default: the vault's associated token account. */
  source?: PublicKey;
}

/**
 * `execute_direct(action, signature)`: accounts `vault(w) payer(ws) system_program` followed by
 * the same remaining accounts as `execute`. Data = discriminator || vec<u8> action || vec<u8> signature.
 */
export function executeDirectInstruction(p: ExecuteDirectParams): TransactionInstruction {
  const actionBytes = encodeAction(p.action);
  if (actionBytes.length === 0 || actionBytes.length > 256) throw new Error("action must be 1..256 bytes");
  const data = new ByteWriter().raw(IX.executeDirect).vecU8(actionBytes).vecU8(p.signature).bytes();
  return new TransactionInstruction({
    programId: p.programId,
    keys: [w(p.vault), ws(p.payer), r(SystemProgram.programId), ...executeRemainingAccounts(p.vault, p.action, p.tokenProgram, p.closeTokenAccounts, p.source)],
    data: Buffer.from(data),
  });
}

/** The header configuration of a v1 transaction (replaces ComputeBudget instructions). */
export interface V1Config {
  /** Required in practice: an unset limit budgets zero compute units. Default 400 000. */
  computeUnitLimit?: number;
  /** Total priority fee for the whole transaction, in lamports (not a per-CU price). Default 0. */
  priorityFeeLamports?: bigint;
  /** Default {@link DEFAULT_LOADED_ACCOUNTS_DATA_SIZE}. */
  loadedAccountsDataSizeLimit?: number;
}

export interface DirectV1Params extends ExecuteDirectParams, V1Config {
  /** Recent blockhash (the message's lifetime specifier). */
  blockhash: string;
  /** Only carried along for confirmation; not part of the bytes. */
  lastValidBlockHeight?: number;
}

export interface DirectV1Transaction {
  instruction: TransactionInstruction;
  /** The compiled v1 message, starting with 0x81: exactly what the payer signs (ed25519). */
  messageBytes: Uint8Array;
  /** `messageBytes` followed by one zeroed 64-byte signature slot: what a wallet `signTransaction` takes. */
  unsignedTransaction: Uint8Array;
  /** Bytes on the wire once signed: `messageBytes.length + 64`. */
  size: number;
  /** The configuration written into the header. */
  config: Required<V1Config>;
}

function toKitInstruction(ix: TransactionInstruction): Instruction {
  return {
    programAddress: address(ix.programId.toBase58()),
    accounts: ix.keys.map((k) => ({
      address: address(k.pubkey.toBase58()),
      role: k.isSigner ? (k.isWritable ? AccountRole.WRITABLE_SIGNER : AccountRole.READONLY_SIGNER) : k.isWritable ? AccountRole.WRITABLE : AccountRole.READONLY,
    })),
    data: new Uint8Array(ix.data),
  };
}

/**
 * Builds the v1 transaction for one `execute_direct`. Pure. Throws if the result would exceed
 * 4096 bytes (it never does for H5..H15: an H15 TransferToken is about 3.1 KB).
 */
export function buildDirectV1Transaction(p: DirectV1Params): DirectV1Transaction {
  const instruction = executeDirectInstruction(p);
  const config: Required<V1Config> = {
    computeUnitLimit: p.computeUnitLimit ?? EXECUTE_COMPUTE_UNITS,
    priorityFeeLamports: p.priorityFeeLamports ?? 0n,
    loadedAccountsDataSizeLimit: p.loadedAccountsDataSizeLimit ?? DEFAULT_LOADED_ACCOUNTS_DATA_SIZE,
  };
  const lifetime = { blockhash: asBlockhash(p.blockhash), lastValidBlockHeight: BigInt(p.lastValidBlockHeight ?? 0) };
  const compiled = pipe(
    createTransactionMessage({ version: 1 }),
    (m) => setTransactionMessageFeePayer(address(p.payer.toBase58()), m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(lifetime, m),
    (m) => setTransactionMessageConfig(config, m),
    (m) => appendTransactionMessageInstructions([toKitInstruction(instruction)], m),
    compileTransaction,
  );
  const messageBytes = new Uint8Array(compiled.messageBytes);
  if (messageBytes[0] !== V1_VERSION_BYTE) throw new Error(`kit produced version byte ${messageBytes[0]}, expected 0x81`);
  const size = messageBytes.length + 64;
  if (size > V1_MAX_TRANSACTION_BYTES) throw new RangeError(`v1 transaction would be ${size} bytes (max ${V1_MAX_TRANSACTION_BYTES})`);
  return { instruction, messageBytes, unsignedTransaction: assembleV1Transaction(messageBytes, [new Uint8Array(64)]), size, config };
}

/**
 * Wire form of a v1 transaction: the message followed by `num_required_signatures` 64-byte
 * signatures, no count prefix and no trailing bytes (SIMD-0385 "Signatures"). `signatures[i]`
 * is by the key at `Addresses[i]`.
 */
export function assembleV1Transaction(messageBytes: Uint8Array, signatures: Uint8Array[]): Uint8Array {
  if (messageBytes[0] !== V1_VERSION_BYTE) throw new Error("not a v1 message (version byte must be 0x81)");
  const required = messageBytes[1]!;
  if (signatures.length !== required) throw new Error(`message needs ${required} signatures, got ${signatures.length}`);
  const out = new Uint8Array(messageBytes.length + 64 * required);
  out.set(messageBytes, 0);
  signatures.forEach((s, i) => {
    if (s.length !== 64) throw new Error(`signature ${i} must be 64 bytes`);
    out.set(s, messageBytes.length + 64 * i);
  });
  return out;
}

/** Signs a v1 message (ed25519 over the message bytes) and returns the 64-byte signature. */
export type V1MessageSigner = (messageBytes: Uint8Array) => Promise<Uint8Array>;

/** A {@link V1MessageSigner} for a 64-byte ed25519 secret key (`Keypair.secretKey`). */
export function keypairV1Signer(secretKey: Uint8Array): V1MessageSigner {
  if (secretKey.length !== 64) throw new Error("secretKey must be the 64-byte ed25519 secret key");
  let pair: Promise<CryptoKeyPair> | undefined;
  return async (messageBytes) => {
    pair ??= createKeyPairFromBytes(secretKey);
    return new Uint8Array(await signBytes((await pair).privateKey, messageBytes));
  };
}

/** Base58 transaction signature (the first signature of the wire transaction). */
export function v1TransactionSignature(wire: Uint8Array): string {
  const messageLen = wire.length - 64 * wire[1]!;
  return getBase58Decoder().decode(wire.subarray(messageLen, messageLen + 64));
}

/** Where a direct execution failed. Only `sign` and `send` can mean "v1 is not supported here". */
export type DirectV1Stage = "sign" | "send" | "confirm";

export class DirectV1Error extends Error {
  readonly stage: DirectV1Stage;
  override readonly cause: unknown;
  constructor(stage: DirectV1Stage, cause: unknown) {
    super(`direct-v1 ${stage} failed: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "DirectV1Error";
    this.stage = stage;
    this.cause = cause;
  }
}

/**
 * True when the error says the wallet or the RPC does not take a v1 transaction (refused to sign,
 * could not parse or sanitize the bytes), as opposed to the transaction having run and failed.
 * The "auto" mode of `VaultSigner` falls back to the staged flow only on these.
 */
export function isV1Rejection(e: unknown): boolean {
  if (!(e instanceof DirectV1Error)) return false;
  if (e.stage === "sign") return true;
  if (e.stage !== "send") return false;
  const text = e.cause instanceof Error ? e.cause.message : String(e.cause);
  // The program ran (preflight simulation) and failed: a real error, not a format problem.
  return !/Error processing Instruction|custom program error|Error Code:|InstructionError|insufficient funds|Blockhash not found|already been processed/i.test(text);
}

export interface SendDirectV1Params extends Omit<DirectV1Params, "blockhash" | "lastValidBlockHeight"> {
  commitment?: Commitment | undefined;
}

export interface DirectV1Result {
  signature: string;
  /** The exact bytes that were sent. */
  transactionBytes: Uint8Array;
  blockhash: string;
  lastValidBlockHeight: number;
}

/**
 * Fetches a blockhash, builds, signs with `signer`, sends the raw v1 bytes through `rpc` and
 * confirms. Errors are wrapped in {@link DirectV1Error} with the stage they happened at.
 */
export async function sendDirectV1(rpc: Rpc, signer: V1MessageSigner, p: SendDirectV1Params): Promise<DirectV1Result> {
  const { blockhash, lastValidBlockHeight } = await rpc.getLatestBlockhash(p.commitment);
  const built = buildDirectV1Transaction({ ...p, blockhash, lastValidBlockHeight });
  let sig: Uint8Array;
  try {
    sig = await signer(built.messageBytes);
  } catch (e) {
    throw new DirectV1Error("sign", e);
  }
  const transactionBytes = assembleV1Transaction(built.messageBytes, [sig]);
  let signature: string;
  try {
    signature = await rpc.sendRawTransaction(transactionBytes, p.commitment ? { preflightCommitment: p.commitment } : {});
  } catch (e) {
    throw new DirectV1Error("send", e);
  }
  const res = await rpc.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, p.commitment);
  if (res.value.err) throw new DirectV1Error("confirm", new Error(`transaction ${signature} failed: ${JSON.stringify(res.value.err)}`));
  return { signature, transactionBytes, blockhash, lastValidBlockHeight };
}
