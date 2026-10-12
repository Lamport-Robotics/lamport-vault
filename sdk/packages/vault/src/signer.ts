/**
 * High-level clients. `VaultSigner` turns "move funds" into the transactions the chain needs:
 * read next_q, sign, open the buffer (carrying the first signature bytes), write the remaining
 * chunks, execute. `RegistryClient` does the same for `rotate_pq`, plus the one-transaction `commit`.
 *
 * Both talk to the cluster through the small `Rpc` interface below, which `Connection` satisfies,
 * so tests run against a mock.
 */
import { LmsPrivateKey, lmsParams, parseLmsPublicKey } from "@lamport-robotics/lms";
import { randomBytes } from "@noble/hashes/utils.js";
import {
  type AccountInfo,
  type Commitment,
  type PublicKey,
  type SendOptions,
  type Signer,
  Transaction,
  type TransactionInstruction,
} from "@solana/web3.js";
import { type CommitmentAccount, decodeCommitment, decodeVault, hasUsedKey, type VaultAccount } from "./accounts.ts";
import { type Action, encodeAction } from "./action.ts";
import { MAX_CHUNK_BYTES } from "./chunk.ts";
import { buildStagedExecution, type CloseTokenAccount, createVaultInstruction, EXECUTE_COMPUTE_UNITS } from "./instructions.ts";
import { registryMessage, vaultMessage } from "./message.ts";
import { findCommitmentPda, findVaultPdaForKey } from "./pda.ts";
import { LAMPORT_VAULT_PROGRAM_ID, PQ_REGISTRY_PROGRAM_ID } from "./programIds.ts";
import { buildStagedRotatePq, commitInstruction } from "./registry.ts";

export interface Rpc {
  getAccountInfo(publicKey: PublicKey, commitment?: Commitment): Promise<AccountInfo<Buffer> | null>;
  getLatestBlockhash(commitment?: Commitment): Promise<{ blockhash: string; lastValidBlockHeight: number }>;
  sendRawTransaction(rawTransaction: Buffer | Uint8Array | number[], options?: SendOptions): Promise<string>;
  confirmTransaction(
    strategy: { signature: string; blockhash: string; lastValidBlockHeight: number },
    commitment?: Commitment,
  ): Promise<{ value: { err: unknown } }>;
  getSlot(commitment?: Commitment): Promise<number>;
}

export interface SendOpts {
  commitment?: Commitment | undefined;
  /** Called after each transaction confirms, with its index, the total and its signature. */
  onTransaction?: (index: number, total: number, signature: string) => void;
}

/** Sign with `signers` (first one pays fees), send and confirm one transaction; throws on a cluster error. */
export async function sendAndConfirm(rpc: Rpc, signers: Signer[], instructions: TransactionInstruction[], opts: SendOpts = {}): Promise<string> {
  const payer = signers[0];
  if (!payer) throw new Error("at least one signer is required");
  const { blockhash, lastValidBlockHeight } = await rpc.getLatestBlockhash(opts.commitment);
  const tx = new Transaction({ feePayer: payer.publicKey, blockhash, lastValidBlockHeight }).add(...instructions);
  tx.sign(...signers);
  const signature = await rpc.sendRawTransaction(tx.serialize(), opts.commitment ? { preflightCommitment: opts.commitment } : {});
  const res = await rpc.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, opts.commitment);
  if (res.value.err) throw new Error(`transaction ${signature} failed: ${JSON.stringify(res.value.err)}`);
  return signature;
}

async function sendSequence(rpc: Rpc, payer: Signer, txs: TransactionInstruction[][], opts: SendOpts): Promise<string[]> {
  const out: string[] = [];
  for (let i = 0; i < txs.length; i++) {
    const sig = await sendAndConfirm(rpc, [payer], txs[i]!, opts);
    out.push(sig);
    opts.onTransaction?.(i, txs.length, sig);
  }
  return out;
}

export function randomNonce(): bigint {
  const b = randomBytes(8);
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
/** An Action whose expiry may be left for the signer to fill from the current slot. */
export type ActionRequest = DistributiveOmit<Action, "expirySlot"> & { expirySlot?: bigint };

export interface VaultSignerOptions {
  rpc: Rpc;
  /** Default: the id declared by `programs/lamport-vault`. */
  programId?: PublicKey;
  /** The LMS key that owns the vault. */
  key: LmsPrivateKey;
  /** Classical key that pays rent and fees; refunded the buffer rent on execute. */
  payer: Signer;
  /**
   * The vault address. Defaults to the PDA of `key.publicKey`, which is right for an unrotated
   * vault; after a `Rotate`, pass the vault address explicitly (it never changes).
   */
  vault?: PublicKey;
  /** Slots an action stays valid when the request has no expiry. Default 300 (about two minutes). */
  defaultExpirySlots?: number;
  /** Signature bytes carried by `open_sig_buffer`. Default "auto": as many as fit. */
  firstChunkSize?: number | "auto";
  chunkSize?: number;
  computeUnits?: number;
  tokenProgram?: PublicKey;
  commitment?: Commitment;
}

export interface SignedAction {
  q: number;
  vault: PublicKey;
  /** the vault's key generation the message was bound to */
  rotations: number;
  action: Action;
  actionBytes: Uint8Array;
  message: Uint8Array;
  lmsSignature: Uint8Array;
}

export interface ExecuteResult extends SignedAction {
  nonce: bigint;
  sigBuffer: PublicKey;
  /** open_sig_buffer, write_sig..., execute */
  signatures: string[];
}

export class VaultSigner {
  readonly rpc: Rpc;
  readonly programId: PublicKey;
  readonly key: LmsPrivateKey;
  readonly payer: Signer;
  readonly vault: PublicKey;
  private readonly opts: VaultSignerOptions;
  /** Leaves this process has already signed with; never reused even before the chain confirms. */
  private localNextQ = 0;

  constructor(opts: VaultSignerOptions) {
    this.opts = opts;
    this.rpc = opts.rpc;
    this.programId = opts.programId ?? LAMPORT_VAULT_PROGRAM_ID;
    this.key = opts.key;
    this.payer = opts.payer;
    this.vault = opts.vault ?? findVaultPdaForKey(this.programId, opts.key.publicKey).address;
  }

  /** `create_vault` for this signer's key. One transaction. */
  async createVault(opts: SendOpts = {}): Promise<{ vault: PublicKey; signature: string }> {
    const { instruction, vault } = createVaultInstruction({ programId: this.programId, payer: this.payer.publicKey, lmsPubkey: this.key.publicKey });
    const signature = await sendAndConfirm(this.rpc, [this.payer], [instruction], { ...opts, commitment: opts.commitment ?? this.opts.commitment });
    return { vault, signature };
  }

  async fetchVault(): Promise<VaultAccount> {
    const info = await this.rpc.getAccountInfo(this.vault, this.opts.commitment);
    if (!info) throw new Error(`vault ${this.vault.toBase58()} does not exist`);
    const v = decodeVault(new Uint8Array(info.data));
    if (!Buffer.from(v.lmsPubkey).equals(Buffer.from(this.key.publicKey))) {
      throw new Error("the vault's current lms_pubkey is not this key (rotated? recover with the next index)");
    }
    return v;
  }

  /** The smallest leaf this signer will use next: max(chain next_q, leaves already signed here). */
  async nextQ(): Promise<number> {
    const v = await this.fetchVault();
    return Math.max(v.nextQ, this.localNextQ);
  }

  /**
   * Sign `request` with leaf `q` (default: next usable) and bind it to this vault and its current
   * key generation (`rotations`, read from the account). Pure: nothing is sent. The returned
   * signature verifies under `key.publicKey` over `message`.
   */
  async sign(request: ActionRequest, opts: { q?: number; C?: Uint8Array } = {}): Promise<SignedAction> {
    const vault = await this.fetchVault();
    const q = opts.q ?? Math.max(vault.nextQ, this.localNextQ);
    const h = lmsParams(parseLmsPublicKey(vault.lmsPubkey).lmsType).h;
    if (q < vault.nextQ) throw new Error(`q=${q} is below the vault's next_q=${vault.nextQ}`);
    if (q >= 2 ** h) throw new Error(`q=${q} is beyond the last leaf of an H${h} key`);
    if (q === 2 ** h - 1 && request.kind !== "Rotate") {
      throw new Error("the last leaf may only be spent on Rotate (exhaustion rule); rotate to a fresh key first");
    }
    if (request.kind === "Rotate" && hasUsedKey(vault.usedKeys, request.newLmsPubkey)) {
      throw new Error("Rotate to a key this vault has used before (the chain would refuse it with KeyReused)");
    }
    const action = await this.withExpiry(request);
    const actionBytes = encodeAction(action);
    const message = vaultMessage(this.vault, vault.rotations, actionBytes);
    const lmsSignature = this.key.sign(q, message, opts.C ? { C: opts.C } : {});
    this.localNextQ = Math.max(this.localNextQ, q + 1);
    return { q, vault: this.vault, rotations: vault.rotations, action, actionBytes, message, lmsSignature };
  }

  /** Sign, stage and execute. Returns the signatures of every transaction, in order. */
  async execute(
    request: ActionRequest,
    opts: SendOpts & { q?: number; nonce?: bigint; closeTokenAccounts?: CloseTokenAccount[] } = {},
  ): Promise<ExecuteResult> {
    const signed = await this.sign(request, opts.q !== undefined ? { q: opts.q } : {});
    const nonce = opts.nonce ?? randomNonce();
    const staged = buildStagedExecution({
      programId: this.programId,
      vault: this.vault,
      payer: this.payer.publicKey,
      nonce,
      action: signed.action,
      signature: signed.lmsSignature,
      firstChunkSize: this.opts.firstChunkSize ?? "auto",
      chunkSize: this.opts.chunkSize ?? MAX_CHUNK_BYTES,
      computeUnits: this.opts.computeUnits ?? EXECUTE_COMPUTE_UNITS,
      ...(this.opts.tokenProgram ? { tokenProgram: this.opts.tokenProgram } : {}),
      ...(opts.closeTokenAccounts ? { closeTokenAccounts: opts.closeTokenAccounts } : {}),
    });
    const signatures = await sendSequence(this.rpc, this.payer, staged.transactions, { ...opts, commitment: opts.commitment ?? this.opts.commitment });
    return { ...signed, nonce, sigBuffer: staged.sigBuffer, signatures };
  }

  private async withExpiry(request: ActionRequest): Promise<Action> {
    if (request.expirySlot !== undefined) return request as Action;
    const slot = await this.rpc.getSlot(this.opts.commitment);
    const expirySlot = BigInt(slot + (this.opts.defaultExpirySlots ?? 300));
    return { ...request, expirySlot } as Action;
  }
}

export interface RegistryClientOptions {
  rpc: Rpc;
  /** Default: the id declared by `programs/pq-registry`. */
  programId?: PublicKey;
  payer: Signer;
  chunkSize?: number;
  computeUnits?: number;
  commitment?: Commitment;
}

export interface RotatePqResult {
  q: number;
  /** the commitment's generation the message was bound to */
  generation: number;
  nonce: bigint;
  message: Uint8Array;
  lmsSignature: Uint8Array;
  buffer: PublicKey;
  /** open_pq_buffer, write_pq_sig..., rotate_pq */
  signatures: string[];
}

export class RegistryClient {
  readonly programId: PublicKey;
  private readonly opts: RegistryClientOptions;

  constructor(opts: RegistryClientOptions) {
    this.opts = opts;
    this.programId = opts.programId ?? PQ_REGISTRY_PROGRAM_ID;
  }

  commitmentAddress(owner: PublicKey): PublicKey {
    return findCommitmentPda(this.programId, owner).address;
  }

  async fetchCommitment(owner: PublicKey): Promise<CommitmentAccount | null> {
    const info = await this.opts.rpc.getAccountInfo(this.commitmentAddress(owner), this.opts.commitment);
    return info ? decodeCommitment(new Uint8Array(info.data)) : null;
  }

  /** `commit`: the classical owner signs once (the client's payer pays rent); first write wins. */
  async commit(owner: Signer, pqPubkey: Uint8Array, opts: SendOpts = {}): Promise<{ commitment: PublicKey; signature: string }> {
    const payer = this.opts.payer;
    const { instruction, commitment } = commitInstruction({ programId: this.programId, owner: owner.publicKey, payer: payer.publicKey, pqPubkey });
    const signers = owner.publicKey.equals(payer.publicKey) ? [payer] : [payer, owner];
    const signature = await sendAndConfirm(this.opts.rpc, signers, [instruction], { ...opts, commitment: opts.commitment ?? this.opts.commitment });
    return { commitment, signature };
  }

  /**
   * `rotate_pq`: sign sha256("pq-registry/v1" || owner || u32le(generation) || new_pq_pubkey) with
   * the committed LMS key at leaf q >= next_q, stage it, rotate. Anyone can pay; the owner's
   * classical key is not needed. A key that was committed before is refused up front.
   */
  async rotatePq(
    owner: PublicKey,
    committedKey: LmsPrivateKey,
    newPqPubkey: Uint8Array,
    opts: SendOpts & { q?: number; nonce?: bigint } = {},
  ): Promise<RotatePqResult> {
    const current = await this.fetchCommitment(owner);
    if (!current) throw new Error(`no commitment for ${owner.toBase58()}`);
    if (!Buffer.from(current.pqPubkey).equals(Buffer.from(committedKey.publicKey))) {
      throw new Error("the committed pq_pubkey is not this key");
    }
    const q = opts.q ?? current.nextQ;
    if (q < current.nextQ) throw new Error(`q=${q} is below the commitment's next_q=${current.nextQ}`);
    if (hasUsedKey(current.usedKeys, newPqPubkey)) {
      throw new Error("rotation to a key that was committed before (the chain would refuse it with KeyReused)");
    }
    const message = registryMessage(owner, current.generation, newPqPubkey);
    const lmsSignature = committedKey.sign(q, message);
    const nonce = opts.nonce ?? randomNonce();
    const staged = buildStagedRotatePq({
      programId: this.programId,
      owner,
      payer: this.opts.payer.publicKey,
      nonce,
      newPqPubkey,
      signature: lmsSignature,
      chunkSize: this.opts.chunkSize ?? MAX_CHUNK_BYTES,
      computeUnits: this.opts.computeUnits ?? EXECUTE_COMPUTE_UNITS,
    });
    const signatures = await sendSequence(this.opts.rpc, this.opts.payer, staged.transactions, { ...opts, commitment: opts.commitment ?? this.opts.commitment });
    return { q, generation: current.generation, nonce, message, lmsSignature, signatures, buffer: staged.buffer };
  }
}
