/**
 * High-level clients. `VaultSigner` turns "move funds" into the transactions the chain needs:
 * read the vault (bitmap + generation), compare it with the signer's leaf journal, pick a free
 * leaf, reserve it durably, sign, then either send one v1 transaction (`execute_direct`, mode
 * "direct-v1") or open the buffer (carrying the first signature bytes), write the remaining
 * chunks and execute (mode "staged"). Mode "auto" tries direct first and falls back to staged
 * when the wallet or the RPC rejects v1. `RegistryClient` does the same for `rotate_pq` (staged
 * only), plus the one-transaction `commit`.
 *
 * Both talk to the cluster through the small `Rpc` interface below, which `Connection` satisfies,
 * so tests run against a mock.
 */
import {
  deriveKeyMaterial,
  deriveLmsInputs,
  type DerivationScope,
  equalBytes,
  type LmsKeyMaterial,
  LMOTS_SHA256_N32_W4,
  LMS_SHA256_M32_H10,
  LmsPrivateKey,
  parseLmsPublicKey,
  RECOVERY_MAX_INDEX,
} from "@lamport-robotics/lms";
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
import {
  type CommitmentAccount,
  decodeCommitment,
  decodeVault,
  decodeVaultOrTombstone,
  firstFreeLeaf,
  freeLeavesExcluding,
  hasUsedKey,
  isLeafUsed,
  leafCount,
  spentLeavesInLane,
  type VaultAccount,
} from "./accounts.ts";
import { type Action, checkValidityWindow, encodeAction, type ValidityWindow } from "./action.ts";
import { MAX_CHUNK_BYTES } from "./chunk.ts";
import { isV1Rejection, keypairV1Signer, sendDirectV1, type V1Config, type V1MessageSigner } from "./direct.ts";
import { buildStagedExecution, type CloseTokenAccount, createVaultInstruction, EXECUTE_COMPUTE_UNITS } from "./instructions.ts";
import { cloneState, JournalVaultMismatchError, keyFingerprint, type LeafJournal, type LeafJournalState, MemoryLeafJournal, type StaleSignerDetail, StaleSignerError } from "./journal.ts";
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

/** Slots an action stays valid when the request names no expiry: about two minutes. */
export const DEFAULT_EXPIRY_SLOTS = 300;

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
/**
 * An Action whose validity window may be left for the signer to fill: `issuedSlot` defaults to
 * the current slot, `expirySlot` to `issuedSlot + defaultExpirySlots`.
 */
export type ActionRequest = DistributiveOmit<Action, "issuedSlot" | "expirySlot"> & Partial<ValidityWindow>;

/**
 * How a signed action reaches the chain.
 * - `"staged"`: open_sig_buffer / write_sig / execute, three or four legacy transactions (works everywhere).
 * - `"direct-v1"`: one `execute_direct` transaction in format v1 (needs a cluster with SIMD-0385 and a signer that takes v1 bytes).
 * - `"auto"`: direct first; if the wallet refuses to sign or the RPC refuses the bytes, staged with the same LMS signature.
 */
export type ExecuteMode = "direct-v1" | "staged" | "auto";

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
  /** Slots an action stays valid when the request has no expiry. Default {@link DEFAULT_EXPIRY_SLOTS}. */
  defaultExpirySlots?: number;
  /**
   * Leaf lane: this signer only uses leaves `q ≡ lane (mod lanes)`. Several devices sharing one
   * key each take a different lane and never collide. Default: lane 0 of 1 (every leaf).
   */
  lane?: number;
  lanes?: number;
  /**
   * Durable record of the leaves this signer signed and of the chain state it last saw
   * (docs/DESIGN.md "Signer rollback"). It is keyed by `key`'s fingerprint (`sha256(lms_pubkey)`,
   * {@link keyFingerprint}); a journal built for another key is refused. A leaf is written to it
   * BEFORE it is signed, so a crash between signing and submitting cannot lead to a second
   * signature on that leaf after a restart; and before every signature the journal is compared
   * with the chain: a journal that is behind (restored from an old backup, or another signer
   * with this key moved on in this lane) makes the signer stale, and a stale signer refuses
   * everything but Rotate ({@link StaleSignerError}); a journal that names another vault means
   * the key is being reused and is refused outright ({@link JournalVaultMismatchError}).
   * Required: a `FileLeafJournal` in Node, a `BrowserLeafJournal` in a browser, or `"ephemeral"`
   * to say in so many words that this signer keeps its record in memory only (a
   * `MemoryLeafJournal` that dies with the object; a crash after signing loses the reservation).
   * An ephemeral signer says so once on `console.warn` when it first signs and in every result's
   * `ephemeral` flag.
   */
  journal: LeafJournal | "ephemeral";
  /**
   * Called with the leaf about to be signed, after the journal has recorded it and BEFORE the
   * signature exists. An extra hook for a secure element or a database; throw to veto. Optional,
   * the journal already persists reservations.
   */
  reserve?: (q: number) => Promise<void> | void;
  /**
   * The 64-byte BIP-39 master seed the vault key was derived from (docs/SPEC-DERIVATION.md).
   * With it a `Rotate` is only signed for the next derived key, index k+1 of the current key
   * (see {@link nextKeyMaterial}); any other target is "foreign" and needs `allowForeignKey`.
   * Without it every Rotate target is foreign: a vault rotated to a key the words cannot
   * reproduce is unrecoverable from the words. Needs `genesisHash`: derivation v2 binds keys
   * to the cluster and the program id.
   */
  master?: Uint8Array;
  /** The cluster's genesis hash (base58 or 32 bytes), see `CLUSTERS` in `@lamport-robotics/lms`. Required with `master`. */
  genesisHash?: string | Uint8Array;
  /** Signature bytes carried by `open_sig_buffer`. Default "auto": as many as fit. */
  firstChunkSize?: number | "auto";
  chunkSize?: number;
  computeUnits?: number;
  tokenProgram?: PublicKey;
  commitment?: Commitment;
  /** Default `"staged"`. See {@link ExecuteMode}. */
  mode?: ExecuteMode;
  /**
   * Signs v1 messages for the direct path. Default: ed25519 with `payer.secretKey`. Pass a
   * wallet-backed signer when the payer is a wallet (see docs/DESIGN.md, "Wallet compatibility").
   */
  v1Signer?: V1MessageSigner;
  /** Header configuration of direct transactions. `computeUnitLimit` defaults to `computeUnits`. */
  v1Config?: V1Config;
}

export interface SignedAction {
  q: number;
  vault: PublicKey;
  /** the vault's key generation the message was bound to */
  generation: number;
  action: Action;
  actionBytes: Uint8Array;
  message: Uint8Array;
  lmsSignature: Uint8Array;
  /** True when the signer was built with `journal: "ephemeral"`: the leaf is recorded in memory only. */
  ephemeral: boolean;
}

export interface StagedExecuteResult extends SignedAction {
  mode: "staged";
  nonce: bigint;
  sigBuffer: PublicKey;
  /** open_sig_buffer, write_sig..., execute */
  signatures: string[];
}

export interface DirectExecuteResult extends SignedAction {
  mode: "direct-v1";
  nonce?: undefined;
  sigBuffer?: undefined;
  /** the one `execute_direct` transaction */
  signatures: string[];
  /** the v1 bytes that were sent */
  transactionBytes: Uint8Array;
}

export type ExecuteResult = StagedExecuteResult | DirectExecuteResult;

export interface SignOpts {
  q?: number;
  /** LM-OTS randomizer C; default random. */
  C?: Uint8Array;
  /**
   * Rotate only: sign for a `newLmsPubkey` that is not the next key derived from the signer's
   * `master` (or when no `master` is known). Off by default; see {@link VaultSignerOptions.master}.
   */
  allowForeignKey?: boolean;
}

export interface ExecuteOpts extends SendOpts {
  q?: number;
  /** Rotate only: see {@link SignOpts.allowForeignKey}. */
  allowForeignKey?: boolean;
  nonce?: bigint;
  closeTokenAccounts?: CloseTokenAccount[];
  /** TransferToken: the vault-owned token account to draw from. Default: the vault's associated token account. */
  source?: PublicKey;
  /** Overrides the signer's default mode for this call. */
  mode?: ExecuteMode;
  /** In "auto" mode: called with the rejection before the staged flow starts. */
  onFallback?: (error: unknown) => void;
}

/** What `syncJournal` establishes: the journal state to work from and, if behind the chain, why. */
export interface JournalSync {
  state: LeafJournalState;
  stale: StaleSignerDetail | undefined;
}

// One critical section per journal identity, so two signers over one journal (same object, or two
// FileLeafJournal objects on one path) never interleave a load / save pair. Inside it the journal's
// own cross-process lock (a `.lock` file, a Web Lock) keeps other processes and tabs out.
const journalLocks = new Map<string, Promise<unknown>>();
const objectLockKeys = new WeakMap<LeafJournal, string>();
let anonymousJournals = 0;

function lockKeyOf(journal: LeafJournal): string {
  if (journal.lockKey !== undefined) return journal.lockKey;
  let key = objectLockKeys.get(journal);
  if (key === undefined) {
    key = `object:${++anonymousJournals}`;
    objectLockKeys.set(journal, key);
  }
  return key;
}

/**
 * Runs `fn` with exclusive access to `journal`: serialised per process by the journal's identity,
 * and, when the journal has `acquireLock`, exclusive across processes or tabs too (a journal held
 * elsewhere rejects with {@link JournalLockedError} or waits, as the implementation chooses).
 */
export async function withJournalLock<T>(journal: LeafJournal, fn: () => Promise<T>): Promise<T> {
  const key = lockKeyOf(journal);
  const previous = journalLocks.get(key) ?? Promise.resolve();
  const locked = async (): Promise<T> => {
    if (!journal.acquireLock) return fn();
    await journal.acquireLock();
    try {
      return await fn();
    } finally {
      await journal.releaseLock?.();
    }
  };
  const run = previous.then(locked, locked);
  const settled = run.then(
    () => undefined,
    () => undefined,
  );
  journalLocks.set(key, settled);
  try {
    return await run;
  } finally {
    if (journalLocks.get(key) === settled) journalLocks.delete(key);
  }
}

export class VaultSigner {
  readonly rpc: Rpc;
  readonly programId: PublicKey;
  readonly key: LmsPrivateKey;
  /** `sha256(key.publicKey)` in hex: what the journal is keyed by. */
  readonly keyId: string;
  readonly payer: Signer;
  readonly vault: PublicKey;
  readonly lane: number;
  readonly lanes: number;
  readonly journal: LeafJournal;
  /** True when built with `journal: "ephemeral"`: reservations live in this object only. */
  readonly ephemeral: boolean;
  private readonly opts: VaultSignerOptions;
  private readonly scope: DerivationScope | undefined;
  private staleAcknowledged = false;
  private warnedEphemeral = false;

  constructor(opts: VaultSignerOptions) {
    this.opts = opts;
    this.rpc = opts.rpc;
    this.programId = opts.programId ?? LAMPORT_VAULT_PROGRAM_ID;
    this.key = opts.key;
    this.payer = opts.payer;
    this.vault = opts.vault ?? findVaultPdaForKey(this.programId, opts.key.publicKey).address;
    this.lanes = opts.lanes ?? 1;
    this.lane = opts.lane ?? 0;
    if (!opts.journal) {
      throw new Error('journal is required: pass a FileLeafJournal (Node) or BrowserLeafJournal (web), or journal: "ephemeral" to keep the leaf record in memory only');
    }
    this.keyId = keyFingerprint(opts.key.publicKey);
    this.ephemeral = opts.journal === "ephemeral";
    this.journal = opts.journal === "ephemeral" ? new MemoryLeafJournal(this.keyId) : opts.journal;
    if (this.journal.key !== this.keyId) {
      throw new Error(`journal is for key ${this.journal.key}, this signer's key is ${this.keyId}: one journal per LMS key`);
    }
    if (!Number.isInteger(this.lanes) || this.lanes < 1) throw new RangeError(`lanes must be >= 1, got ${this.lanes}`);
    if (!Number.isInteger(this.lane) || this.lane < 0 || this.lane >= this.lanes) throw new RangeError(`lane must be in 0..${this.lanes - 1}, got ${this.lane}`);
    if (opts.master) {
      if (!opts.genesisHash) throw new Error("master needs genesisHash: derivation v2 binds every key to a cluster (see CLUSTERS) and a program id");
      this.scope = { genesisHash: opts.genesisHash, programId: this.programId };
    }
    const n = opts.defaultExpirySlots ?? DEFAULT_EXPIRY_SLOTS;
    if (!Number.isInteger(n) || n < 0) throw new RangeError(`defaultExpirySlots must be a non-negative integer, got ${n}`);
    checkValidityWindow({ issuedSlot: 0n, expirySlot: BigInt(n) });
  }

  /**
   * `create_vault` for this signer's key. One transaction. Refused before anything is sent when
   * the address already holds a vault, or the tombstone of a closed one: a closed vault's address
   * is never reusable, so the next vault needs the next key (see {@link nextFreshKeyIndex}).
   */
  async createVault(opts: SendOpts = {}): Promise<{ vault: PublicKey; signature: string }> {
    const { instruction, vault } = createVaultInstruction({ programId: this.programId, payer: this.payer.publicKey, lmsPubkey: this.key.publicKey });
    const occupied = await vaultAddressState(this.rpc, vault, this.opts.commitment);
    if (occupied === "tombstone") {
      throw new Error(`vault ${vault.toBase58()} was closed: a tombstone holds its address for good; create the next vault with the next key (nextFreshKeyIndex)`);
    }
    if (occupied === "vault") throw new Error(`vault ${vault.toBase58()} already exists`);
    const signature = await sendAndConfirm(this.rpc, [this.payer], [instruction], { ...opts, commitment: opts.commitment ?? this.opts.commitment });
    return { vault, signature };
  }

  /**
   * The vault account as it is on chain, whatever key it currently holds. A closed vault (its
   * tombstone) throws `VaultClosedError`.
   */
  async fetchVaultAccount(): Promise<VaultAccount> {
    const info = await this.rpc.getAccountInfo(this.vault, this.opts.commitment);
    if (!info) throw new Error(`vault ${this.vault.toBase58()} does not exist`);
    return decodeVault(new Uint8Array(info.data));
  }

  /** The vault account, checked to hold this signer's key. */
  async fetchVault(): Promise<VaultAccount> {
    const v = await this.fetchVaultAccount();
    if (!Buffer.from(v.lmsPubkey).equals(Buffer.from(this.key.publicKey))) {
      throw new Error("the vault's current lms_pubkey is not this key (rotated? recover with the next index)");
    }
    return v;
  }

  /**
   * Compares the journal with the chain (DESIGN.md "Signer rollback"). A journal that was never
   * written is initialised from the chain. A journal that names another vault means this key is
   * being pointed at a second vault: refused ({@link JournalVaultMismatchError}). Otherwise the
   * journal is behind the chain, "stale", when the chain is at a later key generation, or when
   * this lane has more spent leaves than the journal's `spent` plus its own `reserved` leaves
   * that are now spent can explain: a signer state this journal never saw signed and executed
   * them. A stale journal is returned untouched (so the evidence survives); a fresh one is
   * re-synced: `spent` set to the lane's count and reserved leaves that are spent on chain
   * dropped (the bitmap guards them for good). Called under the journal lock.
   */
  async syncJournal(vault: VaultAccount): Promise<JournalSync> {
    const spentInLane = spentLeavesInLane(vault, this.lane, this.lanes);
    const vaultAddress = this.vault.toBase58();
    const loaded = await this.journal.load();
    if (!loaded) {
      const state: LeafJournalState = { key: this.keyId, vault: vaultAddress, generation: vault.generation, spent: spentInLane, reserved: [] };
      await this.journal.save(state);
      return { state, stale: undefined };
    }
    if (loaded.vault !== vaultAddress) throw new JournalVaultMismatchError(this.keyId, loaded.vault, vaultAddress);
    const state = cloneState(loaded);
    const reservedSpent = state.reserved.filter((q) => isLeafUsed(vault, q));
    const behind = state.generation !== vault.generation || spentInLane > state.spent + reservedSpent.length;
    if (behind && !this.staleAcknowledged) {
      const reserved = new Set(state.reserved);
      const unaccounted: number[] = [];
      if (state.generation === vault.generation) {
        // Every spent leaf of the lane beyond the first `spent` ones that this journal did not reserve.
        let seen = 0;
        for (let q = this.lane; q < leafCount(vault); q += this.lanes) {
          if (!isLeafUsed(vault, q)) continue;
          seen++;
          if (seen > state.spent && !reserved.has(q)) unaccounted.push(q);
        }
      }
      return {
        state,
        stale: {
          vault: this.vault.toBase58(),
          lane: this.lane,
          lanes: this.lanes,
          chain: { generation: vault.generation, spentInLane },
          journal: cloneState(loaded),
          unaccounted,
        },
      };
    }
    // Fresh (or the operator overrode a stale journal): adopt the chain's view.
    this.staleAcknowledged = false;
    state.generation = vault.generation;
    state.spent = spentInLane;
    state.reserved = state.reserved.filter((q) => !isLeafUsed(vault, q));
    await this.journal.save(state);
    return { state, stale: undefined };
  }

  /**
   * UNSAFE. Makes the next sync adopt the chain's state even though the journal is behind it.
   * Only call it when you are certain that no signature this signer made after the journal's
   * last save is still unsubmitted (every one of them is on chain, or expired): otherwise the
   * signer may sign a leaf a second time, and two LM-OTS signatures by one leaf let anyone forge
   * a third. The safe way out of a stale state is a `Rotate`.
   */
  acknowledgeStale(): void {
    this.staleAcknowledged = true;
  }

  /**
   * The leaf this signer will use next: the smallest free leaf of its lane that is neither spent
   * on chain nor reserved in the journal. `undefined` once the lane is exhausted. Does not
   * change the journal.
   */
  async nextQ(): Promise<number | undefined> {
    const v = await this.fetchVault();
    const reserved = new Set((await this.journal.load())?.reserved ?? []);
    return firstFreeLeaf(v, this.lane, this.lanes, (q) => reserved.has(q));
  }

  /**
   * Sign `request` with leaf `q` (default: the lane's next free leaf) and bind it to this vault
   * and its current key generation (read from the account). The leaf is written to the journal
   * (and passed to `reserve`) before anything is signed. Pure otherwise: nothing is sent. The
   * returned signature verifies under `key.publicKey` over `message`. Throws
   * {@link StaleSignerError} for anything but a Rotate when the journal is behind the chain.
   */
  async sign(request: ActionRequest, opts: SignOpts = {}): Promise<SignedAction> {
    return withJournalLock(this.journal, () => this.signLocked(request, opts));
  }

  private async signLocked(request: ActionRequest, opts: SignOpts): Promise<SignedAction> {
    const vault = await this.fetchVault();
    const { state, stale } = await this.syncJournal(vault);
    const reserved = new Set(state.reserved);
    const total = leafCount(vault);
    const q = opts.q ?? firstFreeLeaf(vault, this.lane, this.lanes, (x) => reserved.has(x));
    if (q === undefined) throw new Error(`no free leaf left in lane ${this.lane}/${this.lanes}; rotate to a fresh key`);
    if (!Number.isInteger(q) || q < 0 || q >= total) throw new Error(`q=${q} is beyond the last leaf of a ${total}-leaf key`);
    if (isLeafUsed(vault, q)) throw new Error(`q=${q} is already spent on chain`);
    if (reserved.has(q)) throw new Error(`q=${q} was already signed by this signer (journal)`);
    if (stale && request.kind !== "Rotate") throw new StaleSignerError(stale);
    // leaves this signer already signed with count as gone even before they land
    if (freeLeavesExcluding(vault, (x) => reserved.has(x)) <= 1 && request.kind !== "Rotate" && request.kind !== "Close") {
      throw new Error("the last free leaf may only be spent on Rotate or Close (exhaustion rule); rotate to a fresh key first");
    }
    if (request.kind === "Rotate") {
      if (hasUsedKey(vault, request.newLmsPubkey)) throw new Error("Rotate to a key this vault has used before (the chain would refuse it with KeyReused)");
      for (let i = 0; i < 8; i++) {
        if (request.newLmsPubkey[i] !== vault.lmsPubkey[i]) throw new Error("Rotate must keep the vault's LMS/LM-OTS typecodes (RotateTypeMismatch)");
      }
      if (!opts.allowForeignKey) await this.checkRotateTarget(vault, request.newLmsPubkey);
    }
    const action = await this.withWindow(request);
    const actionBytes = encodeAction(action);
    const message = vaultMessage(this.vault, vault.generation, actionBytes, this.programId);
    // Reserve first, durably: if persisting fails, no signature for this leaf ever exists.
    await this.opts.reserve?.(q);
    state.reserved.push(q);
    await this.journal.save(state);
    if (this.ephemeral && !this.warnedEphemeral) {
      this.warnedEphemeral = true;
      console.warn(`VaultSigner for vault ${this.vault.toBase58()} is ephemeral: leaf reservations live in memory only, a crash after signing can lead to a second signature on a leaf; pass a FileLeafJournal or BrowserLeafJournal`);
    }
    const lmsSignature = this.key.sign(q, message, opts.C ? { C: opts.C } : {});
    return { q, vault: this.vault, generation: vault.generation, action, actionBytes, message, lmsSignature, ephemeral: this.ephemeral };
  }

  /**
   * Foreign-key guard: a Rotate target must be the public key of `nextKeyMaterial(master, vault, scope)`,
   * i.e. derived from the signer's words at index k+1 for this cluster and program. The full
   * tree is built (H10: a fraction of a second) so a key with the right `I` but a wrong root is
   * refused too: rotating to it would lock the vault for good.
   */
  private async checkRotateTarget(vault: VaultAccount, newLmsPubkey: Uint8Array): Promise<void> {
    const master = this.opts.master;
    if (!master || !this.scope) {
      throw new Error("Rotate to a foreign key: this signer has no master seed to derive the next key from; pass { allowForeignKey: true } to rotate to a key the words cannot reproduce");
    }
    const { k, material } = nextKeyMaterial(master, vault, this.scope);
    const target = parseLmsPublicKey(newLmsPubkey);
    if (!equalBytes(target.I, material.I)) {
      throw new Error(`Rotate to a foreign key: not the next key derived from these words (index ${k + 1}); pass { allowForeignKey: true } to rotate to a key the words cannot reproduce`);
    }
    const next = await LmsPrivateKey.generateAsync(material);
    if (!equalBytes(next.publicKey, newLmsPubkey)) {
      throw new Error(`Rotate to a foreign key: its I matches index ${k + 1} of these words but its root does not; pass { allowForeignKey: true } to rotate to a key the words cannot reproduce`);
    }
  }

  /** The signer used for v1 messages: the option, else the payer's secret key. */
  get v1Signer(): V1MessageSigner | undefined {
    if (this.opts.v1Signer) return this.opts.v1Signer;
    return this.payer.secretKey?.length === 64 ? keypairV1Signer(this.payer.secretKey) : undefined;
  }

  /**
   * Sign and execute by the signer's mode (or `opts.mode`). Returns the signatures of every
   * transaction, in order: one for "direct-v1", open/write.../execute for "staged". After a
   * `Rotate` lands the journal is reset for the new generation ({@link confirmRotation}).
   */
  async execute(request: ActionRequest, opts: ExecuteOpts = {}): Promise<ExecuteResult> {
    const signed = await this.sign(request, {
      ...(opts.q !== undefined ? { q: opts.q } : {}),
      ...(opts.allowForeignKey !== undefined ? { allowForeignKey: opts.allowForeignKey } : {}),
    });
    const result = await this.send(signed, opts);
    if (signed.action.kind === "Rotate") await this.confirmRotation(signed);
    return result;
  }

  private async send(signed: SignedAction, opts: ExecuteOpts): Promise<ExecuteResult> {
    const mode = opts.mode ?? this.opts.mode ?? "staged";
    if (mode !== "staged") {
      const v1Signer = this.v1Signer;
      if (!v1Signer && mode === "direct-v1") throw new Error("direct-v1 needs a payer secret key or a v1Signer");
      if (v1Signer) {
        try {
          return await this.sendDirect(signed, v1Signer, opts);
        } catch (e) {
          if (mode === "direct-v1" || !isV1Rejection(e)) throw e;
          opts.onFallback?.(e);
        }
      }
    }
    return this.sendStaged(signed, opts);
  }

  /**
   * Records in the journal that the Rotate in `signed` landed: reads the vault, requires the
   * generation to be `signed.generation + 1` and the key to be the Rotate's target, then closes
   * this key's record out at the new generation (the key is retired; its spent and reserved
   * leaves stay on record). The new key starts its own journal, initialised from the chain on
   * its first signature. `execute` calls this itself; call it after submitting a Rotate signed
   * with `sign()` by other means. Until it runs a stale signer stays stale.
   */
  async confirmRotation(signed: SignedAction): Promise<void> {
    if (signed.action.kind !== "Rotate") throw new Error("confirmRotation takes a signed Rotate");
    const target = signed.action.newLmsPubkey;
    const v = await this.fetchVaultAccount();
    if (v.generation !== signed.generation + 1 || !equalBytes(v.lmsPubkey, target)) {
      throw new Error(`rotation has not landed: the vault is at generation ${v.generation} (signed at ${signed.generation})`);
    }
    await withJournalLock(this.journal, async () => {
      const state = (await this.journal.load()) ?? { key: this.keyId, vault: this.vault.toBase58(), generation: signed.generation, spent: 0, reserved: [] };
      await this.journal.save({ ...state, generation: v.generation });
    });
    this.staleAcknowledged = false;
  }

  private async sendDirect(signed: SignedAction, v1Signer: V1MessageSigner, opts: ExecuteOpts): Promise<DirectExecuteResult> {
    const cfg = this.opts.v1Config ?? {};
    const res = await sendDirectV1(this.rpc, v1Signer, {
      programId: this.programId,
      vault: this.vault,
      payer: this.payer.publicKey,
      action: signed.action,
      signature: signed.lmsSignature,
      computeUnitLimit: cfg.computeUnitLimit ?? this.opts.computeUnits ?? EXECUTE_COMPUTE_UNITS,
      ...(cfg.priorityFeeLamports !== undefined ? { priorityFeeLamports: cfg.priorityFeeLamports } : {}),
      ...(cfg.loadedAccountsDataSizeLimit !== undefined ? { loadedAccountsDataSizeLimit: cfg.loadedAccountsDataSizeLimit } : {}),
      ...(this.opts.tokenProgram ? { tokenProgram: this.opts.tokenProgram } : {}),
      ...(opts.closeTokenAccounts ? { closeTokenAccounts: opts.closeTokenAccounts } : {}),
      ...(opts.source ? { source: opts.source } : {}),
      commitment: opts.commitment ?? this.opts.commitment,
    });
    opts.onTransaction?.(0, 1, res.signature);
    return { ...signed, mode: "direct-v1", signatures: [res.signature], transactionBytes: res.transactionBytes };
  }

  private async sendStaged(signed: SignedAction, opts: ExecuteOpts): Promise<StagedExecuteResult> {
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
      ...(opts.source ? { source: opts.source } : {}),
    });
    const signatures = await sendSequence(this.rpc, this.payer, staged.transactions, { ...opts, commitment: opts.commitment ?? this.opts.commitment });
    return { ...signed, mode: "staged", nonce, sigBuffer: staged.sigBuffer, signatures };
  }

  /**
   * Fills the validity window: `issuedSlot` defaults to the current slot, `expirySlot` to
   * `issuedSlot + defaultExpirySlots`. A window the chain would refuse (inverted, or longer than
   * `MAX_VALIDITY_SLOTS`) is refused here before any leaf is spent.
   */
  private async withWindow(request: ActionRequest): Promise<Action> {
    let { issuedSlot, expirySlot } = request;
    if (issuedSlot === undefined || expirySlot === undefined) {
      const slot = BigInt(await this.rpc.getSlot(this.opts.commitment));
      issuedSlot ??= slot;
      expirySlot ??= issuedSlot + BigInt(this.opts.defaultExpirySlots ?? DEFAULT_EXPIRY_SLOTS);
    }
    checkValidityWindow({ issuedSlot, expirySlot });
    return { ...request, issuedSlot, expirySlot } as Action;
  }
}

/** What sits at a vault address: nothing, a live vault, or the tombstone of a closed one. */
export type VaultAddressState = "free" | "vault" | "tombstone";

/** Reads the account at `vault` and says which of the three it is. Anything else is an error. */
export async function vaultAddressState(rpc: Rpc, vault: PublicKey, commitment?: Commitment): Promise<VaultAddressState> {
  const info = await rpc.getAccountInfo(vault, commitment);
  if (!info) return "free";
  return decodeVaultOrTombstone(new Uint8Array(info.data)).kind;
}

export interface FreshKeyOptions {
  /** First index to try; default 0. */
  start?: number;
  /** Last index to try; default `RECOVERY_MAX_INDEX`. */
  maxIndex?: number;
  /** Typecodes of the keys; default H10 / W4 (the vault default). */
  lmsType?: number;
  lmotsType?: number;
  /** Default: the id declared by `programs/lamport-vault`. */
  programId?: PublicKey;
  commitment?: Commitment;
}

export interface FreshKey {
  /** The index whose vault address is free. */
  k: number;
  /** Its key material (build it with `LmsPrivateKey.generate(material)`). */
  material: LmsKeyMaterial;
  /** The key, already built (the address needs its root). */
  key: LmsPrivateKey;
  /** The vault address `create_vault` would use for it. */
  vault: PublicKey;
  /** Indices skipped because their address holds a live vault or a tombstone. */
  skipped: { k: number; state: Exclude<VaultAddressState, "free"> }[];
}

/**
 * The next key index under `master` whose vault address is free: a closed vault leaves a
 * tombstone at its address for good (DESIGN.md section 2, "Close"), so `create_vault` with that
 * key fails `VaultClosed`, and an address with a live vault is in use. Walks `k` from `start`,
 * builds each key (its address needs the root, H10 takes a fraction of a second) and reads the
 * account. Pass `start` as the index after the last one you know you used to save the probes.
 */
export async function nextFreshKeyIndex(master: Uint8Array, scope: DerivationScope, rpc: Rpc, opts: FreshKeyOptions = {}): Promise<FreshKey> {
  const start = opts.start ?? 0;
  const max = opts.maxIndex ?? RECOVERY_MAX_INDEX;
  if (!Number.isInteger(start) || start < 0 || start > max) throw new RangeError(`start must be in 0..${max}, got ${start}`);
  const programId = opts.programId ?? LAMPORT_VAULT_PROGRAM_ID;
  const skipped: FreshKey["skipped"] = [];
  for (let k = start; k <= max; k++) {
    const material = deriveKeyMaterial(master, k, scope, opts.lmsType ?? LMS_SHA256_M32_H10, opts.lmotsType ?? LMOTS_SHA256_N32_W4);
    const key = await LmsPrivateKey.generateAsync(material);
    const vault = findVaultPdaForKey(programId, key.publicKey).address;
    const state = await vaultAddressState(rpc, vault, opts.commitment);
    if (state === "free") return { k, material, key, vault, skipped };
    skipped.push({ k, state });
  }
  throw new Error(`no free vault address among key indices ${start}..${max}`);
}

export interface NextKeyMaterial {
  /** Index of the vault's current key under `master`. */
  k: number;
  /** Material of the key a `Rotate` should go to: index k+1, the vault's typecodes. */
  material: LmsKeyMaterial;
}

/**
 * The key a vault should rotate to next (SPEC-DERIVATION.md: "each Rotate uses the next index"):
 * find the index `k` of the vault's current `lms_pubkey` under `master` for `scope` (the
 * cluster's genesis hash and the vault program id) by its `I` (the first step of recovery; `I_k`
 * is 128 bits so no tree is built), then derive index k+1 with the vault's own typecodes. Throws
 * when the current key is not derived from `master` within `maxIndex` (default
 * `RECOVERY_MAX_INDEX`). Build it with `LmsPrivateKey.generate(material)`.
 */
export function nextKeyMaterial(master: Uint8Array, vault: Pick<VaultAccount, "lmsPubkey">, scope: DerivationScope, opts: { maxIndex?: number } = {}): NextKeyMaterial {
  const current = parseLmsPublicKey(vault.lmsPubkey);
  const max = opts.maxIndex ?? RECOVERY_MAX_INDEX;
  for (let k = 0; k <= max; k++) {
    if (!equalBytes(deriveLmsInputs(master, k, scope).I, current.I)) continue;
    if (k === 0xffffffff) throw new Error("the vault's key is the registry key (index 0xffffffff); it has no next index");
    return { k, material: deriveKeyMaterial(master, k + 1, scope, current.lmsType, current.lmotsType) };
  }
  throw new Error(`the vault's current key is not derived from this master seed for this cluster and program (indices 0..${max} tried)`);
}

export interface RegistryClientOptions {
  rpc: Rpc;
  /** Default: the id declared by `programs/pq-registry`. */
  programId?: PublicKey;
  payer: Signer;
  chunkSize?: number;
  computeUnits?: number;
  commitment?: Commitment;
  /** Slots a rotation stays valid when the call names no expiry. Default {@link DEFAULT_EXPIRY_SLOTS}. */
  defaultExpirySlots?: number;
}

export interface RotatePqResult extends ValidityWindow {
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
   * `rotate_pq`: sign sha256("pq-registry/v1" || program_id || owner || u32le(generation) ||
   * new_pq_pubkey || u64le(issued_slot) || u64le(expiry_slot)) with the committed LMS key at leaf
   * q >= next_q, stage it, rotate. The window defaults to the current slot and
   * `defaultExpirySlots` after it. Anyone can pay; the owner's classical key is not needed. A key
   * that was committed before is refused up front.
   */
  async rotatePq(
    owner: PublicKey,
    committedKey: LmsPrivateKey,
    newPqPubkey: Uint8Array,
    opts: SendOpts & { q?: number; nonce?: bigint } & Partial<ValidityWindow> = {},
  ): Promise<RotatePqResult> {
    const current = await this.fetchCommitment(owner);
    if (!current) throw new Error(`no commitment for ${owner.toBase58()}`);
    if (!Buffer.from(current.pqPubkey).equals(Buffer.from(committedKey.publicKey))) {
      throw new Error("the committed pq_pubkey is not this key");
    }
    const q = opts.q ?? current.nextQ;
    if (q < current.nextQ) throw new Error(`q=${q} is below the commitment's next_q=${current.nextQ}`);
    if (hasUsedKey(current, newPqPubkey)) {
      throw new Error("rotation to a key that was committed before (the chain would refuse it with KeyReused)");
    }
    let { issuedSlot, expirySlot } = opts;
    if (issuedSlot === undefined || expirySlot === undefined) {
      const slot = BigInt(await this.opts.rpc.getSlot(this.opts.commitment));
      issuedSlot ??= slot;
      expirySlot ??= issuedSlot + BigInt(this.opts.defaultExpirySlots ?? DEFAULT_EXPIRY_SLOTS);
    }
    const window: ValidityWindow = { issuedSlot, expirySlot };
    checkValidityWindow(window);
    const message = registryMessage(owner, current.generation, newPqPubkey, window, this.programId);
    const lmsSignature = committedKey.sign(q, message);
    const nonce = opts.nonce ?? randomNonce();
    const staged = buildStagedRotatePq({
      programId: this.programId,
      owner,
      payer: this.opts.payer.publicKey,
      nonce,
      newPqPubkey,
      window,
      signature: lmsSignature,
      chunkSize: this.opts.chunkSize ?? MAX_CHUNK_BYTES,
      computeUnits: this.opts.computeUnits ?? EXECUTE_COMPUTE_UNITS,
    });
    const signatures = await sendSequence(this.opts.rpc, this.opts.payer, staged.transactions, { ...opts, commitment: opts.commitment ?? this.opts.commitment });
    return { q, generation: current.generation, nonce, message, lmsSignature, signatures, buffer: staged.buffer, ...window };
  }
}
