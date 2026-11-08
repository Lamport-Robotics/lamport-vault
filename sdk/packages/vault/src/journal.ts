/**
 * Signer-side leaf journal: the durable record a `VaultSigner` keeps of what it has signed, and
 * the rollback check built on it (docs/DESIGN.md section 2, "Multi-device" and "Signer rollback").
 *
 * A journal belongs to one LMS key and is keyed by the key's **fingerprint**, `sha256(lms_pubkey)`
 * in hex ({@link keyFingerprint}): a one-time key is one-time wherever it is used, so the record of
 * its spent leaves must follow the key, not the vault or the key generation it happens to serve.
 * The record still names the vault and the generation the key was used under: a journal whose
 * `vault` is not the signer's vault means the key is being pointed at a second vault, which the
 * signer refuses outright; `generation` feeds the stale check below.
 *
 * The chain's bitmap stops a leaf from being *executed* twice. It cannot stop a signer from
 * *signing* a leaf twice, and two LM-OTS signatures by one leaf over two messages are a forgery
 * oracle. Two things make a signer sign a leaf twice: a crash between signing and submitting
 * (the journal's `reserved` list covers it: a leaf is written here before it is signed) and a
 * signer state that went backwards, a journal restored from an old backup or a copy of the key on
 * another device that moved on. The second case is caught by comparing the journal with the
 * chain before every signature: if the chain shows more spent leaves in this signer's lane than
 * the journal can account for, or a newer key generation, the journal is **stale** and the signer
 * refuses everything but `Rotate` (`StaleSignerError`) until a rotation it performed itself
 * lands. A `Rotate` is the safe way out because every signature made under the old generation,
 * known to this journal or not, dies with it.
 *
 * `FileLeafJournal` is the Node implementation (write to a temporary file, fsync, rename, fsync
 * the directory; a `<path>.lock` file keeps two processes out of one journal).
 * `BrowserLeafJournal` is the IndexedDB implementation (one database per origin, one record per
 * key fingerprint; the Web Locks API keeps two tabs out of one journal where the browser has it). `MemoryLeafJournal` lives for one object and nothing in it survives a restart:
 * a `VaultSigner` never picks it on its own, it has to be asked for with `journal: "ephemeral"`.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

/** An LMS key, as the 56-byte public key or as its fingerprint (64 hex characters). */
export type KeyLike = Uint8Array | string;

/**
 * The identity a journal is keyed by: `sha256(lms_pubkey)` as lowercase hex. A fingerprint passed
 * in is normalised and returned; anything else must be a 56-byte LMS public key. (For a vault's
 * initial key this is the hex of its `vault_id`.)
 */
export function keyFingerprint(key: KeyLike): string {
  if (typeof key === "string") {
    const hex = key.toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("key fingerprint must be 64 hex characters (sha256 of the 56-byte LMS public key)");
    return hex;
  }
  if (key.length !== 56) throw new Error("LMS public key must be 56 bytes");
  return bytesToHex(sha256(key));
}

/** What a journal stores for one (key, lane, signer). */
export interface LeafJournalState {
  /** Fingerprint of the key this record belongs to ({@link keyFingerprint}). */
  key: string;
  /** The vault (base58) the key is used in. A key never serves two vaults. */
  vault: string;
  /** The vault's key generation this key was used under. */
  generation: number;
  /** Spent leaves in this signer's lane when the journal was last synced with the chain. */
  spent: number;
  /** Leaves this signer has signed (in order of reservation). Written before the signature exists. */
  reserved: number[];
  /** Leaves this signer signed that the chain has since shown as spent. Kept for good: a leaf once signed is never picked again, whatever an RPC says later. Absent in records written before this field existed. */
  settled?: number[];
  /** Genesis hash (base58) of the cluster the vault lives on, when the signer knows it. A record from another cluster is refused. */
  cluster?: string;
}

/**
 * Durable storage for a {@link LeafJournalState}. `load` returns `null` when nothing was ever
 * saved. Implementations must make `save` durable before resolving: a resolved `save` followed by
 * a crash must still `load` the saved state.
 */
export interface LeafJournal {
  /** Fingerprint of the key this journal is for; `VaultSigner` refuses a journal of another key. */
  readonly key: string;
  load(): Promise<LeafJournalState | null>;
  /** Must reject a state whose `key` is not this journal's. */
  save(state: LeafJournalState): Promise<void>;
  /**
   * Optional identity for serialisation: two journal objects with the same `lockKey` are treated
   * as one by `VaultSigner`, so two signers over the same file never interleave a load/save pair.
   */
  readonly lockKey?: string;
  /**
   * Optional lock against *other* processes or tabs. `withJournalLock` calls `acquireLock` once
   * it holds the per-process critical section and `releaseLock` when the section ends, so a
   * load / save pair is exclusive across everything that can reach the same storage. Throw
   * {@link JournalLockedError} when someone else holds it.
   */
  acquireLock?(): Promise<void>;
  releaseLock?(): Promise<void>;
}

/** Thrown when another live process (or tab) holds the journal's cross-process lock. */
export class JournalLockedError extends Error {
  /** The lock's location: the `.lock` file, or the Web Locks name. */
  readonly lock: string;
  /** Whoever holds it, as far as the lock says. */
  readonly holder: { pid?: number; time?: number };
  constructor(lock: string, holder: { pid?: number; time?: number }) {
    const who = holder.pid !== undefined ? `process ${holder.pid}` : "another process";
    const since = holder.time !== undefined ? ` since ${new Date(holder.time).toISOString()}` : "";
    super(`journal is locked by ${who}${since} (${lock}); run one signing process per journal`);
    this.name = "JournalLockedError";
    this.lock = lock;
    this.holder = holder;
  }
}

/** A journal that lives in this object only. Fine for tests and one-shot scripts; nothing survives a restart. */
export class MemoryLeafJournal implements LeafJournal {
  readonly key: string;
  private state: LeafJournalState | null = null;

  constructor(key: KeyLike, initial: Omit<LeafJournalState, "key"> | null = null) {
    this.key = keyFingerprint(key);
    this.state = initial ? cloneState(validateState({ ...initial, key: this.key })) : null;
  }

  async load(): Promise<LeafJournalState | null> {
    return this.state ? cloneState(this.state) : null;
  }

  async save(state: LeafJournalState): Promise<void> {
    this.state = cloneState(checkKey(validateState(state), this.key, "MemoryLeafJournal"));
  }
}

/** On-disk / IndexedDB record format: 2 since journals are keyed by the key fingerprint. */
export const JOURNAL_FORMAT_VERSION = 2;
const FILE_FORMAT_VERSION = JOURNAL_FORMAT_VERSION;

/** Where a {@link FileLeafJournal} lives: a directory (file `<dir>/<fingerprint>.json`) or an explicit path. */
export type FileLeafJournalLocation = { dir: string; path?: undefined } | { path: string; dir?: undefined };

/**
 * A journal in one JSON file (Node only; `node:fs/promises` is imported on first use so the
 * package still loads in a browser). The file is `<dir>/<key fingerprint>.json`, or the `path`
 * given; either way the record inside names the key and `load` refuses a file written for another
 * key. Every `save` writes a temporary file next to the journal, fsyncs it, renames it over the
 * journal and fsyncs the directory, so the file on disk is always a complete state: the one before
 * the save or the one after, never a torn write.
 *
 * Two `FileLeafJournal` objects on the same path share a `lockKey` (the path), so two signers in
 * one process cannot reserve the same leaf. Across processes a `<path>.lock` file does the same:
 * `VaultSigner` creates it exclusively (`O_EXCL`, holding the creator's pid and the time) around
 * every load / save pair and removes it afterwards. A lock whose process is still alive is
 * respected ({@link JournalLockedError}); one left behind by a dead process is broken once it is
 * {@link STALE_LOCK_MS} old (younger than that it may still be being written).
 */
export class FileLeafJournal implements LeafJournal {
  readonly key: string;
  readonly path: string;
  readonly lockPath: string;
  readonly lockKey: string;
  private fs: Promise<typeof import("node:fs/promises")> | undefined;
  private nodePath: Promise<typeof import("node:path")> | undefined;
  private held = false;

  constructor(key: KeyLike, location: FileLeafJournalLocation) {
    this.key = keyFingerprint(key);
    const path = location.path ?? joinPath(location.dir, `${this.key}.json`);
    this.path = path;
    this.lockPath = `${path}.lock`;
    this.lockKey = `file:${path}`;
  }

  private modules(): Promise<[typeof import("node:fs/promises"), typeof import("node:path")]> {
    this.fs ??= import("node:fs/promises");
    this.nodePath ??= import("node:path");
    return Promise.all([this.fs, this.nodePath]);
  }

  /**
   * Takes the cross-process lock: creates `<path>.lock` with `wx` (fails if it exists) holding
   * `{ pid, time }`. If it exists and its pid is alive, throws {@link JournalLockedError}; if
   * the pid is dead and the file is older than {@link STALE_LOCK_MS}, the lock is broken and
   * taken. `withJournalLock` calls this for every signer; call it yourself only to hold the
   * journal across several operations.
   */
  async acquireLock(): Promise<void> {
    if (this.held) throw new Error(`journal lock ${this.lockPath} is already held by this object`);
    const [fs] = await this.modules();
    const body = JSON.stringify({ pid: process.pid, time: Date.now(), host: hostName() }) + "\n";
    for (let attempt = 0; ; attempt++) {
      try {
        const fh = await fs.open(this.lockPath, "wx", 0o600);
        try {
          await fh.writeFile(body, "utf8");
        } finally {
          await fh.close();
        }
        this.held = true;
        return;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST" || attempt > 2) throw e;
      }
      const holder = await this.readLock();
      // A lock from another host (shared or synced directory) is never broken: its pid cannot be checked
      // from here and its clock is not ours. Clear it by hand once the other side is known to be down.
      if (holder.foreign || holder.alive || holder.age < STALE_LOCK_MS) throw new JournalLockedError(this.lockPath, holder);
      // Dead owner, old lock: break it. Someone else may break it at the same moment; the retry sorts that out.
      await fs.rm(this.lockPath, { force: true });
    }
  }

  /** Releases the lock taken by {@link acquireLock} (removes `<path>.lock` if it is still ours). */
  async releaseLock(): Promise<void> {
    if (!this.held) return;
    this.held = false;
    const [fs] = await this.modules();
    const holder = await this.readLock();
    if (holder.pid === process.pid || holder.pid === undefined) await fs.rm(this.lockPath, { force: true });
  }

  /** What the lock file says, with the owner's liveness and the lock's age in ms (0 if it vanished). */
  private async readLock(): Promise<{ pid?: number; time?: number; host?: string; alive: boolean; age: number; foreign: boolean }> {
    const [fs] = await this.modules();
    let text = "";
    let mtime: number | undefined;
    try {
      text = await fs.readFile(this.lockPath, "utf8");
      mtime = (await fs.stat(this.lockPath)).mtimeMs;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
      return { alive: false, age: 0, foreign: false };
    }
    let pid: number | undefined;
    let time: number | undefined;
    let host: string | undefined;
    try {
      const o = JSON.parse(text) as Record<string, unknown>;
      if (Number.isInteger(o.pid) && (o.pid as number) > 0) pid = o.pid as number;
      if (typeof o.time === "number" && Number.isFinite(o.time)) time = o.time;
      if (typeof o.host === "string") host = o.host;
    } catch {
      // empty or half-written: the owner may still be writing it; age decides below
    }
    // age by the file's mtime (this machine's clock), not by the time the holder wrote into it
    const age = Date.now() - (mtime ?? time ?? Date.now());
    const foreign = host !== undefined && host !== hostName();
    return {
      ...(pid !== undefined ? { pid } : {}),
      ...(time !== undefined ? { time } : {}),
      ...(host !== undefined ? { host } : {}),
      alive: !foreign && pid !== undefined && isProcessAlive(pid),
      age,
      foreign,
    };
  }

  /** What the file held when this object last read it; `save` refuses to overwrite anything else. */
  private loadedText: string | null | undefined;

  async load(): Promise<LeafJournalState | null> {
    const [fs] = await this.modules();
    let text: string;
    try {
      text = await fs.readFile(this.path, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") { this.loadedText = null; return null; }
      throw e;
    }
    this.loadedText = text;
    return parseJournalFile(text, this.path, this.key);
  }

  async save(state: LeafJournalState): Promise<void> {
    checkKey(validateState(state), this.key, this.path);
    const [fs, nodePath] = await this.modules();
    // Compare-and-swap: another process that broke our lock (or a sync client) may have written the
    // file since we read it. Writing over that would drop its reservations, so refuse instead.
    if (this.loadedText !== undefined) {
      let now: string | null;
      try { now = await fs.readFile(this.path, "utf8"); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; now = null; }
      if (now !== this.loadedText) throw new JournalConflictError(this.path);
    }
    const dir = nodePath.dirname(this.path);
    const tmp = nodePath.join(dir, `.${nodePath.basename(this.path)}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`);
    const text = JSON.stringify(toRecord(state));
    const fh = await fs.open(tmp, "w", 0o600);
    try {
      await fh.writeFile(text, "utf8");
      await fh.sync();
    } finally {
      await fh.close();
    }
    try {
      await fs.rename(tmp, this.path);
      this.loadedText = text;
    } catch (e) {
      await fs.rm(tmp, { force: true });
      throw e;
    }
    // The rename is only durable once the directory entry is; fsync the directory where the
    // platform allows opening one (Linux, macOS). Elsewhere the rename itself is still atomic.
    try {
      const dh = await fs.open(dir, "r");
      try {
        await dh.sync();
      } finally {
        await dh.close();
      }
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code !== "EISDIR" && code !== "EPERM" && code !== "EACCES" && code !== "EINVAL") throw e;
    }
  }
}

/** A `.lock` file left by a dead process is broken once it is this old. */
export const STALE_LOCK_MS = 30_000;

/** The journal file changed between this object's `load` and its `save`: someone else wrote it. Reload and retry. */
export class JournalConflictError extends Error {
  readonly path: string;
  constructor(path: string) {
    super(`journal ${path} changed since it was read; another signer wrote it (reload, then retry)`);
    this.name = "JournalConflictError";
    this.path = path;
  }
}

let cachedHost: string | undefined;
function hostName(): string {
  if (cachedHost) return cachedHost;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    cachedHost = (process.versions?.node ? (globalThis as unknown as { require?: (m: string) => { hostname(): string } }).require?.("node:os")?.hostname() : undefined) ?? "";
  } catch { cachedHost = ""; }
  return cachedHost || "?";
}

/** IndexedDB database and object store of {@link BrowserLeafJournal}. */
export const BROWSER_JOURNAL_DB = "lamport-vault-journal";
const BROWSER_JOURNAL_STORE = "journals";
const BROWSER_JOURNAL_DB_VERSION = 1;

export interface BrowserLeafJournalOptions {
  /** The LMS key this journal is for: its 56-byte public key or its fingerprint. */
  key: KeyLike;
  /** Database name; default {@link BROWSER_JOURNAL_DB}. One database per origin, shared by every key. */
  dbName?: string;
  /** The IndexedDB factory; default `globalThis.indexedDB`, read on first use so the module loads anywhere. */
  indexedDB?: IDBFactory;
  /** The Web Locks manager for the cross-tab lock; default `navigator.locks` when it exists, otherwise no cross-tab lock. */
  locks?: LockManager;
}

/**
 * A journal in the browser's IndexedDB: one database per origin ({@link BROWSER_JOURNAL_DB}),
 * one record per LMS key under its fingerprint ({@link keyFingerprint}). Every `save`
 * resolves when its read-write transaction has committed (requested with `durability:
 * "strict"` where the browser honours it). Two tabs over one record are kept apart by a Web
 * Lock named after the record (`navigator.locks`), taken by `withJournalLock` around every
 * load / save pair; where the API is missing, IndexedDB still serialises the writes but a
 * load / save pair is not exclusive, so run the signer in one tab.
 *
 * Nothing here needs Node: `indexedDB` is only read when the journal is first used, so the
 * package loads in Node and the class can be given a fake factory for tests.
 */
export class BrowserLeafJournal implements LeafJournal {
  /** The key fingerprint: the record's key in the object store. */
  readonly key: string;
  readonly dbName: string;
  readonly lockKey: string;
  private readonly opts: BrowserLeafJournalOptions;
  private db: Promise<IDBDatabase> | undefined;
  private release: (() => void) | undefined;

  constructor(opts: BrowserLeafJournalOptions) {
    this.opts = opts;
    this.key = keyFingerprint(opts.key);
    this.dbName = opts.dbName ?? BROWSER_JOURNAL_DB;
    this.lockKey = `idb:${this.dbName}:${this.key}`;
  }

  private factory(): IDBFactory {
    const idb = this.opts.indexedDB ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB;
    if (!idb) throw new Error("BrowserLeafJournal: no indexedDB in this environment (use FileLeafJournal in Node, or pass { indexedDB })");
    return idb;
  }

  private open(): Promise<IDBDatabase> {
    this.db ??= new Promise<IDBDatabase>((resolve, reject) => {
      let req: IDBOpenDBRequest;
      try {
        req = this.factory().open(this.dbName, BROWSER_JOURNAL_DB_VERSION);
      } catch (e) {
        reject(e);
        return;
      }
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(BROWSER_JOURNAL_STORE)) db.createObjectStore(BROWSER_JOURNAL_STORE);
      };
      req.onsuccess = () => {
        const db = req.result;
        // Another tab upgrading the database: let go of the connection; the next call reopens.
        db.onversionchange = () => {
          db.close();
          this.db = undefined;
        };
        resolve(db);
      };
      req.onerror = () => reject(req.error ?? new Error("BrowserLeafJournal: open failed"));
      req.onblocked = () => reject(new Error("BrowserLeafJournal: open blocked by another connection"));
    });
    this.db.catch(() => (this.db = undefined));
    return this.db;
  }

  async load(): Promise<LeafJournalState | null> {
    const db = await this.open();
    const raw = await new Promise<unknown>((resolve, reject) => {
      const tx = db.transaction(BROWSER_JOURNAL_STORE, "readonly");
      const req = tx.objectStore(BROWSER_JOURNAL_STORE).get(this.key);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error("BrowserLeafJournal: load failed"));
      tx.onerror = () => reject(tx.error ?? new Error("BrowserLeafJournal: load failed"));
    });
    if (raw === undefined || raw === null) return null;
    return fromRecord(raw, `BrowserLeafJournal: record ${this.key}`, this.key);
  }

  async save(state: LeafJournalState): Promise<void> {
    checkKey(validateState(state), this.key, `BrowserLeafJournal: record ${this.key}`);
    const db = await this.open();
    const record = toRecord(state);
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(BROWSER_JOURNAL_STORE, "readwrite", { durability: "strict" });
      tx.objectStore(BROWSER_JOURNAL_STORE).put(record, this.key);
      // Resolve on commit, not on the request's success: only then is the write durable.
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("BrowserLeafJournal: save failed"));
      tx.onabort = () => reject(tx.error ?? new Error("BrowserLeafJournal: save aborted"));
    });
  }

  private lockManager(): LockManager | undefined {
    return this.opts.locks ?? (globalThis as { navigator?: { locks?: LockManager } }).navigator?.locks;
  }

  /** Takes the cross-tab Web Lock for this record (waits for another tab to release it). No-op without the API. */
  async acquireLock(): Promise<void> {
    if (this.release) throw new Error(`journal lock ${this.lockKey} is already held by this object`);
    const locks = this.lockManager();
    if (!locks) return;
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    await new Promise<void>((acquired, reject) => {
      locks
        .request(this.lockKey, async () => {
          acquired();
          await held;
        })
        .catch(reject);
    });
    this.release = release;
  }

  async releaseLock(): Promise<void> {
    const release = this.release;
    this.release = undefined;
    release?.();
  }

  /** Closes the database connection; the next `load` / `save` reopens it. */
  close(): void {
    const db = this.db;
    this.db = undefined;
    db?.then((d) => d.close()).catch(() => undefined);
  }
}

/** `kill(pid, 0)`: true when the process exists (EPERM means it exists but is not ours). */
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Parses the on-disk JSON form (`{ v: 2, key, vault, generation, spent, reserved }`); rejects
 * anything that is not a complete, well-typed state, and, when `key` is given, a record written
 * for another key.
 */
export function parseJournalFile(text: string, source = "journal", key?: string): LeafJournalState {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error(`${source}: not valid JSON`);
  }
  return fromRecord(raw, source, key);
}

/** The stored form of a state. */
function toRecord(state: LeafJournalState): Record<string, unknown> {
  return { v: FILE_FORMAT_VERSION, key: state.key, vault: state.vault, generation: state.generation, spent: state.spent, reserved: [...state.reserved], settled: [...(state.settled ?? [])], ...(state.cluster ? { cluster: state.cluster } : {}) };
}

function fromRecord(raw: unknown, source: string, key?: string): LeafJournalState {
  if (typeof raw !== "object" || raw === null) throw new Error(`${source}: not a journal object`);
  const o = raw as Record<string, unknown>;
  if (o.v !== FILE_FORMAT_VERSION) throw new Error(`${source}: journal format ${String(o.v)} is not supported (want ${FILE_FORMAT_VERSION})`);
  if (!Array.isArray(o.reserved)) throw new Error(`${source}: reserved must be an array`);
  const state = validateState({ key: o.key as string, vault: o.vault as string, generation: o.generation as number, spent: o.spent as number, reserved: [...(o.reserved as number[])], settled: Array.isArray(o.settled) ? [...(o.settled as number[])] : [], ...(typeof o.cluster === "string" ? { cluster: o.cluster } : {}) });
  return key === undefined ? state : checkKey(state, key, source);
}

/** Throws unless `state.key` is `key`. Returns the state for chaining. */
function checkKey(state: LeafJournalState, key: string, source: string): LeafJournalState {
  if (state.key !== key) throw new Error(`${source}: journal belongs to key ${state.key}, not ${key}`);
  return state;
}

function isU32(x: unknown): x is number {
  return typeof x === "number" && Number.isInteger(x) && x >= 0 && x <= 0xffffffff;
}

/** Throws unless `state` is a well-typed journal state. Returns it for chaining. */
export function validateState(state: LeafJournalState): LeafJournalState {
  if (typeof state.key !== "string" || !/^[0-9a-f]{64}$/.test(state.key)) throw new Error(`journal: key must be a 64-hex-character fingerprint, got ${String(state.key)}`);
  if (typeof state.vault !== "string" || state.vault.length === 0) throw new Error(`journal: vault must be a base58 address, got ${String(state.vault)}`);
  if (!isU32(state.generation)) throw new Error(`journal: generation must be a u32, got ${String(state.generation)}`);
  if (!isU32(state.spent)) throw new Error(`journal: spent must be a u32, got ${String(state.spent)}`);
  if (!Array.isArray(state.reserved) || !state.reserved.every(isU32)) throw new Error("journal: reserved must be an array of leaf indices");
  if (state.settled !== undefined && (!Array.isArray(state.settled) || !state.settled.every(isU32))) throw new Error("journal: settled must be an array of leaf indices");
  return state;
}

export function cloneState(s: LeafJournalState): LeafJournalState {
  return { key: s.key, vault: s.vault, generation: s.generation, spent: s.spent, reserved: [...s.reserved], settled: [...(s.settled ?? [])] };
}

/** `dir/name` with one separator, without `node:path` (the module must load in a browser). */
function joinPath(dir: string, name: string): string {
  if (!dir) throw new Error("FileLeafJournal: dir must not be empty");
  const sep = dir.includes("\\") && !dir.includes("/") ? "\\" : "/";
  return dir.endsWith(sep) ? dir + name : dir + sep + name;
}

/**
 * Thrown by `VaultSigner` when the journal of its key names another vault: the one-time key is
 * being pointed at a second vault. Its leaves spent in the first vault would be free in the
 * second, and a second signature by a spent leaf is a forgery oracle. There is no override:
 * use a fresh key for the new vault.
 */
export class JournalVaultMismatchError extends Error {
  readonly key: string;
  readonly journalVault: string;
  readonly vault: string;
  constructor(key: string, journalVault: string, vault: string) {
    super(`key ${key} was used with vault ${journalVault}; this signer is for vault ${vault}. A one-time key never serves two vaults: use a fresh key.`);
    this.name = "JournalVaultMismatchError";
    this.key = key;
    this.journalVault = journalVault;
    this.vault = vault;
  }
}

/** What the chain and the journal said when a signer found itself stale. */
export interface StaleSignerDetail {
  vault: string;
  lane: number;
  lanes: number;
  chain: { generation: number; spentInLane: number };
  journal: LeafJournalState;
  /** Chain leaves in this lane that are spent but neither counted in `journal.spent` nor listed in `journal.reserved`. */
  unaccounted: number[];
  /** True when there was no journal at all for a key that has history on chain: a lost record, or a second signer. */
  missingRecord?: boolean;
}

/**
 * Thrown by `VaultSigner.sign` / `execute` for every action but `Rotate` when the journal is
 * behind the chain: restored from an old backup, or a copy of this key on another device signed
 * (and executed) leaves this journal never saw. The signatures this signer made after the
 * journal's last save may still be out there, so signing any of those leaves again would be a
 * second signature by the same one-time key. Rotate: every old-generation signature dies with
 * the rotation, after which the journal is fresh again.
 */
export class StaleSignerError extends Error {
  readonly detail: StaleSignerDetail;
  constructor(detail: StaleSignerDetail) {
    const why = detail.missingRecord
      ? `no journal exists for this key, but the key has history on chain (generation ${detail.chain.generation}, ${detail.chain.spentInLane} spent leaves in lane ${detail.lane}/${detail.lanes}); a lost record may cover a signature that was never submitted`
      : detail.chain.generation !== detail.journal.generation
        ? `the chain is at key generation ${detail.chain.generation}, the journal at ${detail.journal.generation}`
        : `the chain shows ${detail.chain.spentInLane} spent leaves in lane ${detail.lane}/${detail.lanes}, the journal accounts for ${detail.chain.spentInLane - detail.unaccounted.length} (leaves ${detail.unaccounted.join(", ")} were spent by a signer state this journal never saw)`;
    super(`stale signer state for vault ${detail.vault}: ${why}. Only Rotate is allowed until a rotation by this signer lands (or acknowledgeStale(), which is unsafe).`);
    this.name = "StaleSignerError";
    this.detail = detail;
  }
}
