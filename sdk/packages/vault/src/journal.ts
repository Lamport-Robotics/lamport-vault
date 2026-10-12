/**
 * Signer-side leaf journal: the durable record a `VaultSigner` keeps of what it has signed, and
 * the rollback check built on it (docs/DESIGN.md section 2, "Multi-device" and "Signer rollback").
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
 * the directory). `MemoryLeafJournal` lives for one process and is the default when a signer is
 * given no journal. A browser implementation on IndexedDB follows the same interface; until it
 * exists, a web signer keeps the memory journal and relies on the chain's bitmap and the
 * validity window.
 */

/** What a journal stores for one (vault, lane, signer). */
export interface LeafJournalState {
  /** The vault's key generation this record belongs to. */
  generation: number;
  /** Spent leaves in this signer's lane when the journal was last synced with the chain. */
  spent: number;
  /** Leaves this signer has signed (in order of reservation). Written before the signature exists. */
  reserved: number[];
}

/**
 * Durable storage for a {@link LeafJournalState}. `load` returns `null` when nothing was ever
 * saved. Implementations must make `save` durable before resolving: a resolved `save` followed by
 * a crash must still `load` the saved state.
 */
export interface LeafJournal {
  load(): Promise<LeafJournalState | null>;
  save(state: LeafJournalState): Promise<void>;
  /**
   * Optional identity for serialisation: two journal objects with the same `lockKey` are treated
   * as one by `VaultSigner`, so two signers over the same file never interleave a load/save pair.
   */
  readonly lockKey?: string;
}

/** A journal that lives in this object only. Fine for tests and one-shot scripts; nothing survives a restart. */
export class MemoryLeafJournal implements LeafJournal {
  private state: LeafJournalState | null = null;

  constructor(initial: LeafJournalState | null = null) {
    this.state = initial ? cloneState(initial) : null;
  }

  async load(): Promise<LeafJournalState | null> {
    return this.state ? cloneState(this.state) : null;
  }

  async save(state: LeafJournalState): Promise<void> {
    this.state = cloneState(validateState(state));
  }
}

const FILE_FORMAT_VERSION = 1;

/**
 * A journal in one JSON file (Node only; `node:fs/promises` is imported on first use so the
 * package still loads in a browser). Every `save` writes a temporary file next to the journal,
 * fsyncs it, renames it over the journal and fsyncs the directory, so the file on disk is always
 * a complete state: the one before the save or the one after, never a torn write.
 *
 * Two `FileLeafJournal` objects on the same path share a `lockKey` (the resolved path), so two
 * signers in one process cannot reserve the same leaf. Across processes the file is still
 * written atomically, but there is no inter-process lock: run one signing process per journal.
 */
export class FileLeafJournal implements LeafJournal {
  readonly path: string;
  readonly lockKey: string;
  private fs: Promise<typeof import("node:fs/promises")> | undefined;
  private nodePath: Promise<typeof import("node:path")> | undefined;

  constructor(path: string) {
    this.path = path;
    this.lockKey = `file:${path}`;
  }

  private modules(): Promise<[typeof import("node:fs/promises"), typeof import("node:path")]> {
    this.fs ??= import("node:fs/promises");
    this.nodePath ??= import("node:path");
    return Promise.all([this.fs, this.nodePath]);
  }

  async load(): Promise<LeafJournalState | null> {
    const [fs] = await this.modules();
    let text: string;
    try {
      text = await fs.readFile(this.path, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw e;
    }
    return parseJournalFile(text, this.path);
  }

  async save(state: LeafJournalState): Promise<void> {
    validateState(state);
    const [fs, nodePath] = await this.modules();
    const dir = nodePath.dirname(this.path);
    const tmp = nodePath.join(dir, `.${nodePath.basename(this.path)}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`);
    const text = JSON.stringify({ v: FILE_FORMAT_VERSION, generation: state.generation, spent: state.spent, reserved: [...state.reserved] });
    const fh = await fs.open(tmp, "w", 0o600);
    try {
      await fh.writeFile(text, "utf8");
      await fh.sync();
    } finally {
      await fh.close();
    }
    try {
      await fs.rename(tmp, this.path);
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

/** Parses the on-disk JSON form; rejects anything that is not a complete, well-typed state. */
export function parseJournalFile(text: string, source = "journal"): LeafJournalState {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error(`${source}: not valid JSON`);
  }
  if (typeof raw !== "object" || raw === null) throw new Error(`${source}: not a journal object`);
  const o = raw as Record<string, unknown>;
  if (o.v !== FILE_FORMAT_VERSION) throw new Error(`${source}: journal format ${String(o.v)} is not supported (want ${FILE_FORMAT_VERSION})`);
  if (!Array.isArray(o.reserved)) throw new Error(`${source}: reserved must be an array`);
  return validateState({ generation: o.generation as number, spent: o.spent as number, reserved: o.reserved as number[] });
}

function isU32(x: unknown): x is number {
  return typeof x === "number" && Number.isInteger(x) && x >= 0 && x <= 0xffffffff;
}

/** Throws unless `state` is a well-typed journal state. Returns it for chaining. */
export function validateState(state: LeafJournalState): LeafJournalState {
  if (!isU32(state.generation)) throw new Error(`journal: generation must be a u32, got ${String(state.generation)}`);
  if (!isU32(state.spent)) throw new Error(`journal: spent must be a u32, got ${String(state.spent)}`);
  if (!Array.isArray(state.reserved) || !state.reserved.every(isU32)) throw new Error("journal: reserved must be an array of leaf indices");
  return state;
}

export function cloneState(s: LeafJournalState): LeafJournalState {
  return { generation: s.generation, spent: s.spent, reserved: [...s.reserved] };
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
    const why =
      detail.chain.generation !== detail.journal.generation
        ? `the chain is at key generation ${detail.chain.generation}, the journal at ${detail.journal.generation}`
        : `the chain shows ${detail.chain.spentInLane} spent leaves in lane ${detail.lane}/${detail.lanes}, the journal accounts for ${detail.chain.spentInLane - detail.unaccounted.length} (leaves ${detail.unaccounted.join(", ")} were spent by a signer state this journal never saw)`;
    super(`stale signer state for vault ${detail.vault}: ${why}. Only Rotate is allowed until a rotation by this signer lands (or acknowledgeStale(), which is unsafe).`);
    this.name = "StaleSignerError";
    this.detail = detail;
  }
}
