/**
 * Leaf journal and the signer rollback rule (docs/DESIGN.md "Signer rollback"): a journal that is
 * behind the chain makes the signer refuse everything but Rotate, a Rotate that lands resets it,
 * and two signers over one journal file never reserve the same leaf.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Keypair } from "@solana/web3.js";
import { fromHex, LMS_SHA256_M32_H5, LmsPrivateKey, lmsVerify } from "@lamport-robotics/lms";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { encodeVault, usedKeyHash, type VaultAccount } from "../src/accounts.ts";
import { FileLeafJournal, JournalLockedError, type LeafJournal, type LeafJournalState, MemoryLeafJournal, parseJournalFile, STALE_LOCK_MS, StaleSignerError } from "../src/journal.ts";
import { vaultId } from "../src/pda.ts";
import { VaultSigner, withJournalLock } from "../src/signer.ts";
import { MockChain } from "./mock.ts";

const key = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H5, lmotsType: 3, seed: fromHex("784bd340367baa20a90c48bf5623171cba34eb7b4022f11ecca2cc1a893cb506"), I: fromHex("00112233445566778899aabbccddeeff") });
const keyB = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H5, lmotsType: 3, seed: new Uint8Array(32).fill(0x42), I: new Uint8Array(16).fill(0x42) });

function freshVault(k = key): Uint8Array {
  return encodeVault({ version: 2, bump: 0, vaultId: vaultId(k.publicKey), lmsPubkey: k.publicKey, spent: 0, generation: 0, createdSlot: 1n, used: new Uint8Array(4), usedKeys: [] });
}

const transfer = { kind: "TransferSol" as const, to: Keypair.generate().publicKey, lamports: 1n };

let dir: string;
let warn: ReturnType<typeof vi.spyOn>;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "lamport-journal-"));
  warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** The pid of a process that has already exited. */
function deadPid(): number {
  const child = spawnSync(process.execPath, ["-e", ""]);
  if (child.status !== 0 || !child.pid) throw new Error("could not spawn a child");
  return child.pid;
}

/** Writes `<path>.lock` as another process would have, with the given age. */
function plantLock(path: string, holder: { pid?: number; time?: number } | string, ageMs = 0): void {
  const lock = `${path}.lock`;
  writeFileSync(lock, typeof holder === "string" ? holder : JSON.stringify(holder) + "\n");
  const t = (Date.now() - ageMs) / 1000;
  utimesSync(lock, t, t);
}

describe("FileLeafJournal", () => {
  it("starts empty, persists across objects, and leaves no temporary files behind", async () => {
    const path = join(dir, "persist.json");
    const a = new FileLeafJournal(path);
    expect(await a.load()).toBeNull();
    await a.save({ generation: 2, spent: 3, reserved: [4, 7] });
    const b = new FileLeafJournal(path);
    expect(await b.load()).toEqual({ generation: 2, spent: 3, reserved: [4, 7] });
    expect(a.lockKey).toBe(b.lockKey);
    expect(readdirSync(dir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
    const onDisk = JSON.parse(readFileSync(path, "utf8"));
    expect(onDisk).toEqual({ v: 1, generation: 2, spent: 3, reserved: [4, 7] });
    // the returned state is a copy
    const s = (await b.load())!;
    s.reserved.push(99);
    expect((await b.load())!.reserved).toEqual([4, 7]);
  });

  it("refuses a corrupt or foreign file instead of guessing", async () => {
    const path = join(dir, "corrupt.json");
    writeFileSync(path, "{not json");
    await expect(new FileLeafJournal(path).load()).rejects.toThrow(/JSON/);
    writeFileSync(path, JSON.stringify({ v: 2, generation: 0, spent: 0, reserved: [] }));
    await expect(new FileLeafJournal(path).load()).rejects.toThrow(/format 2/);
    writeFileSync(path, JSON.stringify({ v: 1, generation: 0, spent: "0", reserved: [] }));
    await expect(new FileLeafJournal(path).load()).rejects.toThrow(/spent/);
    expect(() => parseJournalFile(JSON.stringify({ v: 1, generation: -1, spent: 0, reserved: [] }))).toThrow(/generation/);
    expect(() => parseJournalFile(JSON.stringify({ v: 1, generation: 0, spent: 0, reserved: [1.5] }))).toThrow(/reserved/);
    await expect(new FileLeafJournal(path).save({ generation: 0, spent: 0, reserved: [-1] })).rejects.toThrow(/reserved/);
  });

  it("the lock file names this process and goes away on release", async () => {
    const path = join(dir, "lock.json");
    const j = new FileLeafJournal(path);
    expect(j.lockPath).toBe(`${path}.lock`);
    await j.acquireLock();
    const onDisk = JSON.parse(readFileSync(j.lockPath, "utf8"));
    expect(onDisk.pid).toBe(process.pid);
    expect(Math.abs(Date.now() - onDisk.time)).toBeLessThan(5_000);
    await expect(j.acquireLock()).rejects.toThrow(/already held by this object/);
    // another object (another process, as far as the file is concerned) sees a live holder
    let err: unknown;
    await new FileLeafJournal(path).acquireLock().catch((e: unknown) => (err = e));
    expect(err).toBeInstanceOf(JournalLockedError);
    expect((err as JournalLockedError).holder.pid).toBe(process.pid);
    expect((err as JournalLockedError).lock).toBe(j.lockPath);
    expect(String(err)).toMatch(new RegExp(`process ${process.pid}`));
    await j.releaseLock();
    expect(existsSync(j.lockPath)).toBe(false);
    await j.releaseLock(); // idempotent
    const other = new FileLeafJournal(path);
    await other.acquireLock();
    await other.releaseLock();
    expect(existsSync(j.lockPath)).toBe(false);
  });

  it("a lock from a dead process is broken once it is 30 s old, and respected before that", async () => {
    const path = join(dir, "stale.json");
    const dead = deadPid();
    // Old enough: broken and taken.
    plantLock(path, { pid: dead, time: Date.now() - STALE_LOCK_MS - 1_000 }, STALE_LOCK_MS + 1_000);
    const j = new FileLeafJournal(path);
    await j.acquireLock();
    expect(JSON.parse(readFileSync(j.lockPath, "utf8")).pid).toBe(process.pid);
    await j.releaseLock();
    // Dead, but young: the file may still be being written; refused.
    plantLock(path, { pid: dead, time: Date.now() });
    await expect(j.acquireLock()).rejects.toThrow(JournalLockedError);
    // Unparsable content: the file's mtime decides.
    plantLock(path, "");
    await expect(j.acquireLock()).rejects.toThrow(JournalLockedError);
    plantLock(path, "", STALE_LOCK_MS + 1_000);
    await j.acquireLock();
    await j.releaseLock();
    expect(existsSync(j.lockPath)).toBe(false);
    // Release never removes a lock that is not ours.
    plantLock(path, { pid: dead, time: Date.now() });
    await j.releaseLock();
    expect(existsSync(j.lockPath)).toBe(true);
    rmSync(j.lockPath);
  });
});

describe("FileLeafJournal across processes", () => {
  it("two journals over one path cannot both reserve q=0 while the other holds the lock", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const path = join(dir, "cross.json");
    const theirs = new FileLeafJournal(path);
    const signer = new VaultSigner({ rpc, key, payer, journal: new FileLeafJournal(path) });
    rpc.accounts.set(signer.vault.toBase58(), freshVault());
    // "Another process" is inside its critical section (its lock file is on disk, its pid alive).
    await theirs.acquireLock();
    let err: unknown;
    await signer.sign(transfer).catch((e: unknown) => (err = e));
    expect(err).toBeInstanceOf(JournalLockedError);
    await expect(signer.execute(transfer)).rejects.toThrow(/locked by process/);
    expect(existsSync(path)).toBe(false); // it did not even initialise the journal
    expect(rpc.sent.length).toBe(0);
    // It finishes: it reserved q=0 itself.
    await theirs.save({ generation: 0, spent: 0, reserved: [0] });
    await theirs.releaseLock();
    const a = await signer.sign(transfer);
    expect(a.q).toBe(1);
    expect(a.ephemeral).toBe(false);
    expect(existsSync(`${path}.lock`)).toBe(false);
    expect(await theirs.load()).toEqual({ generation: 0, spent: 0, reserved: [0, 1] });
    // The lock is per critical section: the signer's own lock is gone between calls, so a third party can take it.
    await theirs.acquireLock();
    await expect(signer.sign(transfer)).rejects.toThrow(JournalLockedError);
    await theirs.releaseLock();
    expect((await signer.sign(transfer)).q).toBe(2);
  });

  it("a stale lock from a crashed process is broken and signing goes on", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const path = join(dir, "crashed.json");
    writeFileSync(path, JSON.stringify({ v: 1, generation: 0, spent: 0, reserved: [0] }));
    const signer = new VaultSigner({ rpc, key, payer, journal: new FileLeafJournal(path) });
    rpc.accounts.set(signer.vault.toBase58(), freshVault());
    plantLock(path, { pid: deadPid(), time: Date.now() - STALE_LOCK_MS - 5_000 }, STALE_LOCK_MS + 5_000);
    expect((await signer.sign(transfer)).q).toBe(1);
    expect(existsSync(`${path}.lock`)).toBe(false);
    expect(await new FileLeafJournal(path).load()).toEqual({ generation: 0, spent: 0, reserved: [0, 1] });
    // a failure inside the critical section still releases the lock
    await expect(signer.sign(transfer, { q: 0 })).rejects.toThrow(/journal/);
    expect(existsSync(`${path}.lock`)).toBe(false);
    expect(readdirSync(dir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  });
});

describe("VaultSigner journal option", () => {
  it("is required: no silent memory journal", () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    expect(() => new VaultSigner({ rpc, key, payer } as never)).toThrow(/journal is required/);
    expect(() => new VaultSigner({ rpc, key, payer, journal: undefined as never })).toThrow(/"ephemeral"/);
  });

  it('"ephemeral" opts in to a memory journal, warns once on first signature and flags every result', async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const signer = new VaultSigner({ rpc, key, payer, journal: "ephemeral" });
    expect(signer.ephemeral).toBe(true);
    expect(signer.journal).toBeInstanceOf(MemoryLeafJournal);
    rpc.accounts.set(signer.vault.toBase58(), freshVault());
    warn.mockClear();
    expect(await signer.nextQ()).toBe(0);
    expect(warn).not.toHaveBeenCalled(); // reading is not signing
    const a = await signer.sign(transfer);
    expect(a.ephemeral).toBe(true);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]?.[0])).toMatch(/ephemeral/);
    expect(String(warn.mock.calls[0]?.[0])).toContain(signer.vault.toBase58());
    const r = await signer.execute(transfer);
    expect(r.ephemeral).toBe(true);
    expect(r.q).toBe(1);
    expect(warn).toHaveBeenCalledTimes(1); // once per signer, not per signature
    // Another ephemeral signer warns for itself; one with a real journal never does.
    const again = new VaultSigner({ rpc, key, payer, journal: "ephemeral" });
    await again.sign(transfer);
    expect(warn).toHaveBeenCalledTimes(2);
    const durable = new VaultSigner({ rpc, key, payer, journal: new MemoryLeafJournal() });
    expect(durable.ephemeral).toBe(false);
    expect((await durable.sign(transfer)).ephemeral).toBe(false);
    expect((await durable.execute(transfer)).ephemeral).toBe(false);
    expect(warn).toHaveBeenCalledTimes(2);
  });
});

describe("MemoryLeafJournal", () => {
  it("holds one state per object", async () => {
    const j = new MemoryLeafJournal();
    expect(await j.load()).toBeNull();
    await j.save({ generation: 0, spent: 1, reserved: [1] });
    expect(await j.load()).toEqual({ generation: 0, spent: 1, reserved: [1] });
    expect(await new MemoryLeafJournal().load()).toBeNull();
    expect(await new MemoryLeafJournal({ generation: 1, spent: 0, reserved: [] }).load()).toEqual({ generation: 1, spent: 0, reserved: [] });
  });
});

describe("VaultSigner with a journal", () => {
  it("reserves in the journal before signing, so a restart never signs a reserved leaf again", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const path = join(dir, "crash.json");
    const first = new VaultSigner({ rpc, key, payer, journal: new FileLeafJournal(path) });
    rpc.accounts.set(first.vault.toBase58(), freshVault());
    const a = await first.sign(transfer);
    expect(a.q).toBe(0);
    expect(await new FileLeafJournal(path).load()).toEqual({ generation: 0, spent: 0, reserved: [0] });
    // "crash": a new process with the same journal; the chain still shows leaf 0 free
    const second = new VaultSigner({ rpc, key, payer, journal: new FileLeafJournal(path) });
    expect(await second.nextQ()).toBe(1);
    await expect(second.sign(transfer, { q: 0 })).rejects.toThrow(/journal/);
    const b = await second.sign(transfer);
    expect(b.q).toBe(1);
    expect(await new FileLeafJournal(path).load()).toEqual({ generation: 0, spent: 0, reserved: [0, 1] });
    // once the leaves land on chain the next sync drops them from reserved and counts them as spent
    rpc.spend(first.vault, [0, 1]);
    const c = await second.sign(transfer);
    expect(c.q).toBe(2);
    expect(await new FileLeafJournal(path).load()).toEqual({ generation: 0, spent: 2, reserved: [2] });
  });

  it("restored from an old backup: only Rotate, and after the Rotate lands the journal is fresh", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const path = join(dir, "backup.json");
    const live = new VaultSigner({ rpc, key, payer, journal: new FileLeafJournal(path) });
    rpc.accounts.set(live.vault.toBase58(), freshVault());

    // Day 1: one transfer executed, then the journal is backed up.
    const r0 = await live.execute(transfer);
    expect(r0.q).toBe(0);
    expect(rpc.vault(live.vault).spent).toBe(1);
    const backup = readFileSync(path, "utf8");
    expect(JSON.parse(backup)).toEqual({ v: 1, generation: 0, spent: 0, reserved: [0] });
    // Day 2: two more transfers; the second is signed but not submitted (its signature is "out there").
    const r1 = await live.execute(transfer);
    expect(r1.q).toBe(1);
    const unsubmitted = await live.sign(transfer);
    expect(unsubmitted.q).toBe(2);
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ v: 1, generation: 0, spent: 2, reserved: [2] });

    // Day 3: the device is restored from the day-1 backup.
    writeFileSync(path, backup);
    const restored = new VaultSigner({ rpc, key, payer, journal: new FileLeafJournal(path) });
    // The chain shows 2 spent leaves in the lane; the backup accounts for 1 (its reserved leaf 0).
    let err: unknown;
    await restored.sign(transfer).catch((e: unknown) => (err = e));
    expect(err).toBeInstanceOf(StaleSignerError);
    const detail = (err as StaleSignerError).detail;
    expect(detail.chain).toEqual({ generation: 0, spentInLane: 2 });
    expect(detail.journal).toEqual({ generation: 0, spent: 0, reserved: [0] });
    expect(detail.unaccounted).toEqual([1]);
    expect(String(err)).toMatch(/Only Rotate/);
    // execute() and an explicit leaf are refused the same way; nothing was sent or reserved.
    await expect(restored.execute(transfer)).rejects.toThrow(StaleSignerError);
    await expect(restored.sign(transfer, { q: 5 })).rejects.toThrow(StaleSignerError);
    await expect(restored.sign({ kind: "Close", to: payer.publicKey })).rejects.toThrow(StaleSignerError);
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ v: 1, generation: 0, spent: 0, reserved: [0] });
    // The stale journal is left as evidence: still stale on the next try.
    await expect(restored.sign(transfer)).rejects.toThrow(StaleSignerError);

    // Rotate is allowed. (It would pick leaf 2 from the chain's point of view, the very leaf whose
    // signature is out there: that is why only a Rotate, which retires the whole key, is allowed.)
    const sentBefore = rpc.sent.length;
    const rot = await restored.execute({ kind: "Rotate", newLmsPubkey: keyB.publicKey }, { allowForeignKey: true });
    expect(rot.action.kind).toBe("Rotate");
    expect(rot.q).toBe(2);
    expect(lmsVerify(key.publicKey, rot.message, rot.lmsSignature)).toBe(true);
    expect(rpc.sent.length).toBeGreaterThan(sentBefore);
    const v = rpc.vault(live.vault);
    expect(v.generation).toBe(1);
    expect(Buffer.from(v.lmsPubkey)).toEqual(Buffer.from(keyB.publicKey));
    // The Rotate landed: the journal is fresh for generation 1.
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ v: 1, generation: 1, spent: 0, reserved: [] });
    // The leaked day-2 signature is dead now (old generation, old key): nothing to protect against.
    const next = new VaultSigner({ rpc, key: keyB, payer, vault: live.vault, journal: new FileLeafJournal(path) });
    const r = await next.execute(transfer);
    expect(r.q).toBe(0);
    expect(r.generation).toBe(1);
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ v: 1, generation: 1, spent: 0, reserved: [0] });
  });

  it("a journal behind the chain's generation is stale too, until confirmRotation sees the rotation", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const journal = new MemoryLeafJournal({ generation: 0, spent: 0, reserved: [] });
    const signer = new VaultSigner({ rpc, key, payer, journal });
    const past = new Uint8Array(56).fill(9);
    const v: VaultAccount = { version: 2, bump: 0, vaultId: vaultId(key.publicKey), lmsPubkey: key.publicKey, spent: 0, generation: 1, createdSlot: 1n, used: new Uint8Array(4), usedKeys: [usedKeyHash(past)] };
    rpc.accounts.set(signer.vault.toBase58(), encodeVault(v));
    await expect(signer.sign(transfer)).rejects.toThrow(/generation 1, the journal at 0/);
    // confirmRotation refuses a rotation that did not land as signed
    const rot = await signer.sign({ kind: "Rotate", newLmsPubkey: keyB.publicKey }, { allowForeignKey: true });
    await expect(signer.confirmRotation(rot)).rejects.toThrow(/not landed/);
    await expect(signer.confirmRotation({ ...rot, action: transfer as never })).rejects.toThrow(/signed Rotate/);
    // the rotation lands (generation 2, key B): the journal is reset
    rpc.accounts.set(signer.vault.toBase58(), encodeVault({ ...v, generation: 2, lmsPubkey: keyB.publicKey, usedKeys: [usedKeyHash(past), usedKeyHash(key.publicKey)] }));
    await signer.confirmRotation(rot);
    expect(await journal.load()).toEqual({ generation: 2, spent: 0, reserved: [] });
  });

  it("another signer moving on in the same lane makes this one stale; other lanes do not", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const mine = new VaultSigner({ rpc, key, payer, lane: 0, lanes: 2, journal: "ephemeral" });
    const other = new VaultSigner({ rpc, key, payer, lane: 1, lanes: 2, journal: "ephemeral" });
    rpc.accounts.set(mine.vault.toBase58(), freshVault());
    expect((await mine.sign(transfer)).q).toBe(0);
    expect((await other.sign(transfer)).q).toBe(1);
    rpc.spend(mine.vault, [0, 1]); // both land
    expect((await mine.sign(transfer)).q).toBe(2);
    expect((await other.sign(transfer)).q).toBe(3);
    // a stranger spends 5 (lane 1): `other` is stale, `mine` is not
    rpc.spend(mine.vault, [5]);
    expect((await mine.sign(transfer)).q).toBe(4);
    await expect(other.sign(transfer)).rejects.toThrow(StaleSignerError);
    // the unsafe override: adopt the chain and carry on
    other.acknowledgeStale();
    expect((await other.sign(transfer)).q).toBe(7);
    await expect(other.sign(transfer)).resolves.toMatchObject({ q: 9 });
  });

  it("two signers sharing a journal file cannot double-reserve, sequentially or concurrently", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const path = join(dir, "shared.json");
    const a = new VaultSigner({ rpc, key, payer, journal: new FileLeafJournal(path) });
    const b = new VaultSigner({ rpc, key, payer, journal: new FileLeafJournal(path) });
    rpc.accounts.set(a.vault.toBase58(), freshVault());
    expect((await a.sign(transfer)).q).toBe(0);
    expect((await b.sign(transfer)).q).toBe(1);
    expect((await a.sign(transfer)).q).toBe(2);
    await expect(b.sign(transfer, { q: 0 })).rejects.toThrow(/journal/);
    await expect(a.sign(transfer, { q: 1 })).rejects.toThrow(/journal/);
    // eight signatures racing from both objects: eight different leaves
    const results = await Promise.all([a.sign(transfer), b.sign(transfer), a.sign(transfer), b.sign(transfer), b.sign(transfer), a.sign(transfer), a.sign(transfer), b.sign(transfer)]);
    const leaves = results.map((r) => r.q).sort((x, y) => x - y);
    expect(leaves).toEqual([3, 4, 5, 6, 7, 8, 9, 10]);
    expect((await new FileLeafJournal(path).load())!.reserved.sort((x, y) => x - y)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(readdirSync(dir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  });

  it("withJournalLock serialises by lockKey and by object", async () => {
    const order: string[] = [];
    const j: LeafJournal = new MemoryLeafJournal();
    const run = (name: string, ms: number) =>
      withJournalLock(j, async () => {
        order.push(`${name} start`);
        await new Promise((r) => setTimeout(r, ms));
        order.push(`${name} end`);
      });
    await Promise.all([run("a", 15), run("b", 1)]);
    expect(order).toEqual(["a start", "a end", "b start", "b end"]);
    // a rejection does not wedge the lock
    await expect(withJournalLock(j, async () => Promise.reject(new Error("x")))).rejects.toThrow("x");
    await expect(withJournalLock(j, async () => 7)).resolves.toBe(7);
    const state: LeafJournalState = { generation: 0, spent: 0, reserved: [] };
    await j.save(state);
    expect(await j.load()).toEqual(state);
  });
});
