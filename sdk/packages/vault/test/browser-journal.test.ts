/**
 * BrowserLeafJournal on a fake IndexedDB (`fake-indexeddb`): records keyed by the key fingerprint,
 * durable across objects, serialised across "tabs" by a Web Lock, and the same reserve-before-sign
 * rule as the file journal. The module itself has no Node dependency and loads with no `indexedDB`.
 */
import { IDBFactory } from "fake-indexeddb";
import { Keypair } from "@solana/web3.js";
import { fromHex, LMS_SHA256_M32_H5, LmsPrivateKey } from "@lamport-robotics/lms";
import { describe, expect, it } from "vitest";
import { encodeVault } from "../src/accounts.ts";
import { BROWSER_JOURNAL_DB, BrowserLeafJournal, keyFingerprint, type LeafJournalState } from "../src/journal.ts";
import { findVaultPdaForKey, vaultId } from "../src/pda.ts";
import { LAMPORT_VAULT_PROGRAM_ID } from "../src/programIds.ts";
import { VaultSigner, withJournalLock } from "../src/signer.ts";
import { MockChain } from "./mock.ts";

const key = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H5, lmotsType: 3, seed: fromHex("784bd340367baa20a90c48bf5623171cba34eb7b4022f11ecca2cc1a893cb506"), I: fromHex("00112233445566778899aabbccddeeff") });
const transfer = { kind: "TransferSol" as const, to: Keypair.generate().publicKey, lamports: 1n };
const KEY = keyFingerprint(key.publicKey);
const VAULT = findVaultPdaForKey(LAMPORT_VAULT_PROGRAM_ID, key.publicKey).address.toBase58();
const st = (generation: number, spent: number, reserved: number[], k = KEY): LeafJournalState => ({ key: k, vault: VAULT, generation, spent, reserved });
const OTHER_KEY = "ab".repeat(32);

function freshVault(): Uint8Array {
  return encodeVault({ version: 2, bump: 0, vaultId: vaultId(key.publicKey), lmsPubkey: key.publicKey, spent: 0, generation: 0, createdSlot: 1n, used: new Uint8Array(4), usedKeys: [] });
}

/** A minimal Web Locks manager: exclusive, FIFO, one name space. */
function fakeLocks(): LockManager & { held: string[] } {
  const queues = new Map<string, Promise<unknown>>();
  const held: string[] = [];
  return {
    held,
    request: ((name: string, a: unknown, b?: unknown) => {
      const cb = (typeof a === "function" ? a : b) as (lock: Lock | null) => Promise<unknown>;
      const previous = queues.get(name) ?? Promise.resolve();
      const run = previous.then(async () => {
        held.push(`+${name}`);
        try {
          return await cb({ name, mode: "exclusive" });
        } finally {
          held.push(`-${name}`);
        }
      });
      queues.set(
        name,
        run.catch(() => undefined),
      );
      return run;
    }) as LockManager["request"],
    query: async () => ({ held: [], pending: [] }),
  };
}

describe("BrowserLeafJournal", () => {
  it("loads in Node and refuses to run without an IndexedDB", async () => {
    expect(typeof globalThis.indexedDB).toBe("undefined");
    const j = new BrowserLeafJournal({ key: key.publicKey });
    expect(j.dbName).toBe(BROWSER_JOURNAL_DB);
    expect(j.key).toBe(KEY);
    expect(j.lockKey).toBe(`idb:${BROWSER_JOURNAL_DB}:${KEY}`);
    await expect(j.load()).rejects.toThrow(/no indexedDB/);
    await expect(j.save(st(0, 0, []))).rejects.toThrow(/no indexedDB/);
    expect(() => new BrowserLeafJournal({ key: "nope" })).toThrow(/64 hex/);
    // a fingerprint works as the key
    expect(new BrowserLeafJournal({ key: KEY.toUpperCase() }).key).toBe(KEY);
  });

  it("starts empty, persists across objects (reload) and keeps one record per key", async () => {
    const indexedDB = new IDBFactory();
    const a = new BrowserLeafJournal({ key: key.publicKey, indexedDB });
    expect(await a.load()).toBeNull();
    await a.save(st(0, 3, [4, 7]));
    const b = new BrowserLeafJournal({ key: KEY, indexedDB });
    expect(await b.load()).toEqual(st(0, 3, [4, 7]));
    expect(a.lockKey).toBe(b.lockKey);
    // the returned state is a copy
    const s = (await b.load())!;
    s.reserved.push(99);
    expect((await b.load())!.reserved).toEqual([4, 7]);
    // other key, other database: other records; a state for another key is refused
    expect(await new BrowserLeafJournal({ key: OTHER_KEY, indexedDB }).load()).toBeNull();
    expect(await new BrowserLeafJournal({ key: KEY, indexedDB, dbName: "elsewhere" }).load()).toBeNull();
    expect(await new BrowserLeafJournal({ key: KEY, indexedDB: new IDBFactory() }).load()).toBeNull();
    await expect(a.save(st(0, 0, [], OTHER_KEY))).rejects.toThrow(/belongs to key/);
    // a save overwrites; close() drops the connection and the next call reopens
    await b.save(st(0, 4, [7]));
    a.close();
    expect(await a.load()).toEqual(st(0, 4, [7]));
    await expect(a.save(st(0, 0, [-1]))).rejects.toThrow(/reserved/);
  });

  it("refuses a foreign or corrupt record instead of guessing", async () => {
    const indexedDB = new IDBFactory();
    const j = new BrowserLeafJournal({ key: KEY, indexedDB });
    await j.save(st(0, 0, []));
    const put = (value: unknown) =>
      new Promise<void>((resolve, reject) => {
        const req = indexedDB.open(BROWSER_JOURNAL_DB, 1);
        req.onsuccess = () => {
          const tx = req.result.transaction("journals", "readwrite");
          tx.objectStore("journals").put(value, KEY);
          tx.oncomplete = () => {
            req.result.close();
            resolve();
          };
          tx.onerror = () => reject(tx.error);
        };
        req.onerror = () => reject(req.error);
      });
    await put({ v: 1, generation: 0, spent: 0, reserved: [] });
    await expect(j.load()).rejects.toThrow(/format 1/);
    await put({ v: 2, key: KEY, vault: VAULT, generation: 0, spent: "0", reserved: [] });
    await expect(j.load()).rejects.toThrow(/spent/);
    await put({ v: 2, key: OTHER_KEY, vault: VAULT, generation: 0, spent: 0, reserved: [] });
    await expect(j.load()).rejects.toThrow(/belongs to key/);
    await put("nonsense");
    await expect(j.load()).rejects.toThrow(/not a journal object/);
    await put({ v: 2, key: KEY, vault: VAULT, generation: 0, spent: 0, reserved: [] });
    expect(await j.load()).toEqual(st(0, 0, []));
  });

  it("reserves before signing: two signers over two journal objects never pick the same leaf", async () => {
    const indexedDB = new IDBFactory();
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const first = new VaultSigner({ rpc, key, payer, journal: new BrowserLeafJournal({ key: key.publicKey, indexedDB }) });
    rpc.accounts.set(first.vault.toBase58(), freshVault());
    const a = await first.sign(transfer);
    expect(a.q).toBe(0);
    expect(a.ephemeral).toBe(false);
    expect(await new BrowserLeafJournal({ key: KEY, indexedDB }).load()).toEqual(st(0, 0, [0]));
    // "reload": a second signer with a fresh journal object over the same database
    const second = new VaultSigner({ rpc, key, payer, journal: new BrowserLeafJournal({ key: KEY, indexedDB }) });
    expect(await second.nextQ()).toBe(1);
    await expect(second.sign(transfer, { q: 0 })).rejects.toThrow(/journal/);
    expect((await second.sign(transfer)).q).toBe(1);
    expect(await new BrowserLeafJournal({ key: KEY, indexedDB }).load()).toEqual(st(0, 0, [0, 1]));
    // racing from both objects: distinct leaves
    const results = await Promise.all([first.sign(transfer), second.sign(transfer), first.sign(transfer), second.sign(transfer)]);
    expect(results.map((r) => r.q).sort((x, y) => x - y)).toEqual([2, 3, 4, 5]);
    // once the leaves land the next sync counts them as spent
    rpc.spend(first.vault, [0, 1, 2, 3, 4, 5]);
    expect((await second.sign(transfer)).q).toBe(6);
    expect(await new BrowserLeafJournal({ key: KEY, indexedDB }).load()).toEqual(st(0, 6, [6]));
  });

  it("takes a Web Lock named after the record around every load / save pair when the API exists", async () => {
    const indexedDB = new IDBFactory();
    const locks = fakeLocks();
    const j = new BrowserLeafJournal({ key: KEY, indexedDB, locks });
    const order: string[] = [];
    const run = (name: string, ms: number) =>
      withJournalLock(j, async () => {
        order.push(`${name} start`);
        await new Promise((r) => setTimeout(r, ms));
        order.push(`${name} end`);
      });
    await Promise.all([run("a", 10), run("b", 1)]);
    expect(order).toEqual(["a start", "a end", "b start", "b end"]);
    expect(locks.held).toEqual([`+${j.lockKey}`, `-${j.lockKey}`, `+${j.lockKey}`, `-${j.lockKey}`]);
    // held directly: a second object (another tab) waits rather than fails
    await j.acquireLock();
    await expect(j.acquireLock()).rejects.toThrow(/already held/);
    const other = new BrowserLeafJournal({ key: KEY, indexedDB, locks });
    let got = false;
    const waiting = other.acquireLock().then(() => (got = true));
    await new Promise((r) => setTimeout(r, 5));
    expect(got).toBe(false);
    await j.releaseLock();
    await waiting;
    expect(got).toBe(true);
    await other.releaseLock();
    await other.releaseLock(); // idempotent
    // no API, no lock, still works
    const bare = new BrowserLeafJournal({ key: KEY, indexedDB });
    await bare.acquireLock();
    await bare.releaseLock();
    expect(await withJournalLock(bare, async () => 7)).toBe(7);
  });
});
