/**
 * durable leaf journal for this browser profile: which one-time keys this signer has already used.
 * keyed by the LMS public key's fingerprint (sha256), not by vault: a one-time key is one-time
 * wherever it is used. written before a signature exists. localStorage, mirrored to IndexedDB.
 *
 * two tabs must not reserve the same leaf: every reserve runs under a Web Lock and re-reads storage
 * inside the lock instead of trusting memory. no Web Locks, no signing.
 * a wiped profile forgets; after restoring from any backup, rotate the key before signing again.
 */
import { sha256 } from "@noble/hashes/sha2.js";

export interface JRec { maxQ: number; used: number[]; vault?: string; generation?: number }
export interface Journal {
  get(key: string): Promise<JRec | undefined>;
  /** records q for this key; false when the leaf (or any lower one) was already used here */
  reserve(key: string, q: number, meta?: { vault?: string; generation?: number }): Promise<boolean>;
}
const JKEY = "lamport-vault-signer-journal";
const LOCK = "lamport-vault-journal";

export const keyFingerprint = (lmsPubkey: Uint8Array) => Array.from(sha256(lmsPubkey)).map((b) => b.toString(16).padStart(2, "0")).join("");

export async function openJournal(): Promise<Journal | null> {
  const ls = (() => { try { localStorage.setItem("__probe", "1"); localStorage.removeItem("__probe"); return true; } catch { return false; } })();
  const idb = "indexedDB" in globalThis;
  if (!ls && !idb) return null;
  const read = async (): Promise<Record<string, JRec>> => {
    let data: Record<string, JRec> = {};
    if (ls) { try { data = JSON.parse(localStorage.getItem(JKEY) ?? "{}"); } catch { data = {}; } }
    const other = idb ? await idbLoad().catch(() => null) : null;
    if (other) for (const [k, v] of Object.entries(other)) { const cur = data[k]; if (!cur || v.maxQ > cur.maxQ) data[k] = v; }
    return data;
  };
  const write = async (data: Record<string, JRec>) => {
    if (ls) localStorage.setItem(JKEY, JSON.stringify(data));
    if (idb) await idbSave(data);
  };
  return {
    async get(key) { return (await read())[key]; },
    reserve: (key, q, meta) => withLock(async () => {
      const data = await read();                      // fresh, inside the lock
      const r = data[key] ?? { maxQ: -1, used: [] };
      if (r.used.includes(q) || q <= r.maxQ) return false;
      data[key] = { maxQ: Math.max(r.maxQ, q), used: [...r.used, q].slice(-64), ...meta };
      await write(data);                               // durable before any signature exists
      return true;
    }),
  };
}

/** Web Locks only. Without them two tabs cannot be kept from reserving the same leaf, so signing is refused. */
async function withLock<T>(f: () => Promise<T>): Promise<T> {
  const locks = (navigator as Navigator & { locks?: LockManager }).locks;
  if (!locks) throw new Error("this browser has no Web Locks, so two tabs could use the same one-time key; use a current Chrome, Firefox or Safari");
  return locks.request(LOCK, { mode: "exclusive" }, f);
}

function idbLoad(): Promise<Record<string, JRec> | null> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("lamport-vault-signer", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("journal");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => { const db = open.result; const tx = db.transaction("journal", "readonly"); const g = tx.objectStore("journal").get("all"); g.onsuccess = () => { resolve((g.result as Record<string, JRec>) ?? {}); db.close(); }; g.onerror = () => { reject(g.error); db.close(); }; };
  });
}
function idbSave(data: Record<string, JRec>): Promise<void> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("lamport-vault-signer", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("journal");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => { const db = open.result; const tx = db.transaction("journal", "readwrite", { durability: "strict" } as IDBTransactionOptions); tx.objectStore("journal").put(data, "all"); tx.oncomplete = () => { resolve(); db.close(); }; tx.onerror = () => { reject(tx.error); db.close(); }; };
  });
}
