/**
 * durable leaf journal for this browser profile: which one-time keys this signer has already used,
 * per vault and key generation. written before a signature exists. localStorage, mirrored to IndexedDB.
 * a wiped profile forgets; after restoring from any backup, rotate the key before signing again.
 */
export interface JRec { maxQ: number; used: number[] }
export interface Journal { get(k: string): JRec | undefined; reserve(k: string, q: number): Promise<boolean> }
const JKEY = "lamport-vault-signer-journal";
export async function openJournal(): Promise<Journal | null> {
  let data: Record<string, JRec> = {};
  let ls = false;
  try { localStorage.setItem("__probe", "1"); localStorage.removeItem("__probe"); ls = true; data = JSON.parse(localStorage.getItem(JKEY) ?? "{}"); } catch { /* blocked */ }
  const idb = await idbLoad().catch(() => null);
  if (!ls && !idb) return null;
  if (idb) for (const [k, v] of Object.entries(idb)) { const cur = data[k]; if (!cur || v.maxQ > cur.maxQ) data[k] = v; }
  const persist = async () => {
    if (ls) localStorage.setItem(JKEY, JSON.stringify(data));
    await idbSave(data).catch(() => {});
  };
  return {
    get: (k) => data[k],
    async reserve(k, q) {
      const r = data[k] ?? { maxQ: -1, used: [] };
      if (r.used.includes(q) || q <= r.maxQ) return false;
      data[k] = { maxQ: Math.max(r.maxQ, q), used: [...r.used, q].slice(-64) };
      await persist();           // written before the signature exists
      return true;
    },
  };
}
function idbLoad(): Promise<Record<string, JRec> | null> {
  return new Promise((resolve, reject) => {
    if (!("indexedDB" in globalThis)) return resolve(null);
    const open = indexedDB.open("lamport-vault-signer", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("journal");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => { const tx = open.result.transaction("journal", "readonly"); const g = tx.objectStore("journal").get("all"); g.onsuccess = () => resolve((g.result as Record<string, JRec>) ?? {}); g.onerror = () => reject(g.error); };
  });
}
function idbSave(data: Record<string, JRec>): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!("indexedDB" in globalThis)) return resolve();
    const open = indexedDB.open("lamport-vault-signer", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("journal");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => { const tx = open.result.transaction("journal", "readwrite"); tx.objectStore("journal").put(data, "all"); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); };
  });
}
