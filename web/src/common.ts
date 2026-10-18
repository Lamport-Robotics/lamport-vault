import { Connection, PublicKey } from "@solana/web3.js";

export const CLUSTER = "devnet" as const;
// on the hosted site json-rpc goes through the same origin (/rpc), which the server forwards to a
// provider; elsewhere (local dev, the single-file build) the public devnet endpoint is used
export const RPC_URL = typeof location !== "undefined" && location.hostname === "vault.lamportrobotics.com" ? `${location.origin}/rpc` : "https://api.devnet.solana.com";
export const GENESIS_HASH = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"; // devnet; mainnet 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d
/** ~400 ms per slot: a rough wall-clock for a slot number relative to `now` */
export const slotToDate = (slot: bigint | number, nowSlot: number) => new Date(Date.now() + (Number(slot) - nowSlot) * 400);
export const EXPLORER = (sig: string) => `https://explorer.solana.com/tx/${sig}?cluster=${CLUSTER}`;
export const EXPLORER_ADDR = (a: string) => `https://explorer.solana.com/address/${a}?cluster=${CLUSTER}`;
/** a transaction signature as the rpc or a wallet returns it: base58, 64 bytes. anything else is not linked */
export const isTxSig = (s: unknown): s is string => typeof s === "string" && /^[1-9A-HJ-NP-Za-km-z]{64,88}$/.test(s);
export const txLink = (sig: string, n = 6): HTMLElement => isTxSig(sig) ? el("a", { href: EXPLORER(sig), target: "_blank", rel: "noopener" }, short(sig, n)) : el("span", { class: "quiet" }, "unreadable signature");

export const rpc = new Connection(RPC_URL, "confirmed");

export const short = (s: string, n = 4) => (s.length > n * 2 + 1 ? `${s.slice(0, n)}…${s.slice(-n)}` : s);
export const sol = (lamports: number | bigint) => (Number(lamports) / 1e9).toLocaleString("en-US", { maximumFractionDigits: 4 });
export const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
export const unb64 = (s: string) => Uint8Array.from(atob(s.trim()), (c) => c.charCodeAt(0));

export function isPubkey(s: string): boolean { try { new PublicKey(s.trim()); return true; } catch { return false; } }

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, ...kids: (Node | string | null | undefined)[]): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) { if (k === "class") n.className = v; else n.setAttribute(k, v); }
  for (const k of kids) if (k != null) n.append(k);
  return n;
}
export const $ = <T extends HTMLElement = HTMLElement>(sel: string, root: ParentNode = document) => root.querySelector(sel) as T;

export async function copy(text: string, btn?: HTMLButtonElement) {
  try { await navigator.clipboard.writeText(text); if (btn) { const t = btn.textContent; btn.textContent = "copied"; setTimeout(() => (btn.textContent = t), 900); } } catch { /* clipboard blocked */ }
}

/** a signing request handed to the cold signer, and what it hands back */
export interface SignRequest {
  v: 1;
  cluster: string;
  vault: string;
  lmsPubkey: string;   // base64, 56 bytes
  nextQ: number;       // the leaf to sign with (first free one, or the signer's lane)
  generation: number;  // key generation of the vault at request time; part of the signed message
  freeLeaves?: number; // leaves the chain still shows as free; the signer subtracts what it has signed itself
  used?: string;       // base64, the vault's used-leaf bitmap at request time; the signer counts free leaves from it
  issuedSlot: string;  // decimal; the window issued..expiry is at most ~1 day of slots
  expirySlot: string;  // decimal
  action:
    | { kind: "TransferSol"; to: string; lamports: string }
    // `to` is the receiver's associated token account; `toOwner` the address the user typed. the signer re-derives `to` from it.
    | { kind: "TransferToken"; mint: string; to: string; toOwner?: string; amount: string; tokenProgram: string; symbol?: string; decimals?: number; source?: string }
    // the signer derives the target itself: the next key of the same words. a target given here must match it.
    | { kind: "Rotate"; newLmsPubkey?: string }
    | { kind: "Close"; to: string };
}
export interface SignedBlob {
  v: 1;
  vault: string;
  q: number;
  action: SignRequest["action"];
  generation?: number;
  issuedSlot: string;
  expirySlot: string;
  signature: string;   // base64
}
