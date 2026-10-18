/**
 * cold signer. one file, no network. paste the request the vault page gave you, type the words,
 * get a signature back. the words never leave this page; close the tab when done.
 */
import "./polyfill.ts";
import "./style.css";
import { PublicKey } from "@solana/web3.js";
import { LmsPrivateKey, isValidMnemonic, mnemonicToMaster, recoverKey, parseLmsPublicKey, deriveKeyMaterial, lmsParams, equalBytes, CLUSTERS, RECOVERY_MAX_INDEX } from "@lamport-robotics/lms";
import { LAMPORT_VAULT_PROGRAM_ID, MAX_VALIDITY_SLOTS, associatedTokenAddress, nextKeyMaterial } from "@lamport-robotics/vault";
import { encodeAction, vaultMessage, type Action } from "@lamport-robotics/vault";
import { $, b64, el, isPubkey, short, unb64, copy, type SignRequest, type SignedBlob } from "./common.ts";
import * as qr from "./qr.ts";
import { openJournal, keyFingerprint } from "./journal.ts";

const app = $("#app");
app.className = "shell";
app.append(
  el("div", { class: "top" }, el("a", { class: "brand", href: "#" }, el("b", {}, "Lamport Vault"), el("i", {}), el("small", {}, "cold signer")), el("span", { class: "offline-pill", id: "net" }, "…")),
  el("div", { class: "page", style: "grid-template-columns:1fr;max-width:640px" },
    el("div", {},
      el("div", { class: "panel" },
        el("div", { class: "eyebrow" }, "1 · Request"),
        el("label", { class: "field" }, el("span", {}, "From the vault page"), el("textarea", { class: "mono", id: "req", rows: "4", placeholder: "" })),
        el("div", { class: "actions" }, el("button", { class: "link quiet", id: "scanreq" }, "Scan QR instead")),
        el("div", { id: "scanbox", class: "qr" }),
        el("div", { id: "reqview" })),
      el("div", { class: "panel" },
        el("div", { class: "eyebrow" }, "2 · Words"),
        el("label", { class: "field" }, el("span", {}, "24 words"), el("textarea", { class: "mono", id: "words", rows: "2", autocomplete: "off", spellcheck: "false" })),
        el("label", { class: "field" }, el("span", {}, "Passphrase, if you set one"), el("input", { class: "mono", id: "pass", type: "password", autocomplete: "off" })),
        el("div", { class: "actions" }, el("button", { class: "btn primary", id: "sign" }, "Sign")),
        el("div", { class: "err hidden", id: "err" })),
      el("div", { class: "panel hidden", id: "out" },
        el("div", { class: "eyebrow" }, "3 · Signature"),
        el("label", { class: "field" }, el("span", {}, "Take this back to the vault page"), el("textarea", { class: "mono", id: "sig", rows: "4", readonly: "" })),
        el("div", { class: "actions" }, el("button", { id: "copy", class: "link" }, "Copy"), el("button", { id: "dl", class: "link" }, "Download .json"), el("button", { id: "qrsig", class: "link" }, "Show QR")),
        el("div", { id: "qrbox", class: "qr", style: "margin-top:14px" }),
        el("div", { class: "notice", style: "margin-top:18px" }, "One one-time key is now spent. If this signature is lost, the next one must use a higher key number; the vault page reads it from the chain.")))),
  el("footer", {}, el("span", {}, "nothing on this page talks to the network"), el("span", {}, "lamportrobotics.com")),
);

const net = $("#net");
const paintNet = () => { const on = navigator.onLine; net.textContent = on ? "online · go offline before typing words" : "offline"; net.className = `offline-pill ${on ? "on" : "off"}`; };
paintNet(); addEventListener("online", paintNet); addEventListener("offline", paintNet);

/** a request that passed every shape check, with what the signer worked out from it */
interface Checked { req: SignRequest; pub: Uint8Array; total: number; used: Uint8Array | null; spentOnChain: number }

const isU64 = (x: unknown) => typeof x === "string" && /^\d{1,20}$/.test(x) && BigInt(x) <= 0xffffffffffffffffn;
const isPk = (x: unknown) => typeof x === "string" && x === x.trim() && isPubkey(x);
const bad = (m: string): never => { throw new Error(`refusing the request: ${m}`); };
const must = <T,>(f: () => T, m: string): T => { try { return f(); } catch { return bad(m); } };

/**
 * every field the signer will act on, checked before a leaf is reserved or a key derived. the request
 * comes from an online machine and may be anything; nothing here is trusted until it has been looked at.
 */
function checkRequest(x: unknown): Checked {
  if (!x || typeof x !== "object") bad("not a sign request");
  const r = x as SignRequest;
  if (r.v !== 1) bad("unknown request version");
  if (typeof r.cluster !== "string" || !r.cluster) bad("cluster missing");
  if (!isPk(r.vault)) bad("vault is not a valid address");
  const pub = must(() => unb64(r.lmsPubkey), "lmsPubkey is not base64");
  const h = must(() => lmsParams(parseLmsPublicKey(pub).lmsType).h, "lmsPubkey is not an LMS public key this signer knows");
  const total = 2 ** h;
  if (!Number.isInteger(r.nextQ) || r.nextQ < 0 || r.nextQ >= total) bad(`nextQ must be a whole number in 0…${total - 1}`);
  if (!Number.isInteger(r.generation) || r.generation < 0 || r.generation > 0xffffffff) bad("generation must be a u32");
  if (!isU64(r.issuedSlot) || !isU64(r.expirySlot)) bad("issuedSlot and expirySlot must be decimal u64 strings");
  // no clock reference offline: only the width of the window can be checked here, the chain checks the rest
  const span = BigInt(r.expirySlot) - BigInt(r.issuedSlot);
  if (span < 1n || span > MAX_VALIDITY_SLOTS) bad(`validity window must be 1…${MAX_VALIDITY_SLOTS} slots, this one is ${span}`);
  if (r.freeLeaves !== undefined && (!Number.isInteger(r.freeLeaves) || r.freeLeaves < 0 || r.freeLeaves > total)) bad("freeLeaves out of range");
  let used: Uint8Array | null = null;
  if (r.used !== undefined) {
    used = must(() => unb64(r.used!), "used bitmap is not base64");
    if (used.length !== total / 8) bad(`used bitmap is ${used.length} bytes, a ${total}-leaf key has ${total / 8}`);
  }
  const a = r.action;
  if (!a || typeof a !== "object") bad("action missing");
  if (a.kind === "TransferSol") {
    if (!isPk(a.to)) bad("destination is not a valid address");
    if (!isU64(a.lamports) || BigInt(a.lamports) === 0n) bad("lamports must be a positive u64");
  } else if (a.kind === "TransferToken") {
    if (!isPk(a.mint) || !isPk(a.to) || !isPk(a.tokenProgram)) bad("mint, destination or token program is not a valid address");
    if (a.source !== undefined && !isPk(a.source)) bad("source is not a valid address");
    if (!isU64(a.amount) || BigInt(a.amount) === 0n) bad("amount must be a positive u64");
    if (a.decimals !== undefined && (!Number.isInteger(a.decimals) || a.decimals < 0 || a.decimals > 255)) bad("decimals out of range");
    if (a.symbol !== undefined && typeof a.symbol !== "string") bad("symbol is not text");
    if (!isPk(a.toOwner)) bad("the request names no receiving owner; prepare it again with the current vault page");
    // the token account is derived here from the owner the user typed; a request that names another one is refused
    const ata = associatedTokenAddress(new PublicKey(a.toOwner!), new PublicKey(a.mint), new PublicKey(a.tokenProgram)).toBase58();
    if (ata !== a.to) bad(`destination token account ${a.to} is not the associated account of ${a.toOwner} for this mint (that is ${ata})`);
  } else if (a.kind === "Rotate") {
    if (a.newLmsPubkey !== undefined) must(() => parseLmsPublicKey(unb64(a.newLmsPubkey!)), "rotation target is not an LMS public key");
  } else if (a.kind === "Close") {
    if (!isPk(a.to)) bad("heir is not a valid address");
  } else bad("unknown action kind");
  let spentOnChain = r.nextQ;   // without a bitmap, the leaves below nextQ are the least that are gone
  if (used) { spentOnChain = 0; for (let b of used) while (b) { spentOnChain += b & 1; b >>= 1; } }
  return { req: r, pub, total, used, spentOnChain };
}

const ui = (raw: string, decimals: number | undefined) => decimals == null ? "" : (Number(raw) / 10 ** decimals).toLocaleString("en-US", { maximumFractionDigits: decimals });

let req: SignRequest | null = null;
let checked: Checked | null = null;
let lastQ = 0;
$("#req").addEventListener("input", () => {
  const v = $("#reqview"); v.innerHTML = ""; req = null; checked = null;
  try {
    const c = checkRequest(JSON.parse(($("#req") as HTMLTextAreaElement).value));
    req = c.req; checked = c;
    const r = c.req, a = r.action;
    const rows: (Node | string)[] = [el("dt", {}, "vault"), el("dd", {}, r.vault)];
    if (a.kind === "TransferSol") rows.push(el("dt", {}, "action"), el("dd", {}, `send ${a.lamports} lamports (${(Number(a.lamports) / 1e9).toLocaleString("en-US", { maximumFractionDigits: 9 })} SOL) to ${a.to}`));
    else if (a.kind === "TransferToken") rows.push(
      el("dt", {}, "action"), el("dd", {}, `send ${a.amount} base units of token ${a.mint}`),
      el("dt", {}, "as decimal"), el("dd", {}, a.decimals == null ? "unknown, the online page gave no decimals" : `${ui(a.amount, a.decimals)} with ${a.decimals} decimals, as reported by the online page`),
      el("dt", {}, "to owner"), el("dd", {}, a.toOwner!),
      el("dt", {}, "token account"), el("dd", {}, `${a.to} (derived here from the owner, matches)`));
    else if (a.kind === "Rotate") rows.push(el("dt", {}, "action"), el("dd", {}, "rotate the vault to the next key from your words"));
    else rows.push(el("dt", {}, "action"), el("dd", {}, `close the vault, everything to ${a.to}`));
    rows.push(
      el("dt", {}, "leaf q"), el("dd", {}, String(r.nextQ)),
      el("dt", {}, "keys spent"), el("dd", {}, c.used ? `${c.spentOnChain} of ${c.total}, from the bitmap` : `at least ${c.spentOnChain} of ${c.total}; the request carries no bitmap`),
      el("dt", {}, "key generation"), el("dd", {}, String(r.generation)),
      el("dt", {}, "valid"), el("dd", {}, `slot ${r.issuedSlot} to ${r.expirySlot} (about ${Math.round((Number(r.expirySlot) - Number(r.issuedSlot)) * 0.4 / 60)} min)`),
      el("dt", {}, "cluster"), el("dd", {}, r.cluster));
    v.append(el("dl", { class: "spec", style: "margin-top:4px" }, ...rows));
  } catch (e) { v.append(el("div", { class: "err" }, String((e as Error).message))); }
});

/** a warning that needs a deliberate yes before anything is reserved or signed */
function confirmBox(text: string): Promise<boolean> {
  return new Promise((resolve) => {
    const box = el("div", { class: "notice warn", style: "margin-top:14px" }, el("div", { style: "margin-bottom:12px" }, text),
      el("div", { class: "actions" }, el("button", { class: "btn primary sm", id: "cf-yes" }, "I know every earlier key was submitted — continue"), el("button", { class: "link quiet", id: "cf-no" }, "Cancel")));
    $("#err").before(box);
    $("#cf-yes", box).addEventListener("click", () => { box.remove(); resolve(true); });
    $("#cf-no", box).addEventListener("click", () => { box.remove(); resolve(false); });
  });
}
const UNSEEN = "this signer has never seen this key but the key has already been used; if this machine was restored or is a second signer, a second signature on a reused leaf would let anyone forge. Only continue if you know every earlier leaf was submitted.";

$("#sign").addEventListener("click", async () => {
  const err = $("#err"); err.classList.add("hidden");
  const btn = $("#sign") as HTMLButtonElement;
  let master: Uint8Array | null = null, key: LmsPrivateKey | null = null, next: LmsPrivateKey | null = null;
  try {
    if (!req || !checked) throw new Error("paste a valid request first");
    const { pub, total, used } = checked;
    const words = ($("#words") as HTMLTextAreaElement).value.trim().toLowerCase().split(/\s+/).join(" ");
    if (!isValidMnemonic(words)) throw new Error("that is not a valid 24-word phrase");
    const clusterKey = req.cluster === "mainnet-beta" ? "mainnet" : req.cluster;
    const cluster = (CLUSTERS as Record<string, { genesisHash: string }>)[clusterKey];
    if (!cluster) throw new Error(`unknown cluster "${req.cluster}" in the request; refusing to sign`);
    const scope = { genesisHash: cluster.genesisHash, programId: LAMPORT_VAULT_PROGRAM_ID };
    // one-time keys: never sign the same leaf twice. the journal is this browser's durable memory of
    // which leaves this signer has used; nothing below it is ever offered again.
    const journal = await openJournal();
    if (!journal) throw new Error("this browser gives the signer no durable storage, so it cannot remember which one-time keys it used; open the file in Chrome or Firefox, or use a hardware signer");
    const jk = keyFingerprint(pub);
    const rec = await journal.get(jk);
    const mine = (x: number) => !!rec && (x <= rec.maxQ || rec.used.includes(x));
    const chainUsed = (x: number) => !!used && ((used[x >> 3] >> (x & 7)) & 1) === 1;
    const free = (x: number) => !chainUsed(x) && !mine(x);
    const floor = Math.max(req.nextQ, rec ? rec.maxQ + 1 : 0);
    // free leaves by this signer's own count: the bitmap minus what it signed itself. without a bitmap the
    // online page's number is a ceiling, never more than the leaves above the floor
    let freeNow = 0;
    if (used) { for (let x = 0; x < total; x++) if (free(x)) freeNow++; }
    else freeNow = Math.max(0, Math.min((req.freeLeaves ?? total) - (floor - req.nextQ), total - floor));
    // behind: the chain has moved past what this signer remembers signing
    const behind = rec ? rec.maxQ < req.nextQ - 1 : checked.spentOnChain > 0;
    let q: number | undefined;
    if (req.action.kind === "Rotate" && behind && used) {
      // a rotation retires the key; the highest free leaf is the one least likely to be held by another signer
      for (let x = total - 1; x >= 0; x--) if (free(x)) { q = x; break; }
    } else for (let x = floor; x < total; x++) if (free(x)) { q = x; break; }
    if (q === undefined) throw new Error("no one-time key is left that this signer can use");
    if (freeNow <= 1 && req.action.kind !== "Rotate" && req.action.kind !== "Close") throw new Error("this is the last one-time key of the vault; it may only be spent on a rotation or on closing the vault");
    if (!rec && checked.spentOnChain > 0) { if (!(await confirmBox(UNSEEN))) throw new Error("cancelled; nothing was signed"); }
    else if (req.action.kind === "Rotate" && behind && !used) { if (!(await confirmBox(`this signer's record stops at key ${rec!.maxQ} but the request says the chain is at ${req.nextQ}, and it carries no bitmap to pick a safer key from. ${UNSEEN}`))) throw new Error("cancelled; nothing was signed"); }
    if (q !== req.nextQ) note(`the request asked for key ${req.nextQ}; this signer used key ${q} instead`);
    btn.disabled = true; btn.classList.add("spin"); btn.textContent = "deriving key";
    master = mnemonicToMaster(words, ($("#pass") as HTMLInputElement).value);
    const found = await recoverKey(master, pub, scope, { onProgress: (d, t) => (btn.textContent = `deriving key ${Math.round((d / t) * 100)}%`) });
    if (!found) throw new Error(`these words do not open this vault (checked k = 0…${RECOVERY_MAX_INDEX})`);
    key = found.key;
    if (req.action.kind === "Rotate") {
      // the target is the next key of these same words, derived here; a target in the request must be that key
      btn.textContent = "deriving the next key";
      const { k, material } = nextKeyMaterial(master, { lmsPubkey: pub }, scope);
      next = await LmsPrivateKey.generateAsync(material, { onProgress: (d, t) => (btn.textContent = `deriving the next key ${Math.round((d / t) * 100)}%`) });
      if (req.action.newLmsPubkey && !equalBytes(unb64(req.action.newLmsPubkey), next.publicKey)) throw new Error(`the request asks to rotate to a key these words cannot reproduce (not index ${k + 1}); refusing, the vault would be lost`);
      req.action = { kind: "Rotate", newLmsPubkey: b64(next.publicKey) };
    }
    const action = toAction(req);
    const message = vaultMessage(new PublicKey(req.vault), req.generation, encodeAction(action));
    // every check passed: record the leaf durably, then sign. a refused request costs no leaf.
    if (!(await journal.reserve(jk, q, { vault: req.vault, generation: req.generation }))) throw new Error(`key ${q} is already recorded as used by this signer`);
    const signature = key.sign(q, message);
    lastQ = q;
    const blob: SignedBlob = { v: 1, vault: req.vault, q, generation: req.generation, action: req.action, issuedSlot: req.issuedSlot, expirySlot: req.expirySlot, signature: b64(signature) };
    ($("#sig") as HTMLTextAreaElement).value = JSON.stringify(blob);
    $("#out").classList.remove("hidden");
    $("#out").scrollIntoView({ behavior: "smooth" });
  } catch (e) { err.textContent = String((e as Error).message ?? e); err.classList.remove("hidden"); }
  finally {
    // once a seed was derived the words and the seeds leave this page; best effort, the gc keeps no promise
    if (master) { ($("#words") as HTMLTextAreaElement).value = ""; ($("#pass") as HTMLInputElement).value = ""; }
    try { master?.fill(0); key?.material.seed.fill(0); next?.material.seed.fill(0); } catch { /* fine */ }
    btn.disabled = false; btn.classList.remove("spin"); btn.textContent = "Sign";
  }
});
$("#copy").addEventListener("click", (e) => copy(($("#sig") as HTMLTextAreaElement).value, e.currentTarget as HTMLButtonElement));
let stopQr: (() => void) | null = null;
$("#qrsig").addEventListener("click", async () => { if (stopQr) { stopQr(); stopQr = null; return; } stopQr = await qr.show($("#qrbox"), ($("#sig") as HTMLTextAreaElement).value); });
let scanning: { stop: () => void } | null = null;
$("#scanreq").addEventListener("click", () => {
  if (scanning) { scanning.stop(); scanning = null; return; }
  const sc = qr.scan($("#scanbox")); scanning = sc;
  sc.done.then((text) => { ($("#req") as HTMLTextAreaElement).value = text; $("#req").dispatchEvent(new Event("input")); scanning = null; }).catch(() => { scanning = null; });
});
$("#dl").addEventListener("click", () => {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([($("#sig") as HTMLTextAreaElement).value], { type: "application/json" }));
  a.download = `lamport-vault-signature-q${lastQ}.json`; a.click();
});

function toAction(r: SignRequest): Action {
  const expirySlot = BigInt(r.expirySlot);
  const issuedSlot = BigInt(r.issuedSlot);
  const a = r.action;
  if (a.kind === "TransferSol") return { kind: "TransferSol", to: new PublicKey(a.to), lamports: BigInt(a.lamports), issuedSlot, expirySlot };
  if (a.kind === "TransferToken") return { kind: "TransferToken", mint: new PublicKey(a.mint), to: new PublicKey(a.to), amount: BigInt(a.amount), issuedSlot, expirySlot };
  if (a.kind === "Rotate") { if (!a.newLmsPubkey) throw new Error("rotation target not derived"); const k = unb64(a.newLmsPubkey); parseLmsPublicKey(k); return { kind: "Rotate", newLmsPubkey: k, issuedSlot, expirySlot }; }
  return { kind: "Close", to: new PublicKey(a.to), issuedSlot, expirySlot };
}

// keep the key-derivation code path warm so the first sign is not a cold import
void LmsPrivateKey; void deriveKeyMaterial;

function note(text: string) { const n = el("div", { class: "notice", style: "margin-top:14px" }, text); $("#out").prepend(n); }
