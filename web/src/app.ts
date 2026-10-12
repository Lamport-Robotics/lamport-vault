import "./polyfill.ts";
import "./style.css";
import { PublicKey, SystemProgram, type TransactionInstruction } from "@solana/web3.js";
import { LmsPrivateKey, generateMnemonic, isValidMnemonic, mnemonicToMaster, deriveKeyMaterial, recoverKey, parseLmsPublicKey, lmsParams, LMS_SHA256_M32_H10 } from "@lamport-robotics/lms";
import { LAMPORT_VAULT_PROGRAM_ID, PQ_REGISTRY_PROGRAM_ID, TOKEN_PROGRAM_ID, associatedTokenAddress, firstFreeLeaf, isLeafUsed, buildStagedExecution, buildDirectV1Transaction, createVaultInstruction, decodeVault, isTombstone, decodeCommitment, findCommitmentPda, findVaultPdaForKey, commitInstruction, encodeAction, vaultMessage, randomNonce, type Action, type VaultAccount } from "@lamport-robotics/vault";
import { $, CLUSTER, EXPLORER, EXPLORER_ADDR, GENESIS_HASH, b64, copy, el, isPubkey, rpc, short, sol, slotToDate, unb64, type SignRequest, type SignedBlob } from "./common.ts";
import { connectStandard, listWallets, localWallet, onWalletsChange, remember, remembered, type Wallet } from "./wallet.ts";
import * as qr from "./qr.ts";
import { holdings, destinationTokenAccount, toBase, type Holding } from "./tokens.ts";
import { tape } from "./tape.ts";
import { openJournal, keyFingerprint } from "./journal.ts";
import { equalBytes } from "@lamport-robotics/lms";

// ── state ──
let wallet: Wallet | null = null;
let vaultAddr: PublicKey | null = null;
let vault: VaultAccount | null = null;
let vaultLamports = 0;
let vaultTokens: Holding[] = [];
let closed = false;   // the address holds a closed vault's tombstone
let hotKey: LmsPrivateKey | null = null;   // only while the owner chose hot mode in this tab
const SCOPE = { genesisHash: GENESIS_HASH, programId: LAMPORT_VAULT_PROGRAM_ID };
let lastRun: { vault: string; q: number; kind: string; sigs: string[] } | null = null;
type Tab = "deposit" | "withdraw" | "rotate" | "registry";
let tab: Tab = "deposit";
type Mode = "cold" | "hot";
let mode: Mode = "cold";

const app = $("#app");
app.className = "shell";
const top = el("div", { class: "top" },
  el("a", { class: "brand", href: "/" }, el("img", { src: "/mark.svg", alt: "" }), el("b", {}, "Lamport Vault"), el("i", {}), el("small", {}, CLUSTER)),
  el("div", { class: "wallet", id: "walletbox" }));
const main = el("div", { id: "main" });
app.append(top, main, el("footer", {},
  el("a", { href: "https://github.com/Lamport-Robotics/lamport-vault" }, "Source"),
  el("a", { href: "/signer.html", download: "lamport-vault-signer.html" }, "Cold signer"),
  el("a", { href: "https://lamportrobotics.com" }, "Lamport Robotics"),
  el("span", { class: "ids" }, `vault ${short(LAMPORT_VAULT_PROGRAM_ID.toBase58(), 6)} · registry ${short(PQ_REGISTRY_PROGRAM_ID.toBase58(), 6)}`)));

// ── wallet ──
function paintWallet() {
  const box = $("#walletbox"); box.innerHTML = "";
  if (wallet) {
    box.append(el("span", {}, el("span", { class: "dot" }), short(wallet.pubkey.toBase58())), el("button", { class: "link quiet", id: "disc" }, "Disconnect"));
    $("#disc").addEventListener("click", async () => { await wallet?.disconnect(); wallet = null; remember(null); paintWallet(); render(); });
    return;
  }
  const btn = el("button", { class: "link" }, "Connect wallet");
  btn.addEventListener("click", () => pickWallet());
  box.append(btn);
}

/** the wallet picker: every Wallet Standard wallet the browser exposes, with its own icon */
function pickWallet() {
  const ws = listWallets();
  const local = location.hostname === "localhost" || location.hostname === "127.0.0.1";
  const overlay = el("div", { class: "overlay" });
  const list = el("div", { class: "wlist" });
  const close = () => overlay.remove();
  const choose = async (name: string) => {
    try {
      wallet = name === "__local" ? localWallet() : await connectStandard(ws.find((w) => w.name === name)!);
      remember(name); close(); paintWallet(); render();
    } catch (e) { $("#werr-modal", overlay).textContent = String((e as Error).message ?? e); }
  };
  for (const w of ws) {
    const row = el("button", { class: "wrow" }, el("img", { src: w.icon, alt: "" }), el("span", {}, w.name));
    row.addEventListener("click", () => choose(w.name));
    list.append(row);
  }
  if (local) { const row = el("button", { class: "wrow" }, el("span", { class: "wdot" }), el("span", {}, "Local test key")); row.addEventListener("click", () => choose("__local")); list.append(row); }
  if (!ws.length && !local) list.append(el("p", { class: "quiet", style: "margin:4px 0 0" }, "No Solana wallet is installed in this browser. On a phone, open this page inside your wallet's browser, or install Phantom, Solflare or Backpack on desktop."));
  const modal = el("div", { class: "modal" },
    el("div", { class: "mhead" }, el("span", { class: "eyebrow", style: "margin:0" }, "Connect a wallet"), el("button", { class: "link quiet", id: "mclose" }, "Close")),
    el("p", { class: "quiet", style: "font-size:13px" }, "The wallet pays fees and funds deposits. It never holds the vault key."),
    list, el("div", { class: "err", id: "werr-modal" }));
  overlay.append(modal);
  overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });
  $("#mclose", modal).addEventListener("click", close);
  document.body.append(overlay);
}
onWalletsChange(paintWallet);
paintWallet();
void (async () => {
  const name = remembered(); if (!name || wallet) return;
  try {
    if (name === "__local") { if (sessionStorage.getItem("lamport-vault-local-payer")) wallet = localWallet(); }
    else { const w = listWallets().find((x) => x.name === name); if (w) wallet = await connectStandard(w, true); }
    if (wallet) { paintWallet(); render(); }
  } catch { /* the wallet wants a click this time */ }
})();
onWalletsChange(() => { const name = remembered(); if (name && !wallet) { const w = listWallets().find((x) => x.name === name); if (w) connectStandard(w, true).then((c) => { wallet = c; paintWallet(); render(); }).catch(() => {}); } });

// ── routing: #<vault address> ──
addEventListener("hashchange", () => void load());
void load();

async function load() {
  const h = location.hash.slice(1);
  const next = isPubkey(h) ? new PublicKey(h) : null;
  if (!next || !vaultAddr || !next.equals(vaultAddr)) hotKey = null;   // a key loaded for one vault never outlives a switch
  vaultAddr = next;
  vault = null; vaultLamports = 0; closed = false;
  if (vaultAddr) {
    const info = await rpc.getAccountInfo(vaultAddr, "confirmed").catch(() => null);
    if (info && info.owner.equals(LAMPORT_VAULT_PROGRAM_ID)) {
      try { vault = decodeVault(info.data); } catch (e) { closed = isTombstone(info.data); if (!closed) console.warn("vault account not readable", e); vault = null; }
      vaultLamports = info.lamports;
      try { vaultTokens = await holdings(vaultAddr); } catch (e) { console.error("holdings", e); vaultTokens = []; }
    }
  }
  render();
}

function render() {
  main.innerHTML = "";
  if (!vaultAddr) return main.append(home());
  if (!vault) return main.append(notFound());
  main.append(vaultView());
}

// ── home ──
function home() {
  const left = el("div", {},
    el("div", { class: "eyebrow" }, "Post-quantum custody · Solana"),
    el("h1", { style: "margin-top:14px" }, "A vault a quantum computer can't open."),
    el("p", { style: "max-width:46ch" }, "Funds in a Lamport Vault move only on a hash-based signature. No elliptic curve stands between the key and the money, and the chain itself keeps count of which one-time keys have been spent."),
    el("div", { class: "facts" },
      el("div", {}, el("b", {}, "SHA-256"), el("span", {}, "the only cryptographic assumption")),
      el("div", {}, el("b", {}, "1,024"), el("span", {}, "signatures per key, then rotate in place")),
      el("div", {}, el("b", {}, "None"), el("span", {}, "admin keys, pause switches, fees"))));
  const panel = el("div", { class: "panel" },
    el("div", { class: "eyebrow" }, "Open"),
    el("label", { class: "field" }, el("span", {}, "Vault address"), el("input", { class: "mono", id: "open", placeholder: "", autocomplete: "off", spellcheck: "false" })),
    el("div", { class: "actions" }, el("button", { class: "btn primary", id: "go" }, "Open vault"), el("button", { class: "link arrow", id: "new" }, "Create a new one")),
    el("div", { id: "newbox" }));
  const rail = el("div", { class: "rail" },
    el("div", { "data-n": "01" }, el("h3", {}, "Deposit"), el("p", {}, "From any wallet or exchange. A plain transfer to an address that never changes.")),
    el("div", { "data-n": "02" }, el("h3", {}, "Sign offline"), el("p", {}, "The page prepares a request. A single-file signer, run on a machine with no network, turns it into a signature with your 24 words.")),
    el("div", { "data-n": "03" }, el("h3", {}, "Execute"), el("p", {}, "The signature is verified on chain, the key is marked spent, the transfer goes out.")));
  const s = el("div", {}, el("div", { class: "page" }, left, panel), rail);
  $("#go", s).addEventListener("click", () => { const v = ($("#open", s) as HTMLInputElement).value.trim(); if (isPubkey(v)) location.hash = v; else $("#open", s).focus(); });
  $("#open", s).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") $("#go", s).click(); });
  $("#new", s).addEventListener("click", () => newVault($("#newbox", s)));
  return s;
}

function notFound() {
  const s = el("div", { class: "page" }, el("div", {}, el("h2", {}, closed ? "This vault was closed" : "No vault at this address"), el("p", { class: "quiet mono" }, vaultAddr?.toBase58() ?? ""), closed ? el("p", { class: "quiet" }, "A closed vault leaves a permanent marker at its address so it can never be reopened under the same key. Create a new vault; your words give the next key.") : null, el("button", { class: "link arrow", id: "back" }, "Back")));
  $("#back", s).addEventListener("click", () => (location.hash = ""));
  return s;
}

async function newVault(box: HTMLElement) {
  box.innerHTML = "";
  if (!wallet) { box.append(el("div", { class: "notice" }, "Connect the wallet that pays for the vault account first.")); return; }
  const words = generateMnemonic();
  const grid = el("div", { class: "words" });
  words.split(" ").forEach((w, i) => grid.append(el("div", {}, el("span", {}, String(i + 1).padStart(2, "0")), w)));
  const prog = el("div", { class: "ok" }, "Deriving the key…");
  const btn = el("button", { class: "btn primary wide", id: "mk", disabled: "" }, "I wrote them down — create the vault");
  box.append(el("div", { class: "notice warn", style: "margin-top:22px" }, "These 24 words are the vault. Paper or metal, never a screenshot. Nothing here stores them."), grid, prog, el("div", { style: "margin-top:16px" }, btn), el("div", { class: "err hidden", id: "mkerr" }));
  const key = await LmsPrivateKey.generateAsync(deriveKeyMaterial(mnemonicToMaster(words), 0, SCOPE, LMS_SHA256_M32_H10), { onProgress: (d, t) => (prog.textContent = `Deriving the key ${Math.round((d / t) * 100)}%`) });
  prog.textContent = `Address ${findVaultPdaForKey(LAMPORT_VAULT_PROGRAM_ID, key.publicKey).address.toBase58()}`;
  btn.removeAttribute("disabled");
  btn.addEventListener("click", async () => {
    try {
      btn.setAttribute("disabled", ""); btn.classList.add("spin");
      const { instruction, vault: v } = createVaultInstruction({ programId: LAMPORT_VAULT_PROGRAM_ID, payer: wallet!.pubkey, lmsPubkey: key.publicKey });
      await wallet!.send([instruction]);
      hotKey = null; tab = "deposit"; location.hash = v.toBase58();
    } catch (e) { $("#mkerr", box).textContent = String((e as Error).message ?? e); $("#mkerr", box).classList.remove("hidden"); btn.removeAttribute("disabled"); btn.classList.remove("spin"); }
  });
}

// ── vault ──
function vaultView() {
  const v = vault!, addr = vaultAddr!.toBase58();
  const h = lmsParams(parseLmsPublicKey(v.lmsPubkey).lmsType).h;
  const leaves = 2 ** h;
  const nextFree = firstFreeLeaf(v);
  const statement = el("div", { class: "statement" },
    el("div", { class: "eyebrow" }, "Vault"),
    el("div", { class: "addr" }, addr),
    el("div", { class: "meta" }, el("button", { class: "link quiet", id: "cp" }, "Copy address"), el("a", { class: "link quiet", href: EXPLORER_ADDR(addr), target: "_blank", rel: "noopener" }, "Explorer")),
    el("div", { class: "balance" }, sol(vaultLamports), el("small", {}, "SOL")),
    vaultTokens.length ? el("div", { class: "holdings" }, ...vaultTokens.map((t) => el("div", {}, el("span", {}, short(t.mint.toBase58(), 5)), el("span", {}, t.ui)))) : null,
    tape(leaves, v.used, v.spent, nextFree),
    el("dl", { class: "spec" },
      el("dt", {}, "Scheme"), el("dd", {}, `LMS-SHA256 H${h} / W4`),
      el("dt", {}, "Key generation"), el("dd", {}, String(v.generation)),
      el("dt", {}, "Public key"), el("dd", {}, short(b64(v.lmsPubkey), 14))));
  $("#cp", statement).addEventListener("click", (e) => copy(addr, e.currentTarget as HTMLButtonElement));

  const panel = el("div", { class: "panel" });
  const seg = el("div", { class: "seg" }, ...(["deposit", "withdraw", "rotate", "registry"] as Tab[]).map((t) => el("button", { "data-t": t }, t[0].toUpperCase() + t.slice(1))));
  const body = el("div", {});
  panel.append(seg, body);
  const paint = () => {
    seg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.t === tab));
    body.innerHTML = "";
    body.append(tab === "deposit" ? depositPanel() : tab === "withdraw" ? withdrawPanel() : tab === "rotate" ? rotatePanel() : registryPanel());
  };
  seg.addEventListener("click", (e) => { const b = (e.target as HTMLElement).closest("button"); if (b) { tab = b.dataset.t as Tab; paint(); } });
  paint();
  return el("div", { class: "page" }, statement, panel);
}

function resultLine(): HTMLElement | null {
  if (!lastRun || lastRun.vault !== vaultAddr!.toBase58()) return null;
  const r = lastRun, last = r.sigs[r.sigs.length - 1];
  return el("div", { class: "result" }, el("span", {}, `${r.kind} · key ${r.q} spent`), el("a", { href: EXPLORER(last), target: "_blank", rel: "noopener" }, short(last, 6)));
}

function depositPanel() {
  const s = el("div", {},
    el("p", { class: "quiet" }, "A plain transfer. Any wallet or exchange can send to the vault address; nothing else is needed."),
    el("label", { class: "field" }, el("span", {}, "Amount, SOL"), el("input", { class: "mono", id: "amt", inputmode: "decimal", placeholder: "0.00" })),
    el("div", { class: "actions" }, el("button", { class: "btn primary", id: "dep" }, "Deposit"), el("span", { class: "quiet", style: "font-size:12.5px;color:var(--mute)" }, wallet ? `from ${wallet.name}` : "connect a wallet")),
    el("div", { class: "err hidden", id: "deperr" }), el("div", { class: "ok hidden", id: "depok" }));
  $("#dep", s).addEventListener("click", async () => {
    const err = $("#deperr", s), ok = $("#depok", s); err.classList.add("hidden"); ok.classList.add("hidden");
    try {
      if (!wallet) throw new Error("Connect a wallet first.");
      const n = Number(($("#amt", s) as HTMLInputElement).value);
      if (!(n > 0)) throw new Error("Enter an amount.");
      const sig = await wallet.send([SystemProgram.transfer({ fromPubkey: wallet.pubkey, toPubkey: vaultAddr!, lamports: Math.round(n * 1e9) })]);
      ok.innerHTML = `Deposited · <a href="${EXPLORER(sig)}" target="_blank" rel="noopener">${short(sig, 6)}</a>`; ok.classList.remove("hidden");
      await load();
    } catch (e) { err.textContent = String((e as Error).message ?? e); err.classList.remove("hidden"); }
  });
  return s;
}

function modeSwitch(scope: Scope, host: HTMLElement) {
  const sw = el("div", { class: "switch" }, el("button", { "data-m": "cold" }, "Offline signer"), el("button", { "data-m": "hot" }, "This device"));
  const body = el("div", {});
  host.append(sw, body);
  const paint = () => { sw.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.m === mode)); body.innerHTML = ""; body.append(mode === "cold" ? coldFlow(scope) : hotFlow(scope)); };
  sw.addEventListener("click", (e) => { const b = (e.target as HTMLElement).closest("button"); if (b) { mode = b.dataset.m as Mode; paint(); } });
  paint();
}

function withdrawPanel() {
  const s = el("div", {});
  const rl = resultLine(); if (rl) s.append(rl);
  modeSwitch("transfer", s);
  return s;
}

function rotatePanel() {
  const s = el("div", {}, el("p", { class: "quiet" }, "Install a fresh key at the same address. Do it before the last one-time key is spent; the last key can only be used for this."));
  const rl = resultLine(); if (rl) s.append(rl);
  modeSwitch("rotate", s);
  return s;
}

type Scope = "transfer" | "rotate";

function actionForm(scope: Scope): { node: HTMLElement; read: () => SignRequest["action"] } {
  const kinds = scope === "rotate"
    ? [el("option", { value: "Rotate" }, "Rotate to a new key"), el("option", { value: "Close" }, "Close the vault")]
    : [el("option", { value: "TransferSol" }, "Send SOL"), ...(vaultTokens.length ? [el("option", { value: "TransferToken" }, "Send a token")] : [])];
  const kind = el("select", { id: "kind" }, ...kinds);
  const mint = el("select", { id: "mint" }, ...vaultTokens.map((t) => el("option", { value: t.mint.toBase58() }, `${short(t.mint.toBase58(), 5)} · ${t.ui}`)));
  const to = el("input", { class: "mono", id: "to", autocomplete: "off", spellcheck: "false" });
  const amt = el("input", { class: "mono", id: "wamt", inputmode: "decimal", placeholder: "0.00" });
  const rot = el("input", { class: "mono", id: "rot", placeholder: "base64, 56 bytes", autocomplete: "off", spellcheck: "false" });
  const node = el("div", {},
    el("label", { class: "field" }, el("span", {}, "Action"), kind),
    el("label", { class: "field", id: "f-mint" }, el("span", {}, "Token"), mint),
    el("div", { class: "two" },
      el("label", { class: "field", id: "f-to" }, el("span", {}, "Destination"), to),
      el("label", { class: "field", id: "f-amt" }, el("span", {}, "Amount"), amt)),
    el("label", { class: "field", id: "f-rot" }, el("span", {}, "New public key"), rot));
  const sync = () => {
    const k = (kind as HTMLSelectElement).value;
    $("#f-to", node).classList.toggle("hidden", k === "Rotate");
    $("#f-amt", node).classList.toggle("hidden", k !== "TransferSol" && k !== "TransferToken");
    $("#f-rot", node).classList.toggle("hidden", k !== "Rotate");
    $("#f-mint", node).classList.toggle("hidden", k !== "TransferToken");
  };
  kind.addEventListener("change", sync); sync();
  const read = (): SignRequest["action"] => {
    const k = (kind as HTMLSelectElement).value;
    if (k === "TransferSol") { if (!isPubkey(to.value)) throw new Error("Enter a destination address."); const n = Number(amt.value); if (!(n > 0)) throw new Error("Enter an amount."); return { kind: "TransferSol", to: to.value.trim(), lamports: String(Math.round(n * 1e9)) }; }
    if (k === "TransferToken") {
      const h = vaultTokens.find((t) => t.mint.toBase58() === (mint as HTMLSelectElement).value); if (!h) throw new Error("Pick a token.");
      if (!isPubkey(to.value)) throw new Error("Enter a destination address.");
      const amount = toBase(amt.value, h.decimals); if (amount <= 0n || amount > h.amount) throw new Error("Enter an amount the vault holds.");
      lastTokenOwner = new PublicKey(to.value.trim());
      const ata = associatedTokenAddress(lastTokenOwner, h.mint, h.tokenProgram);
      return { kind: "TransferToken", mint: h.mint.toBase58(), to: ata.toBase58(), amount: amount.toString(), tokenProgram: h.tokenProgram.toBase58(), decimals: h.decimals };
    }
    if (k === "Rotate") { const b = unb64(rot.value); parseLmsPublicKey(b); return { kind: "Rotate", newLmsPubkey: b64(b) }; }
    if (!isPubkey(to.value)) throw new Error("Enter a destination address."); return { kind: "Close", to: to.value.trim() };
  };
  return { node, read };
}

/** in-panel confirmation: the action in words, a validity note, Confirm / Cancel */
function confirmPanel(host: HTMLElement, what: string, note: string): Promise<boolean> {
  return new Promise((resolve) => {
    const box = el("div", { class: "notice", style: "margin-top:16px" }, el("div", { class: "mono", style: "font-size:13px;margin-bottom:6px" }, what), el("div", { class: "quiet", style: "font-size:12.5px;margin-bottom:12px" }, note),
      el("div", { class: "actions" }, el("button", { class: "btn primary sm", id: "cf-yes" }, "Confirm"), el("button", { class: "link quiet", id: "cf-no" }, "Cancel")));
    host.append(box);
    $("#cf-yes", box).addEventListener("click", () => { box.remove(); resolve(true); });
    $("#cf-no", box).addEventListener("click", () => { box.remove(); resolve(false); });
  });
}

function describe(a: SignRequest["action"]): string {
  if (a.kind === "TransferSol") return `Send ${(Number(a.lamports) / 1e9).toLocaleString("en-US", { maximumFractionDigits: 9 })} SOL to ${a.to}`;
  if (a.kind === "TransferToken") return `Send ${a.decimals != null ? (Number(a.amount) / 10 ** a.decimals).toLocaleString("en-US", { maximumFractionDigits: a.decimals }) : a.amount} of ${short(a.mint, 6)} to token account ${a.to}`;
  if (a.kind === "Rotate") return `Rotate the vault to a new key ${short(a.newLmsPubkey, 10)}`;
  return `Close the vault and send everything to ${a.to}`;
}

function toAction(a: SignRequest["action"], issuedSlot: bigint, expirySlot: bigint): Action {
  if (a.kind === "TransferSol") return { kind: "TransferSol", to: new PublicKey(a.to), lamports: BigInt(a.lamports), issuedSlot, expirySlot };
  if (a.kind === "TransferToken") return { kind: "TransferToken", mint: new PublicKey(a.mint), to: new PublicKey(a.to), amount: BigInt(a.amount), issuedSlot, expirySlot };
  if (a.kind === "Rotate") return { kind: "Rotate", newLmsPubkey: unb64(a.newLmsPubkey), issuedSlot, expirySlot };
  return { kind: "Close", to: new PublicKey(a.to), issuedSlot, expirySlot };
}

function coldFlow(scope: Scope) {
  const v = vault!;
  const form = actionForm(scope);
  const s = el("div", {}, form.node,
    el("div", { class: "actions" }, el("button", { class: "btn", id: "mkreq" }, "Prepare request")),
    el("div", { id: "reqout", class: "hidden", style: "margin-top:22px" },
      el("label", { class: "field" }, el("span", {}, "Request · for the cold signer"), el("textarea", { class: "mono", id: "reqtxt", rows: "3", readonly: "" })),
      el("div", { class: "actions" }, el("button", { class: "link", id: "cpreq" }, "Copy"), el("button", { class: "link", id: "qrreq" }, "Show QR"), el("a", { class: "link quiet", href: "/signer.html", download: "lamport-vault-signer.html" }, "Download the signer")),
      el("div", { id: "qrbox", class: "qr", style: "margin-top:14px" }),
      el("p", { class: "quiet", style: "margin-top:14px" }, "Open the signer on a machine with no network. Paste or scan the request, type the words, bring the signature back here."),
      el("p", { class: "quiet mono", id: "reqvalid", style: "font-size:12px" })),
    el("div", { style: "margin-top:22px" },
      el("label", { class: "field" }, el("span", {}, "Signature · from the cold signer"), el("textarea", { class: "mono", id: "sigtxt", rows: "3", placeholder: "" })),
      el("div", { class: "actions" }, el("button", { class: "btn primary", id: "run" }, "Verify and execute"), el("button", { class: "link quiet", id: "scansig" }, "Scan QR")),
      el("div", { id: "scanbox", class: "qr", style: "margin-top:14px" })),
    el("ul", { class: "steps hidden", id: "steps" }),
    el("div", { class: "err hidden", id: "werr" }));
  $("#mkreq", s).addEventListener("click", async () => {
    const err = $("#werr", s); err.classList.add("hidden");
    try {
      const slot = await rpc.getSlot("confirmed");
      const q = firstFreeLeaf(v); if (q === undefined) throw new Error("No one-time keys left on this vault.");
      const act = form.read();
      if (act.kind === "Close" && vaultTokens.length) throw new Error("This vault still holds tokens. Send them out first; a closed vault's token accounts are hard to reach.");
      const req: SignRequest = { v: 1, cluster: CLUSTER, vault: vaultAddr!.toBase58(), lmsPubkey: b64(v.lmsPubkey), nextQ: q, generation: v.generation, issuedSlot: String(slot), expirySlot: String(slot + 9000), action: act };
      ($("#reqtxt", s) as HTMLTextAreaElement).value = JSON.stringify(req); $("#reqout", s).classList.remove("hidden");
      $("#reqvalid", s).textContent = `Valid until about ${slotToDate(slot + 9000, slot).toLocaleTimeString()} (slot ${slot + 9000}).`;
    } catch (e) { err.textContent = String((e as Error).message ?? e); err.classList.remove("hidden"); }
  });
  $("#cpreq", s).addEventListener("click", (e) => copy(($("#reqtxt", s) as HTMLTextAreaElement).value, e.currentTarget as HTMLButtonElement));
  let stopQr: (() => void) | null = null;
  $("#qrreq", s).addEventListener("click", async () => { if (stopQr) { stopQr(); stopQr = null; return; } stopQr = await qr.show($("#qrbox", s), ($("#reqtxt", s) as HTMLTextAreaElement).value); });
  let scanning: { stop: () => void } | null = null;
  $("#scansig", s).addEventListener("click", () => {
    if (scanning) { scanning.stop(); scanning = null; return; }
    const sc = qr.scan($("#scanbox", s)); scanning = sc;
    sc.done.then((text) => { ($("#sigtxt", s) as HTMLTextAreaElement).value = text; scanning = null; }).catch(() => { scanning = null; });
  });
  $("#run", s).addEventListener("click", async () => {
    const err = $("#werr", s); err.classList.add("hidden");
    try {
      const blob = JSON.parse(($("#sigtxt", s) as HTMLTextAreaElement).value) as SignedBlob;
      if (blob.v !== 1 || blob.vault !== vaultAddr!.toBase58()) throw new Error("This signature belongs to another vault.");
      if ((blob.generation ?? 0) !== v.generation) throw new Error("This signature was made for an earlier key generation. Prepare a new request.");
      await stageAndExecute(toAction(blob.action, BigInt(blob.issuedSlot ?? blob.expirySlot), BigInt(blob.expirySlot)), unb64(blob.signature), blob.q, $("#steps", s), $("#run", s) as HTMLButtonElement);
    } catch (e) { err.textContent = String((e as Error).message ?? e); err.classList.remove("hidden"); }
  });
  return s;
}

function hotFlow(scope: Scope) {
  const v = vault!;
  const form = actionForm(scope);
  const s = el("div", {},
    el("div", { class: "notice warn" }, "The words stay in this browser tab until you close it. Fine for small amounts; use the offline signer for anything that matters."),
    hotKey ? el("div", { class: "actions", style: "margin:0 0 18px" }, el("span", { class: "ok", style: "margin:0" }, "Key loaded for this tab"), el("button", { class: "link quiet", id: "forget" }, "Forget it")) : el("div", {},
      el("label", { class: "field" }, el("span", {}, "24 words"), el("textarea", { class: "mono", id: "hwords", rows: "2", autocomplete: "off", spellcheck: "false" })),
      el("label", { class: "field" }, el("span", {}, "Passphrase, if any"), el("input", { class: "mono", id: "hpass", type: "password", autocomplete: "off" }))),
    form.node,
    el("div", { class: "actions" }, el("button", { class: "btn primary", id: "hrun" }, "Sign and execute")),
    el("ul", { class: "steps hidden", id: "steps" }),
    el("div", { class: "err hidden", id: "werr" }));
  $("#forget", s)?.addEventListener("click", () => { hotKey = null; render(); });
  $("#hrun", s).addEventListener("click", async () => {
    const err = $("#werr", s), btn = $("#hrun", s) as HTMLButtonElement; err.classList.add("hidden");
    try {
      if (!wallet) throw new Error("Connect a wallet to pay the fees.");
      if (!hotKey) {
        const words = ($("#hwords", s) as HTMLTextAreaElement).value.trim().toLowerCase().split(/\s+/).join(" ");
        if (!isValidMnemonic(words)) throw new Error("That is not a valid 24-word phrase.");
        btn.setAttribute("disabled", ""); btn.classList.add("spin");
        const found = await recoverKey(mnemonicToMaster(words, ($("#hpass", s) as HTMLInputElement).value), v.lmsPubkey, SCOPE, { onProgress: (d, t) => (btn.textContent = `Deriving ${Math.round((d / t) * 100)}%`) });
        if (!found) throw new Error("These words do not open this vault.");
        hotKey = found.key;
      }
      if (!equalBytes(hotKey.publicKey, v.lmsPubkey)) { hotKey = null; throw new Error("The loaded key does not belong to this vault. Enter the words again."); }
      const a = form.read();
      if (a.kind === "Close" && vaultTokens.length) throw new Error("This vault still holds tokens. Send them out first; a closed vault's token accounts are hard to reach.");
      const slot = await rpc.getSlot("confirmed");
      const until = slotToDate(slot + 1500, slot);
      if (!(await confirmPanel(s, describe(a), `Valid until about ${until.toLocaleTimeString()}. One one-time key will be spent.`))) return;
      const action = toAction(a, BigInt(slot), BigInt(slot + 1500));
      // never sign the same one-time key twice, even if the chain has not seen the first signature yet
      const journal = await openJournal();
      if (!journal) throw new Error("This browser gives no durable storage for the key journal; signing here is not safe.");
      const jk = keyFingerprint(v.lmsPubkey);
      const rec = await journal.get(jk);
      const minQ = rec ? rec.maxQ + 1 : 0;
      const q = firstFreeLeaf(v, 0, 1, (x) => x < minQ); if (q === undefined) throw new Error("No one-time keys left on this vault.");
      const leaves = 2 ** lmsParams(parseLmsPublicKey(v.lmsPubkey).lmsType).h;
      if (leaves - v.spent <= 1 && action.kind !== "Rotate") throw new Error("Last one-time key: only a rotation is allowed now.");
      if (!(await journal.reserve(jk, q, { vault: vaultAddr!.toBase58(), generation: v.generation }))) throw new Error(`One-time key ${q} is already recorded as used in this browser.`);
      const signature = hotKey.sign(q, vaultMessage(vaultAddr!, v.generation, encodeAction(action)));
      await stageAndExecute(action, signature, q, $("#steps", s), btn);
    } catch (e) { err.textContent = String((e as Error).message ?? e); err.classList.remove("hidden"); }
    finally { btn.removeAttribute("disabled"); btn.classList.remove("spin"); btn.textContent = "Sign and execute"; }
  });
  return s;
}

async function stageAndExecute(action: Action, signature: Uint8Array, q: number, steps: HTMLElement, btn: HTMLButtonElement) {
  if (!wallet) throw new Error("Connect a wallet to pay the fees.");
  if (isLeafUsed(vault!, q)) throw new Error(`One-time key ${q} is already spent. Sign again with a fresh one.`);
  let tokenProgram = TOKEN_PROGRAM_ID;
  const pre: { name: string; ixs: TransactionInstruction[] }[] = [];
  if (action.kind === "TransferToken") {
    const h = vaultTokens.find((t) => t.mint.equals(action.mint)); if (!h) throw new Error("The vault does not hold that token.");
    tokenProgram = h.tokenProgram;
    const info = await rpc.getAccountInfo(action.to, "confirmed");
    if (!info) {
      const owner = await ownerOfAta(action.to, h);
      if (!owner) throw new Error("The destination token account does not exist and cannot be created from here.");
      const d = await destinationTokenAccount(wallet.pubkey, owner, h.mint, h.tokenProgram);
      if (d.create) pre.push({ name: "Create destination token account", ixs: [d.create] });
    }
  }
  steps.innerHTML = ""; steps.classList.remove("hidden");
  const addStep = (n: string) => { const li = el("li", {}, el("span", {}, n)); steps.append(li); return li; };
  const run = async (li: HTMLElement, f: () => Promise<string>) => { li.classList.add("on"); const sig = await f(); li.classList.remove("on"); li.classList.add("done"); li.append(el("a", { href: EXPLORER(sig), target: "_blank", rel: "noopener" }, short(sig, 5))); return sig; };
  btn.setAttribute("disabled", ""); btn.classList.add("spin");
  const sigs: string[] = [];
  try {
    for (const p of pre) sigs.push(await run(addStep(p.name), () => wallet!.send(p.ixs)));
    // one 4 KB transaction when the wallet signs transaction v1; otherwise the staged buffer
    let done = false;
    if (wallet.sendV1) {
      const li = addStep("Verify and execute · one transaction");
      try {
        const { blockhash, lastValidBlockHeight } = await rpc.getLatestBlockhash("confirmed");
        const built = buildDirectV1Transaction({ programId: LAMPORT_VAULT_PROGRAM_ID, vault: vaultAddr!, payer: wallet.pubkey, action, signature, tokenProgram, blockhash, lastValidBlockHeight });
        sigs.push(await run(li, () => wallet!.sendV1!({ ...built, blockhash, lastValidBlockHeight })));
        done = true;
      } catch (e) { li.classList.remove("on"); li.append(el("span", { class: "mono", style: "margin-left:auto;font-size:11px;color:var(--mute)" }, "not accepted, using the buffer")); console.warn("v1 path", e); }
    }
    if (!done) {
      const staged = buildStagedExecution({ programId: LAMPORT_VAULT_PROGRAM_ID, vault: vaultAddr!, payer: wallet.pubkey, nonce: randomNonce(), action, signature, tokenProgram });
      const names = ["Open signature buffer", ...staged.writes.map((_, i) => `Write part ${i + 2} of ${staged.writes.length + 1}`), "Verify and execute"];
      for (let i = 0; i < staged.transactions.length; i++) sigs.push(await run(addStep(names[i]), () => wallet!.send(staged.transactions[i])));
    }
    hotKey = action.kind === "Rotate" || action.kind === "Close" ? null : hotKey;
    lastRun = { vault: vaultAddr!.toBase58(), q, kind: action.kind, sigs };
    await load();
  } finally { btn.removeAttribute("disabled"); btn.classList.remove("spin"); }
}

let lastTokenOwner: PublicKey | null = null;
async function ownerOfAta(ata: PublicKey, h: Holding): Promise<PublicKey | null> {
  if (lastTokenOwner && associatedTokenAddress(lastTokenOwner, h.mint, h.tokenProgram).equals(ata)) return lastTokenOwner;
  return null;
}

function registryPanel() {
  const s = el("div", {},
    el("p", { class: "quiet" }, "Bind a post-quantum key to your ordinary wallet address now. When Solana verifies such signatures natively, the record is proof of intent made before any attacker existed. First write wins; later changes need the committed key."),
    el("div", { id: "regbox" }, wallet ? el("button", { class: "btn", id: "regchk" }, "Check my address") : el("p", { class: "quiet" }, "Connect a wallet to continue.")));
  $("#regchk", s)?.addEventListener("click", async () => {
    const box = $("#regbox", s); box.innerHTML = ""; box.append(el("div", { class: "ok" }, "Checking…"));
    const pda = findCommitmentPda(PQ_REGISTRY_PROGRAM_ID, wallet!.pubkey).address;
    const info = await rpc.getAccountInfo(pda, "confirmed").catch(() => null);
    box.innerHTML = "";
    if (info) { const c = decodeCommitment(info.data); box.append(el("dl", { class: "spec", style: "margin-top:0" }, el("dt", {}, "Committed key"), el("dd", {}, short(b64(c.pqPubkey), 14)), el("dt", {}, "Generation"), el("dd", {}, String(c.generation ?? 0)))); return; }
    box.append(el("p", { class: "quiet" }, "No commitment for this address yet."),
      el("label", { class: "field" }, el("span", {}, "Post-quantum public key · base64"), el("input", { class: "mono", id: "regpk", value: b64(vault!.lmsPubkey) })),
      el("div", { class: "actions" }, el("button", { class: "btn primary", id: "regdo" }, "Commit"), el("span", { class: "quiet", style: "font-size:12.5px;color:var(--mute)" }, "prefilled with this vault's key")),
      el("div", { class: "err hidden", id: "regerr" }), el("div", { class: "ok hidden", id: "regok" }));
    $("#regdo", s).addEventListener("click", async () => {
      const err = $("#regerr", s), ok = $("#regok", s); err.classList.add("hidden");
      try {
        const pk = unb64(($("#regpk", s) as HTMLInputElement).value); parseLmsPublicKey(pk);
        const { instruction } = commitInstruction({ programId: PQ_REGISTRY_PROGRAM_ID, owner: wallet!.pubkey, payer: wallet!.pubkey, pqPubkey: pk });
        const sig = await wallet!.send([instruction]);
        ok.innerHTML = `Committed · <a href="${EXPLORER(sig)}" target="_blank" rel="noopener">${short(sig, 6)}</a>`; ok.classList.remove("hidden");
      } catch (e) { err.textContent = String((e as Error).message ?? e); err.classList.remove("hidden"); }
    });
  });
  return s;
}

// the hot key lives in this tab only: dropped when the tab is hidden for a while or closed
let hiddenAt = 0;
document.addEventListener("visibilitychange", () => {
  if (document.hidden) hiddenAt = Date.now();
  else if (hotKey && hiddenAt && Date.now() - hiddenAt > 5 * 60_000) { hotKey = null; render(); }
});
addEventListener("pagehide", () => { hotKey = null; });
