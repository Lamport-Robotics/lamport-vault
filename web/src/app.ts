import "./polyfill.ts";
import "./style.css";
import { PublicKey, SystemProgram, type TransactionInstruction } from "@solana/web3.js";
import { LmsPrivateKey, generateMnemonic, isValidMnemonic, mnemonicToMaster, deriveKeyMaterial, recoverKey, parseLmsPublicKey, lmsParams, LMS_SHA256_M32_H10 } from "@lamport-robotics/lms";
import { LAMPORT_VAULT_PROGRAM_ID, PQ_REGISTRY_PROGRAM_ID, buildStagedExecution, createVaultInstruction, decodeVault, decodeCommitment, findCommitmentPda, findVaultPdaForKey, commitInstruction, encodeAction, vaultMessage, randomNonce, type Action, type VaultAccount } from "@lamport-robotics/vault";
import { $, CLUSTER, EXPLORER, EXPLORER_ADDR, b64, copy, el, isPubkey, rpc, short, sol, unb64, type SignRequest, type SignedBlob } from "./common.ts";
import { connectStandard, listWallets, localWallet, onWalletsChange, remember, remembered, type Wallet } from "./wallet.ts";
import * as qr from "./qr.ts";
import { holdings, destinationTokenAccount, toBase, type Holding } from "./tokens.ts";
import { TOKEN_PROGRAM_ID, associatedTokenAddress } from "@lamport-robotics/vault";
import { tape } from "./tape.ts";

// ── state ──
let wallet: Wallet | null = null;
let vaultAddr: PublicKey | null = null;
let vault: VaultAccount | null = null;
let vaultLamports = 0;
let vaultTokens: Holding[] = [];
let hotKey: LmsPrivateKey | null = null;   // only while the owner chose hot mode in this tab
let lastRun: { vault: string; q: number; kind: string; sigs: string[] } | null = null;

const app = $("#app");
const hdr = el("header", {},
  el("a", { class: "brand", href: "/" }, el("img", { src: "/mark.svg", alt: "" }), el("b", {}, "Lamport Vault"), el("small", {}, CLUSTER)),
  el("div", { class: "right", id: "walletbox" }));
const main = el("div", { id: "main" });
app.append(hdr, main, el("footer", {},
  el("a", { href: "https://github.com/Lamport-Robotics/lamport-vault" }, "source"),
  el("a", { href: "/signer.html", download: "lamport-vault-signer.html" }, "download cold signer"),
  el("a", { href: "https://lamportrobotics.com" }, "lamport robotics")));

// ── wallet box ──
function paintWallet() {
  const box = $("#walletbox"); box.innerHTML = "";
  if (wallet) {
    box.append(el("span", { class: "mono", style: "font-size:12px;color:var(--mute)" }, short(wallet.pubkey.toBase58())),
      el("button", { class: "small ghost", id: "disc" }, "disconnect"));
    $("#disc").addEventListener("click", async () => { await wallet?.disconnect(); wallet = null; remember(null); paintWallet(); render(); });
    return;
  }
  const ws = listWallets();
  const sel = el("select", { id: "wsel" });
  for (const w of ws) sel.append(el("option", { value: w.name }, w.name));
  if (location.hostname === "localhost" || location.hostname === "127.0.0.1") sel.append(el("option", { value: "__local" }, "local test key"));
  if (!sel.options.length) { box.append(el("span", { class: "mono", style: "font-size:12px;color:var(--mute)" }, "no solana wallet found")); return; }
  const btn = el("button", { class: "small" }, "connect");
  btn.addEventListener("click", async () => {
    try {
      const v = (sel as HTMLSelectElement).value;
      wallet = v === "__local" ? localWallet() : await connectStandard(ws.find((w) => w.name === v)!);
      remember(v); paintWallet(); render();
    } catch (e) { alert(String((e as Error).message ?? e)); }
  });
  box.append(sel, btn);
}
onWalletsChange(paintWallet);
paintWallet();
// come back to the wallet used last time, without a prompt
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
  vaultAddr = isPubkey(h) ? new PublicKey(h) : null;
  vault = null; vaultLamports = 0;
  if (vaultAddr) {
    const info = await rpc.getAccountInfo(vaultAddr, "confirmed").catch(() => null);
    if (info && info.owner.equals(LAMPORT_VAULT_PROGRAM_ID)) {
      vault = decodeVault(info.data); vaultLamports = info.lamports;
      try { vaultTokens = await holdings(vaultAddr); } catch (e) { console.error("holdings", e); vaultTokens = []; }
    }
  }
  render();
}

// ── views ──
function render() {
  main.innerHTML = "";
  if (!vaultAddr) return main.append(home());
  if (!vault) return main.append(notFound());
  main.append(vaultView());
}

function home() {
  const s = el("div", {});
  s.append(el("section", {},
    el("h1", {}, "Your funds move only on a hash-based signature."),
    el("p", {}, "A Lamport Vault is a Solana account that only a post-quantum (LMS, SHA-256) signature can spend from. Deposit from any wallet. Withdraw by signing offline with your 24 words."),
    el("label", {}, "open a vault"),
    el("div", { class: "row" }, el("input", { class: "mono", id: "open", placeholder: "vault address", autocomplete: "off", spellcheck: "false" }), el("button", { id: "go" }, "Open")),
  ));
  const make = el("section", {},
    el("div", { class: "label" }, el("span", {}, "or create one")),
    el("p", {}, "You get 24 words. They are the vault. Write them down; nothing here stores them."),
    el("div", { class: "row" }, el("button", { class: "primary", id: "new" }, "New vault")),
    el("div", { id: "newbox" }));
  s.append(make);
  s.append(el("section", {},
    el("div", { class: "label" }, el("span", {}, "how it works")),
    el("dl", { class: "kv" },
      el("dt", {}, "deposit"), el("dd", {}, "any wallet, plain transfer to the vault address"),
      el("dt", {}, "withdraw"), el("dd", {}, "sign the action with one leaf of the key, offline if you like; the page stages the 2.5 KB signature and runs execute"),
      el("dt", {}, "keys"), el("dd", {}, "1024 one-time leaves per key (H10); the chain tracks which are spent; the last one is reserved for rotating to a new key"),
      el("dt", {}, "trust"), el("dd", {}, "no admin, no fee switch; verify the program against the source"))));
  $("#go", s).addEventListener("click", () => { const v = ($("#open", s) as HTMLInputElement).value.trim(); if (isPubkey(v)) location.hash = v; });
  $("#open", s).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") $("#go", s).click(); });
  $("#new", s).addEventListener("click", () => newVault($("#newbox", s)));
  return s;
}

function notFound() {
  return el("section", {}, el("h2", {}, "No vault here"), el("p", {}, `${vaultAddr?.toBase58()} is not a Lamport Vault on ${CLUSTER}.`), el("button", { id: "back" }, "Back"))
    .also((n) => $("#back", n).addEventListener("click", () => (location.hash = "")));
}

async function newVault(box: HTMLElement) {
  box.innerHTML = "";
  if (!wallet) { box.append(el("div", { class: "note warn" }, "Connect the wallet that will pay for the vault account first.")); return; }
  const words = generateMnemonic();
  const grid = el("div", { class: "words" });
  words.split(" ").forEach((w, i) => grid.append(el("div", {}, el("span", {}, String(i + 1).padStart(2, "0")), w)));
  const prog = el("div", { class: "ok" }, "deriving key…");
  const btn = el("button", { class: "primary", id: "mk", disabled: "" }, "I wrote them down. Create the vault");
  box.append(el("p", { class: "note warn" }, "These 24 words are the only way to spend from the vault. Paper or metal. Not a screenshot."), grid, prog, el("div", { class: "row" }, btn), el("div", { class: "err hidden", id: "mkerr" }));
  const key = await LmsPrivateKey.generateAsync(deriveKeyMaterial(mnemonicToMaster(words), 0, LMS_SHA256_M32_H10), { onProgress: (d, t) => (prog.textContent = `deriving key ${Math.round((d / t) * 100)}%`) });
  prog.textContent = `vault address ${findVaultPdaForKey(LAMPORT_VAULT_PROGRAM_ID, key.publicKey).address.toBase58()}`;
  btn.removeAttribute("disabled");
  btn.addEventListener("click", async () => {
    try {
      btn.setAttribute("disabled", ""); btn.classList.add("spin");
      const { instruction, vault: v } = createVaultInstruction({ programId: LAMPORT_VAULT_PROGRAM_ID, payer: wallet!.pubkey, lmsPubkey: key.publicKey });
      await wallet!.send([instruction]);
      hotKey = null; location.hash = v.toBase58();
    } catch (e) { $("#mkerr", box).textContent = String((e as Error).message ?? e); $("#mkerr", box).classList.remove("hidden"); btn.removeAttribute("disabled"); btn.classList.remove("spin"); }
  });
}

function vaultView() {
  const v = vault!, addr = vaultAddr!.toBase58();
  const pub = parseLmsPublicKey(v.lmsPubkey);
  const h = lmsParams(pub.lmsType).h;
  const leaves = 2 ** h;
  const s = el("div", {});
  const head = el("section", {},
    el("div", { class: "label" }, el("span", {}, "vault"), el("a", { href: EXPLORER_ADDR(addr), target: "_blank", rel: "noopener" }, "explorer")),
    el("div", { class: "copy" }, el("span", { class: "addr" }, addr), el("button", { class: "small ghost", id: "cp" }, "copy")),
    el("div", { class: "big", style: "margin-top:16px" }, sol(vaultLamports), el("small", {}, "SOL")),
    vaultTokens.length ? el("div", { class: "kv", style: "margin-top:10px" }, ...vaultTokens.flatMap((t) => [el("dt", {}, short(t.mint.toBase58(), 4)), el("dd", {}, `${t.ui}`)])) : null,
    tape(leaves, v.nextQ),
    el("dl", { class: "kv", style: "margin-top:16px" },
      el("dt", {}, "key"), el("dd", {}, `LMS H${h} / W4 · rotated ${v.rotations}×`),
      el("dt", {}, "lms pubkey"), el("dd", {}, short(b64(v.lmsPubkey), 12))));
  $("#cp", head).addEventListener("click", (e) => copy(addr, e.currentTarget as HTMLButtonElement));
  s.append(head, depositSection(), withdrawSection(), registrySection());
  return s;
}

function depositSection() {
  const s = el("section", {}, el("div", { class: "label" }, el("span", {}, "01 — deposit"), el("span", {}, wallet ? wallet.name : "connect a wallet")));
  s.append(el("div", { class: "row" }, el("input", { class: "mono", id: "amt", placeholder: "amount in SOL", inputmode: "decimal" }), el("button", { id: "dep", class: "primary" }, "Deposit")),
    el("p", { style: "margin-top:10px;font-size:13px" }, "Plain transfer. Any wallet or exchange can send here; the address never changes."),
    el("div", { class: "err hidden", id: "deperr" }), el("div", { class: "ok hidden", id: "depok" }));
  $("#dep", s).addEventListener("click", async () => {
    const err = $("#deperr", s), ok = $("#depok", s); err.classList.add("hidden"); ok.classList.add("hidden");
    try {
      if (!wallet) throw new Error("connect a wallet first");
      const n = Number(($("#amt", s) as HTMLInputElement).value);
      if (!(n > 0)) throw new Error("amount?");
      const sig = await wallet.send([SystemProgram.transfer({ fromPubkey: wallet.pubkey, toPubkey: vaultAddr!, lamports: Math.round(n * 1e9) })]);
      ok.innerHTML = `deposited · <a href="${EXPLORER(sig)}" target="_blank" rel="noopener">${short(sig, 6)}</a>`; ok.classList.remove("hidden");
      await load();
    } catch (e) { err.textContent = String((e as Error).message ?? e); err.classList.remove("hidden"); }
  });
  return s;
}

type Mode = "cold" | "hot";
let mode: Mode = "cold";

function withdrawSection() {
  const v = vault!;
  const s = el("section", {}, el("div", { class: "label" }, el("span", {}, "02 — withdraw"), el("span", {}, `next q ${v.nextQ}`)));
  if (lastRun && lastRun.vault === vaultAddr!.toBase58()) {
    const r = lastRun;
    s.append(el("div", { class: "ok", style: "margin:0 0 18px" }, `${r.kind} done with leaf ${r.q} · `, el("a", { href: EXPLORER(r.sigs[r.sigs.length - 1]), target: "_blank", rel: "noopener" }, "execute " + short(r.sigs[r.sigs.length - 1], 6))));
  }
  const tabs = el("div", { class: "tabs" }, el("button", { "data-m": "cold" }, "offline signer"), el("button", { "data-m": "hot" }, "words in this tab"));
  const body = el("div", {});
  s.append(tabs, body);
  const paint = () => {
    tabs.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.m === mode));
    body.innerHTML = ""; body.append(mode === "cold" ? coldFlow() : hotFlow());
  };
  tabs.addEventListener("click", (e) => { const b = (e.target as HTMLElement).closest("button"); if (b) { mode = b.dataset.m as Mode; paint(); } });
  paint();
  return s;
}

function actionForm(): { node: HTMLElement; read: () => SignRequest["action"] } {
  const kind = el("select", { id: "kind" }, el("option", { value: "TransferSol" }, "send SOL"), ...(vaultTokens.length ? [el("option", { value: "TransferToken" }, "send a token")] : []), el("option", { value: "Rotate" }, "rotate to a new key"), el("option", { value: "Close" }, "close the vault"));
  const mint = el("select", { id: "mint" }, ...vaultTokens.map((t) => el("option", { value: t.mint.toBase58() }, `${short(t.mint.toBase58(), 4)} · ${t.ui}`)));
  const to = el("input", { class: "mono", id: "to", placeholder: "destination address", autocomplete: "off", spellcheck: "false" });
  const amt = el("input", { class: "mono", id: "wamt", placeholder: "amount in SOL", inputmode: "decimal" });
  const rot = el("input", { class: "mono", id: "rot", placeholder: "new lms pubkey (base64, 56 bytes)", autocomplete: "off", spellcheck: "false" });
  const node = el("div", { class: "grid2" }, el("div", {}, el("label", {}, "action"), kind), el("div", { id: "f-to" }, el("label", {}, "to"), to), el("div", { id: "f-amt" }, el("label", {}, "amount"), amt), el("div", { id: "f-rot", class: "hidden" }, el("label", {}, "new key"), rot), el("div", { id: "f-mint", class: "hidden" }, el("label", {}, "token"), mint));
  const sync = () => { const k = (kind as HTMLSelectElement).value; $("#f-to", node).classList.toggle("hidden", k === "Rotate"); $("#f-amt", node).classList.toggle("hidden", k !== "TransferSol" && k !== "TransferToken"); $("#f-rot", node).classList.toggle("hidden", k !== "Rotate"); $("#f-mint", node).classList.toggle("hidden", k !== "TransferToken"); amt.placeholder = k === "TransferToken" ? "amount" : "amount in SOL"; };
  kind.addEventListener("change", sync);
  const read = (): SignRequest["action"] => {
    const k = (kind as HTMLSelectElement).value;
    if (k === "TransferSol") { if (!isPubkey(to.value)) throw new Error("destination?"); const n = Number(amt.value); if (!(n > 0)) throw new Error("amount?"); return { kind: "TransferSol", to: to.value.trim(), lamports: String(Math.round(n * 1e9)) }; }
    if (k === "TransferToken") {
      const h = vaultTokens.find((t) => t.mint.toBase58() === (mint as HTMLSelectElement).value); if (!h) throw new Error("token?");
      if (!isPubkey(to.value)) throw new Error("destination?");
      const amount = toBase(amt.value, h.decimals); if (amount <= 0n || amount > h.amount) throw new Error("amount?");
      // the action names the receiver's token account; it is created before execute if it does not exist
      lastTokenOwner = new PublicKey(to.value.trim());
      const ata = associatedTokenAddress(lastTokenOwner, h.mint, h.tokenProgram);
      return { kind: "TransferToken", mint: h.mint.toBase58(), to: ata.toBase58(), amount: amount.toString(), tokenProgram: h.tokenProgram.toBase58(), decimals: h.decimals };
    }
    if (k === "Rotate") { const b = unb64(rot.value); parseLmsPublicKey(b); return { kind: "Rotate", newLmsPubkey: b64(b) }; }
    if (!isPubkey(to.value)) throw new Error("destination?"); return { kind: "Close", to: to.value.trim() };
  };
  return { node, read };
}

function toAction(a: SignRequest["action"], expirySlot: bigint): Action {
  if (a.kind === "TransferSol") return { kind: "TransferSol", to: new PublicKey(a.to), lamports: BigInt(a.lamports), expirySlot };
  if (a.kind === "TransferToken") return { kind: "TransferToken", mint: new PublicKey(a.mint), to: new PublicKey(a.to), amount: BigInt(a.amount), expirySlot };
  if (a.kind === "Rotate") return { kind: "Rotate", newLmsPubkey: unb64(a.newLmsPubkey), expirySlot };
  return { kind: "Close", to: new PublicKey(a.to), expirySlot };
}

function coldFlow() {
  const v = vault!;
  const form = actionForm();
  const s = el("div", {}, form.node,
    el("div", { class: "row", style: "margin-top:16px" }, el("button", { id: "mkreq" }, "Make request")),
    el("div", { id: "reqout", class: "hidden" },
      el("label", {}, "request — paste into the cold signer"),
      el("textarea", { class: "mono", id: "reqtxt", rows: "4", readonly: "" }),
      el("div", { class: "row", style: "margin-top:8px" }, el("button", { class: "small", id: "cpreq" }, "copy"), el("button", { class: "small", id: "qrreq" }, "show as QR"), el("a", { class: "small", href: "/signer.html", download: "lamport-vault-signer.html", style: "align-self:center;font-size:13px" }, "download the signer")),
      el("div", { id: "qrbox", style: "margin-top:10px" }),
      el("p", { class: "note" }, "Open the signer on an offline machine, paste the request, type the words. It gives you a signature; bring it back below. The request is valid for about an hour.")),
    el("div", { class: "row", style: "align-items:center;margin-top:14px" }, el("label", { style: "margin:0" }, "signature from the cold signer"), el("button", { class: "small ghost", id: "scansig" }, "scan QR")),
    el("div", { id: "scanbox" }),
    el("textarea", { class: "mono", id: "sigtxt", rows: "4", placeholder: '{"v":1,"vault":"…","q":…,"signature":"…"}' }),
    el("div", { class: "row", style: "margin-top:10px" }, el("button", { class: "primary", id: "run" }, "Stage and execute")),
    el("ul", { class: "steps hidden", id: "steps" }),
    el("div", { class: "err hidden", id: "werr" }));
  $("#mkreq", s).addEventListener("click", async () => {
    const err = $("#werr", s); err.classList.add("hidden");
    try {
      const slot = await rpc.getSlot("confirmed");
      const req: SignRequest = { v: 1, cluster: CLUSTER, vault: vaultAddr!.toBase58(), lmsPubkey: b64(v.lmsPubkey), nextQ: v.nextQ, expirySlot: String(slot + 9000), action: form.read() };
      ($("#reqtxt", s) as HTMLTextAreaElement).value = JSON.stringify(req); $("#reqout", s).classList.remove("hidden");
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
      if (blob.v !== 1 || blob.vault !== vaultAddr!.toBase58()) throw new Error("this signature is for another vault");
      await stageAndExecute(toAction(blob.action, BigInt(blob.expirySlot)), unb64(blob.signature), blob.q, $("#steps", s), $("#run", s) as HTMLButtonElement);
    } catch (e) { err.textContent = String((e as Error).message ?? e); err.classList.remove("hidden"); }
  });
  return s;
}

function hotFlow() {
  const v = vault!;
  const form = actionForm();
  const s = el("div", {},
    el("p", { class: "note warn" }, "Hot mode: the words are in this browser tab until you close it. Fine for small amounts; use the offline signer for anything that matters."),
    hotKey ? el("div", { class: "ok" }, "key loaded for this tab") : el("div", {}, el("label", {}, "24 words"), el("textarea", { class: "mono", id: "hwords", rows: "3", autocomplete: "off", spellcheck: "false" }), el("label", {}, "passphrase (if any)"), el("input", { class: "mono", id: "hpass", type: "password", autocomplete: "off" })),
    el("div", { style: "margin-top:18px" }, form.node),
    el("div", { class: "row", style: "margin-top:16px" }, el("button", { class: "primary", id: "hrun" }, "Sign and execute")),
    el("ul", { class: "steps hidden", id: "steps" }),
    el("div", { class: "err hidden", id: "werr" }));
  $("#hrun", s).addEventListener("click", async () => {
    const err = $("#werr", s), btn = $("#hrun", s) as HTMLButtonElement; err.classList.add("hidden");
    try {
      if (!wallet) throw new Error("connect a wallet to pay the fees");
      if (!hotKey) {
        const words = ($("#hwords", s) as HTMLTextAreaElement).value.trim().toLowerCase().split(/\s+/).join(" ");
        if (!isValidMnemonic(words)) throw new Error("that is not a valid 24-word phrase");
        btn.setAttribute("disabled", ""); btn.classList.add("spin");
        const found = await recoverKey(mnemonicToMaster(words, ($("#hpass", s) as HTMLInputElement).value), v.lmsPubkey, { onProgress: (d, t) => (btn.textContent = `deriving ${Math.round((d / t) * 100)}%`) });
        if (!found) throw new Error("these words do not open this vault");
        hotKey = found.key;
      }
      const a = form.read();
      const slot = await rpc.getSlot("confirmed");
      const action = toAction(a, BigInt(slot + 1500));
      const q = v.nextQ;
      if (q >= 2 ** lmsParams(parseLmsPublicKey(v.lmsPubkey).lmsType).h - 1 && action.kind !== "Rotate") throw new Error("last leaf: only Rotate is allowed now");
      const signature = hotKey.sign(q, vaultMessage(vaultAddr!, encodeAction(action)));
      await stageAndExecute(action, signature, q, $("#steps", s), btn);
    } catch (e) { err.textContent = String((e as Error).message ?? e); err.classList.remove("hidden"); }
    finally { btn.removeAttribute("disabled"); btn.classList.remove("spin"); btn.textContent = "Sign and execute"; }
  });
  return s;
}

async function stageAndExecute(action: Action, signature: Uint8Array, q: number, steps: HTMLElement, btn: HTMLButtonElement) {
  if (!wallet) throw new Error("connect a wallet to pay the fees");
  if (q < vault!.nextQ) throw new Error(`leaf ${q} is already spent (next is ${vault!.nextQ}); sign again with the current q`);
  // token transfers: the receiver's token account must exist; the payer creates it first if needed
  let tokenProgram = TOKEN_PROGRAM_ID;
  const pre: { name: string; ixs: TransactionInstruction[] }[] = [];
  if (action.kind === "TransferToken") {
    const h = vaultTokens.find((t) => t.mint.equals(action.mint)); if (!h) throw new Error("the vault does not hold that token");
    tokenProgram = h.tokenProgram;
    const info = await rpc.getAccountInfo(action.to, "confirmed");
    if (!info) {
      const owner = await ownerOfAta(action.to, h);
      if (!owner) throw new Error("destination token account does not exist and is not an associated token account I can create");
      const d = await destinationTokenAccount(wallet.pubkey, owner, h.mint, h.tokenProgram);
      if (d.create) pre.push({ name: "create destination token account", ixs: [d.create] });
    }
  }
  const staged = buildStagedExecution({ programId: LAMPORT_VAULT_PROGRAM_ID, vault: vaultAddr!, payer: wallet.pubkey, nonce: randomNonce(), action, signature, tokenProgram });
  const names = [...pre.map((p) => p.name), "open buffer", ...staged.writes.map((_, i) => `write chunk ${i + 1}`), "execute"];
  const txs = [...pre.map((p) => p.ixs), ...staged.transactions];
  steps.innerHTML = ""; steps.classList.remove("hidden");
  const items = names.map((n) => { const li = el("li", {}, el("span", {}, n)); steps.append(li); return li; });
  btn.setAttribute("disabled", ""); btn.classList.add("spin");
  const sigs: string[] = [];
  try {
    for (let i = 0; i < txs.length; i++) {
      items[i].classList.add("on");
      const sig = await wallet.send(txs[i]);
      sigs.push(sig);
      items[i].classList.remove("on"); items[i].classList.add("done");
      items[i].append(el("a", { href: EXPLORER(sig), target: "_blank", rel: "noopener" }, short(sig, 6)));
    }
    hotKey = action.kind === "Rotate" || action.kind === "Close" ? null : hotKey;
    lastRun = { vault: vaultAddr!.toBase58(), q, kind: action.kind, sigs };
    await load();
  } finally { btn.removeAttribute("disabled"); btn.classList.remove("spin"); }
}

/** which owner an associated token account belongs to, if `ata` is one: ask the form's destination first, else give up */
let lastTokenOwner: PublicKey | null = null;
async function ownerOfAta(ata: PublicKey, h: Holding): Promise<PublicKey | null> {
  if (lastTokenOwner && associatedTokenAddress(lastTokenOwner, h.mint, h.tokenProgram).equals(ata)) return lastTokenOwner;
  return null;
}

function registrySection() {
  const s = el("section", {}, el("div", { class: "label" }, el("span", {}, "03 — registry"), el("span", {}, "optional")),
    el("p", {}, "Bind a post-quantum key to your ordinary wallet address now. When Solana verifies such signatures natively, the record is proof of intent made before the attacker existed. First write wins."),
    el("div", { id: "regbox" }, wallet ? el("button", { id: "regchk" }, "Check my address") : el("span", { class: "mono", style: "font-size:12px;color:var(--mute)" }, "connect a wallet")));
  $("#regchk", s)?.addEventListener("click", async () => {
    const box = $("#regbox", s); box.innerHTML = "checking…";
    const pda = findCommitmentPda(PQ_REGISTRY_PROGRAM_ID, wallet!.pubkey).address;
    const info = await rpc.getAccountInfo(pda, "confirmed").catch(() => null);
    box.innerHTML = "";
    if (info) { const c = decodeCommitment(info.data); box.append(el("dl", { class: "kv" }, el("dt", {}, "committed"), el("dd", {}, short(b64(c.pqPubkey), 12)), el("dt", {}, "next q"), el("dd", {}, String(c.nextQ)))); return; }
    box.append(el("p", { class: "ink" }, "No commitment yet."),
      el("label", {}, "pq public key (base64, 56 bytes) — from the cold signer's registry key, or use this vault's key"),
      el("div", { class: "row" }, el("input", { class: "mono", id: "regpk", value: b64(vault!.lmsPubkey) }), el("button", { class: "primary", id: "regdo" }, "Commit")),
      el("div", { class: "err hidden", id: "regerr" }), el("div", { class: "ok hidden", id: "regok" }));
    $("#regdo", s).addEventListener("click", async () => {
      const err = $("#regerr", s), ok = $("#regok", s); err.classList.add("hidden");
      try {
        const pk = unb64(($("#regpk", s) as HTMLInputElement).value); parseLmsPublicKey(pk);
        const { instruction } = commitInstruction({ programId: PQ_REGISTRY_PROGRAM_ID, owner: wallet!.pubkey, payer: wallet!.pubkey, pqPubkey: pk });
        const sig = await wallet!.send([instruction]);
        ok.innerHTML = `committed · <a href="${EXPLORER(sig)}" target="_blank" rel="noopener">${short(sig, 6)}</a>`; ok.classList.remove("hidden");
      } catch (e) { err.textContent = String((e as Error).message ?? e); err.classList.remove("hidden"); }
    });
  });
  return s;
}

declare global { interface HTMLElement { also(f: (n: this) => void): this } }
HTMLElement.prototype.also = function (f) { f(this); return this; };
