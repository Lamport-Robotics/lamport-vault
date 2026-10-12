/**
 * cold signer. one file, no network. paste the request the vault page gave you, type the words,
 * get a signature back. the words never leave this page; close the tab when done.
 */
import "./polyfill.ts";
import "./style.css";
import { PublicKey } from "@solana/web3.js";
import { LmsPrivateKey, isValidMnemonic, mnemonicToMaster, recoverKey, parseLmsPublicKey, deriveKeyMaterial } from "@lamport-robotics/lms";
import { encodeAction, vaultMessage, type Action } from "@lamport-robotics/vault";
import { $, b64, el, short, unb64, copy, type SignRequest, type SignedBlob } from "./common.ts";
import * as qr from "./qr.ts";

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

let req: SignRequest | null = null;
$("#req").addEventListener("input", () => {
  const v = $("#reqview"); v.innerHTML = ""; req = null;
  try {
    const r = JSON.parse(($("#req") as HTMLTextAreaElement).value) as SignRequest;
    if (r.v !== 1 || !r.vault || !r.action) throw new Error("not a sign request");
    req = r;
    const a = r.action;
    const line = a.kind === "TransferSol" ? `send ${(Number(a.lamports) / 1e9).toLocaleString("en-US", { maximumFractionDigits: 9 })} SOL to ${a.to}`
      : a.kind === "TransferToken" ? `send ${a.decimals != null ? (Number(a.amount) / 10 ** a.decimals).toLocaleString("en-US", { maximumFractionDigits: a.decimals }) : a.amount + " base units"} of token ${short(a.mint, 6)} to token account ${a.to}`
      : a.kind === "Rotate" ? `rotate the vault key to ${short(a.newLmsPubkey, 10)}` : `close the vault, everything to ${a.to}`;
    v.append(el("dl", { class: "spec", style: "margin-top:4px" },
      el("dt", {}, "vault"), el("dd", {}, r.vault),
      el("dt", {}, "action"), el("dd", {}, line),
      el("dt", {}, "leaf q"), el("dd", {}, String(r.nextQ)),
      el("dt", {}, "key generation"), el("dd", {}, String(r.generation ?? 0)),
      el("dt", {}, "valid until slot"), el("dd", {}, r.expirySlot),
      el("dt", {}, "cluster"), el("dd", {}, r.cluster)));
  } catch (e) { v.append(el("div", { class: "err" }, String((e as Error).message))); }
});

$("#sign").addEventListener("click", async () => {
  const err = $("#err"); err.classList.add("hidden");
  const btn = $("#sign") as HTMLButtonElement;
  try {
    if (!req) throw new Error("paste the request first");
    const words = ($("#words") as HTMLTextAreaElement).value.trim().toLowerCase().split(/\s+/).join(" ");
    if (!isValidMnemonic(words)) throw new Error("that is not a valid 24-word phrase");
    btn.disabled = true; btn.classList.add("spin"); btn.textContent = "deriving key";
    const master = mnemonicToMaster(words, ($("#pass") as HTMLInputElement).value);
    const pub = unb64(req.lmsPubkey);
    const found = await recoverKey(master, pub, { onProgress: (d, t) => (btn.textContent = `deriving key ${Math.round((d / t) * 100)}%`) });
    if (!found) throw new Error("these words do not open this vault (checked k = 0…64)");
    const action = toAction(req);
    const message = vaultMessage(new PublicKey(req.vault), req.generation ?? 0, encodeAction(action));
    const signature = found.key.sign(req.nextQ, message);
    const blob: SignedBlob = { v: 1, vault: req.vault, q: req.nextQ, generation: req.generation ?? 0, action: req.action, expirySlot: req.expirySlot, signature: b64(signature) };
    ($("#sig") as HTMLTextAreaElement).value = JSON.stringify(blob);
    $("#out").classList.remove("hidden");
    ($("#words") as HTMLTextAreaElement).value = ""; ($("#pass") as HTMLInputElement).value = "";
    $("#out").scrollIntoView({ behavior: "smooth" });
  } catch (e) { err.textContent = String((e as Error).message ?? e); err.classList.remove("hidden"); }
  finally { btn.disabled = false; btn.classList.remove("spin"); btn.textContent = "Sign"; }
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
  a.download = `lamport-vault-signature-q${req?.nextQ ?? 0}.json`; a.click();
});

function toAction(r: SignRequest): Action {
  const expirySlot = BigInt(r.expirySlot);
  const a = r.action;
  if (a.kind === "TransferSol") return { kind: "TransferSol", to: new PublicKey(a.to), lamports: BigInt(a.lamports), expirySlot };
  if (a.kind === "TransferToken") return { kind: "TransferToken", mint: new PublicKey(a.mint), to: new PublicKey(a.to), amount: BigInt(a.amount), expirySlot };
  if (a.kind === "Rotate") { const k = unb64(a.newLmsPubkey); parseLmsPublicKey(k); return { kind: "Rotate", newLmsPubkey: k, expirySlot }; }
  return { kind: "Close", to: new PublicKey(a.to), expirySlot };
}

// keep the key-derivation code path warm so the first sign is not a cold import
void LmsPrivateKey; void deriveKeyMaterial;
