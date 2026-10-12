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

const app = $("#app");
app.append(
  el("header", {}, el("a", { class: "brand", href: "#" }, el("b", {}, "Lamport Vault"), el("small", {}, "cold signer")), el("span", { class: "offline-pill", id: "net" }, "…")),
  el("section", {},
    el("div", { class: "label" }, el("span", {}, "01 — request"), el("span", {}, "from the vault page")),
    el("textarea", { class: "mono", id: "req", rows: "6", placeholder: '{"v":1,"vault":"…","action":{…}}' }),
    el("div", { id: "reqview" }),
  ),
  el("section", {},
    el("div", { class: "label" }, el("span", {}, "02 — words")),
    el("textarea", { class: "mono", id: "words", rows: "3", placeholder: "24 words", autocomplete: "off", spellcheck: "false" }),
    el("label", {}, "passphrase (if you set one)"),
    el("input", { class: "mono", id: "pass", type: "password", autocomplete: "off" }),
    el("div", { class: "row", style: "margin-top:16px" }, el("button", { class: "primary", id: "sign" }, "Sign")),
    el("div", { class: "err hidden", id: "err" }),
  ),
  el("section", { id: "out", class: "hidden" },
    el("div", { class: "label" }, el("span", {}, "03 — signature"), el("span", {}, "take this back to the vault page")),
    el("textarea", { class: "mono", id: "sig", rows: "6", readonly: "" }),
    el("div", { class: "row", style: "margin-top:10px" }, el("button", { id: "copy", class: "small" }, "copy"), el("button", { id: "dl", class: "small" }, "download .json")),
    el("p", { class: "note warn" }, "One leaf is now spent. If this signature is lost, the next one must use a higher q; the vault page reads it from the chain."),
  ),
  el("footer", {}, el("span", {}, "nothing here talks to the network"), el("span", {}, "lamportrobotics.com")),
);

const net = $("#net");
const paintNet = () => { const on = navigator.onLine; net.textContent = on ? "online — go offline before typing words" : "offline"; net.className = `offline-pill ${on ? "on" : "off"}`; };
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
      : a.kind === "Rotate" ? `rotate the vault key to ${short(a.newLmsPubkey, 10)}` : `close the vault, everything to ${a.to}`;
    v.append(el("dl", { class: "kv", style: "margin-top:14px" },
      el("dt", {}, "vault"), el("dd", {}, r.vault),
      el("dt", {}, "action"), el("dd", {}, line),
      el("dt", {}, "leaf q"), el("dd", {}, String(r.nextQ)),
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
    const message = vaultMessage(new PublicKey(req.vault), encodeAction(action));
    const signature = found.key.sign(req.nextQ, message);
    const blob: SignedBlob = { v: 1, vault: req.vault, q: req.nextQ, action: req.action, expirySlot: req.expirySlot, signature: b64(signature) };
    ($("#sig") as HTMLTextAreaElement).value = JSON.stringify(blob);
    $("#out").classList.remove("hidden");
    ($("#words") as HTMLTextAreaElement).value = ""; ($("#pass") as HTMLInputElement).value = "";
    $("#out").scrollIntoView({ behavior: "smooth" });
  } catch (e) { err.textContent = String((e as Error).message ?? e); err.classList.remove("hidden"); }
  finally { btn.disabled = false; btn.classList.remove("spin"); btn.textContent = "Sign"; }
});
$("#copy").addEventListener("click", (e) => copy(($("#sig") as HTMLTextAreaElement).value, e.currentTarget as HTMLButtonElement));
$("#dl").addEventListener("click", () => {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([($("#sig") as HTMLTextAreaElement).value], { type: "application/json" }));
  a.download = `lamport-vault-signature-q${req?.nextQ ?? 0}.json`; a.click();
});

function toAction(r: SignRequest): Action {
  const expirySlot = BigInt(r.expirySlot);
  const a = r.action;
  if (a.kind === "TransferSol") return { kind: "TransferSol", to: new PublicKey(a.to), lamports: BigInt(a.lamports), expirySlot };
  if (a.kind === "Rotate") { const k = unb64(a.newLmsPubkey); parseLmsPublicKey(k); return { kind: "Rotate", newLmsPubkey: k, expirySlot }; }
  return { kind: "Close", to: new PublicKey(a.to), expirySlot };
}

// keep the key-derivation code path warm so the first sign is not a cold import
void LmsPrivateKey; void deriveKeyMaterial;
