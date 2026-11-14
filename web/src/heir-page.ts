/**
 * The Inheritance tab of a Heir build of the vault page: where the plan stands, and the form a
 * new plan is prepared with. Signing and submitting are the page's own flow, the same one a
 * transfer goes through; this file only supplies the form and reads the chain.
 *
 * Only a Heir build reaches it (`__HEIR__`). Nothing here runs when the module loads.
 */
import { PublicKey, SYSVAR_CLOCK_PUBKEY, SystemProgram } from "@solana/web3.js";
import { LAMPORT_VAULT_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, UNUSABLE_CLAIM_OWNERS, decodeVault, isLiveVault, successionStatus } from "@lamport-robotics/vault";
import { $, EXPLORER_ADDR, el, isPubkey, short, type SignRequest } from "./common.ts";
import { rpc } from "./rpc.ts";
import { NO_ADDRESS, clearRequest, days, planClock, planProblem, planRows, type HeirCtx, type PlanRequest } from "./heir-plan.ts";
import { claimComposer, extraPanels } from "./heir-ext.ts";

/** the cluster's own clock, which is the one the program reads; unix seconds */
export async function clusterTime(): Promise<bigint> {
  const info = await rpc.getAccountInfo(SYSVAR_CLOCK_PUBKEY, "confirmed");
  if (!info || info.data.length < 40) throw new Error("the cluster's clock could not be read");
  return info.data.readBigInt64LE(32);
}

/** a moment of the cluster's clock, to the minute; to the second in the test build, where a day lasts one */
const when = (ts: bigint) => new Date(Number(ts) * 1000).toLocaleString("en-US", { dateStyle: "medium", timeStyle: planClock().daySecs === 86_400n ? "short" : "medium" });

/**
 * what the chain has to say about a claim address before an owner signs for it. the program
 * refuses some of these itself; the last one it cannot see.
 */
export async function claimProblemOnChain(claim: PublicKey, vault: PublicKey, mayBeUnkeyed = false): Promise<string | null> {
  const info = await rpc.getAccountInfo(claim, "confirmed");
  const owner = info?.owner.toBase58();
  if (info?.executable || (owner && (owner === TOKEN_PROGRAM_ID.toBase58() || owner === TOKEN_2022_PROGRAM_ID.toBase58() || UNUSABLE_CLAIM_OWNERS.includes(owner)))) return "That address is a program, a token account or mint, or a sysvar. Nothing released there could be moved on.";
  if (info && info.owner.equals(LAMPORT_VAULT_PROGRAM_ID)) {
    if (!isLiveVault(info.data)) return "That address is an account of the vault program that is not an open vault.";
    if (decodeVault(info.data).succession?.claim.equals(vault)) return "That address is a vault whose own plan names this vault. A release would be trapped between the two.";
  }
  // a plan's address before the plan exists looks like this. the form never lets it through: the plan is created first
  if (!info && !PublicKey.isOnCurve(claim.toBytes()) && !mayBeUnkeyed) return "Nothing exists at that address and no key can sign for it. If it is a program's address (a plan, a multisig), create that account first.";
  return null;
}

/**
 * something the owner should know about a claim address the form accepts. an address that belongs to a
 * program and holds only SOL is what a multisig's vault looks like, and also what the address of a plan
 * that was never created looks like once anyone has sent it a lamport. the form cannot tell which.
 */
export async function claimNoteOnChain(claim: PublicKey): Promise<string | null> {
  if (PublicKey.isOnCurve(claim.toBytes())) return null;
  const info = await rpc.getAccountInfo(claim, "confirmed");
  if (info && info.owner.equals(SystemProgram.programId) && info.data.length === 0) return "This address belongs to a program, not to a key, and holds nothing but SOL. Whoever controls that program controls what is released there. If you meant a Lamport Heir plan, this is not one: a plan that exists is an account of the claim program.";
  return null;
}

/** the plan form, in the shape the page's signing flow takes a form in */
export function planForm(ctx: HeirCtx): { node: HTMLElement; read: () => SignRequest["action"] } {
  const s = ctx.vault.succession;
  const armed = !!s && !s.claim.equals(PublicKey.default);
  const day = planClock().daySecs;
  const kind = el("select", { id: "pkind" }, el("option", { value: "set" }, armed ? "Change the plan" : "Set a plan"), ...(armed ? [el("option", { value: "clear" }, "Remove the plan")] : []));
  const claim = el("input", { class: "mono", id: "pclaim", autocomplete: "off", spellcheck: "false", value: armed ? s!.claim.toBase58() : "" });
  const win = el("input", { class: "mono", id: "pwin", inputmode: "numeric", value: String(armed ? s!.windowSecs / day : 365n) });
  const wait = el("input", { class: "mono", id: "pwait", inputmode: "numeric", value: String(armed ? s!.waitSecs / day : 60n) });
  const optional = (k: PublicKey | undefined) => (k && !k.equals(PublicKey.default) ? k.toBase58() : "");
  const checkin = el("input", { class: "mono", id: "pcheckin", autocomplete: "off", spellcheck: "false", value: armed ? optional(s!.checkinKey) : "" });
  const contact = el("input", { class: "mono", id: "pcontact", autocomplete: "off", spellcheck: "false", value: armed ? optional(s!.contactKey) : "" });
  let terms: unknown;
  const composer = claimComposer(ctx, (address, t) => { claim.value = address; terms = t; stale(); });
  const fields = el("div", { id: "pfields" },
    composer,
    el("label", { class: "field" }, el("span", {}, "Releases to · address"), claim),
    el("div", { class: "two" },
      el("label", { class: "field" }, el("span", {}, "Silence before a waiting period · days"), win),
      el("label", { class: "field" }, el("span", {}, "Waiting period · days"), wait)),
    el("div", { class: "two" },
      el("label", { class: "field" }, el("span", {}, "Check-in key · optional"), checkin),
      el("label", { class: "field" }, el("span", {}, "Trusted contact · optional"), contact)));
  const out = el("div", { id: "pout" });
  const node = el("div", {}, el("label", { class: "field" }, el("span", {}, "Plan"), kind), fields,
    el("div", { class: "actions" }, el("button", { class: "btn", id: "pcheck" }, "Check the plan")), out);

  const wholeDays = (input: HTMLInputElement, what: string): string => {
    const v = input.value.trim();
    if (!/^\d{1,6}$/.test(v)) throw new Error(`Enter ${what} as a whole number of days.`);
    return String(BigInt(v) * day);
  };
  const optionalKey = (input: HTMLInputElement, what: string): string => {
    const v = input.value.trim();
    if (!v) return NO_ADDRESS;
    if (!isPubkey(v)) throw new Error(`The ${what} is not a valid address.`);
    return v;
  };
  /** the request the fields spell right now; throws on the first thing wrong with them */
  const current = (): PlanRequest => {
    if ((kind as HTMLSelectElement).value === "clear") return clearRequest();
    if (!isPubkey(claim.value)) throw new Error("Enter the address the vault releases to.");
    const a: PlanRequest = { kind: "SetSuccession", claim: claim.value.trim(), windowSecs: wholeDays(win, "the silence"), waitSecs: wholeDays(wait, "the waiting period"), checkinKey: optionalKey(checkin, "check-in key"), contactKey: optionalKey(contact, "trusted contact") };
    if (terms !== undefined) a.terms = terms;
    const why = planProblem(a, ctx.address.toBase58());
    if (why) throw new Error(why);
    return a;
  };
  // a plan is handed to the signing flow only as it was when the chain was last asked about it
  let checked: string | null = null;
  const stale = () => { checked = null; out.innerHTML = ""; };
  node.addEventListener("input", (e) => { if (e.target === claim) terms = undefined; stale(); });
  kind.addEventListener("change", () => { fields.classList.toggle("hidden", (kind as HTMLSelectElement).value === "clear"); stale(); });
  $("#pcheck", node).addEventListener("click", async () => {
    stale();
    const btn = $("#pcheck", node) as HTMLButtonElement;
    try {
      const a = current();
      btn.setAttribute("disabled", "");
      let note: string | null = null;
      if (a.claim !== NO_ADDRESS) {
        const why = await claimProblemOnChain(new PublicKey(a.claim), ctx.address); if (why) throw new Error(why);
        note = await claimNoteOnChain(new PublicKey(a.claim));
      }
      checked = JSON.stringify(a);
      out.append(el("dl", { class: "spec", style: "margin-top:14px" }, ...planRows(a, ctx.address.toBase58())),
        ...(note ? [el("div", { class: "notice warn", style: "margin-top:14px" }, note)] : []),
        el("p", { class: "quiet", style: "font-size:12.5px;margin-top:14px" }, "The signer shows these same lines. Sign only if it does."));
    } catch (e) { out.append(el("div", { class: "err" }, String((e as Error).message ?? e))); }
    finally { btn.removeAttribute("disabled"); }
  });
  const read = (): SignRequest["action"] => {
    const a = current();
    if (checked !== JSON.stringify(a)) throw new Error("Check the plan first.");
    return a;
  };
  return { node, read };
}

/** where the vault's plan stands, read from the vault account the page already has and the cluster's clock */
export function inheritancePanel(ctx: HeirCtx): HTMLElement {
  const box = el("div", {});
  const s = ctx.vault.succession;
  if (!s) { box.append(el("p", { class: "quiet" }, "This vault has no inheritance fields.")); return box; }
  const status = el("p", { class: "quiet" }, "Reading the cluster's clock…");
  box.append(status);
  const armed = !s.claim.equals(PublicKey.default);
  if (armed) {
    const claim = s.claim.toBase58();
    box.append(el("dl", { class: "spec", style: "margin:14px 0 22px" },
      el("dt", {}, "Releases to"), el("dd", {}, el("a", { href: EXPLORER_ADDR(claim), target: "_blank", rel: "noopener" }, short(claim, 8))),
      el("dt", {}, "Silence"), el("dd", {}, days(s.windowSecs)),
      el("dt", {}, "Waiting period"), el("dd", {}, days(s.waitSecs)),
      el("dt", {}, "Last signature"), el("dd", {}, when(s.lastSignedTs)),
      el("dt", {}, "Last check-in"), el("dd", {}, s.lastCheckinTs > 0n ? when(s.lastCheckinTs) : "none"),
      el("dt", {}, "Check-in key"), el("dd", {}, s.checkinKey.equals(PublicKey.default) ? "none" : short(s.checkinKey.toBase58(), 8)),
      el("dt", {}, "Trusted contact"), el("dd", {}, s.contactKey.equals(PublicKey.default) ? "none" : `${short(s.contactKey.toBase58(), 8)}${s.contactUsed ? " · extension used" : ""}`)));
  }
  void clusterTime().then((now) => {
    const st = successionStatus(s, now, planClock());
    status.textContent =
      st.phase === "unarmed" ? "No plan. Nothing in this vault is released to anyone." :
      st.phase === "quiet" ? `A plan is armed. If you sign nothing and do not check in until ${when(st.deadline!)}, anyone may open the waiting period. The soonest the vault could be released is ${when(st.earliestRelease!)}.` :
      st.phase === "overdue" ? `The deadline passed on ${when(st.deadline!)}. Anyone may open the waiting period now. Any signature from your words, or a check-in, resets the clock.` :
      st.phase === "waiting" ? `A waiting period is open. The vault can be released from ${when(st.releaseAt!)}. Any signature from your words, or a check-in, cancels it.` :
      `The waiting period is over: anyone may release the vault now. Until someone does, a signature from your words or a check-in still cancels it.`;
    status.classList.toggle("quiet", st.phase === "unarmed" || st.phase === "quiet");
  }).catch((e) => { status.textContent = `The plan's dates could not be worked out: ${String((e as Error).message ?? e)}`; });
  const more = extraPanels(ctx);
  if (more) box.append(more);
  return box;
}
