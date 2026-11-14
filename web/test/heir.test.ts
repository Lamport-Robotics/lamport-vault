/**
 * The Heir build's own code, without a browser: how a `SetSuccession` request is checked and
 * described (src/heir-plan.ts), and that the SDK as a Heir build sees it (src/heir-sdk.ts) signs
 * for the Heir-enabled program. The bytes and messages are compared with
 * kat/succession_encoding.json, the vectors the program's own tests read.
 *
 *   node --test test/
 *
 * The page's constants (`__HEIR__` and the others) are set by the bundler; here they are set by
 * hand before anything is imported.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

Object.assign(globalThis, { __HEIR__: true, __HEIR_RPC__: "", __HEIR_SHORT_CLOCKS__: false });

const { PublicKey } = await import("@solana/web3.js");
const real = await import("@lamport-robotics/vault");
const heir = await import("../src/heir-sdk.ts");
const plan = await import("../src/heir-plan.ts");

const kat = JSON.parse(readFileSync(new URL("../../kat/succession_encoding.json", import.meta.url), "utf8"));
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const VAULT = kat.pdas.vault.address as string;
const HEIR = "4JuUSWNLp73VutwTKFZA3D3oZz2n16dvaNbdx2494LNo";
const KEY = "7wAR7rhEDu9R95zFTxSGM5V8QvmRr4ZYuLusSWQfJNMB";
const DAY = 86_400;
const request = (over: Record<string, unknown> = {}) => ({ kind: "SetSuccession" as const, claim: HEIR, windowSecs: String(365 * DAY), waitSecs: String(60 * DAY), checkinKey: plan.NO_ADDRESS, contactKey: plan.NO_ADDRESS, ...over });

test("a Heir build's SDK names the Heir-enabled program, and nothing else changes", () => {
  assert.equal(heir.LAMPORT_VAULT_PROGRAM_ID.toBase58(), kat.program_ids.lamport_vault_heir);
  assert.notEqual(heir.LAMPORT_VAULT_PROGRAM_ID.toBase58(), real.LAMPORT_VAULT_PROGRAM_ID.toBase58());
  const changed = Object.keys(real).filter((k) => (heir as Record<string, unknown>)[k] !== (real as Record<string, unknown>)[k]).sort();
  assert.deepEqual(changed, ["LAMPORT_VAULT_PROGRAM_ID", "encodeAction", "vaultMessage"]);
  assert.deepEqual(Object.keys(heir).sort(), Object.keys(real).sort());
});

test("a signature made in a Heir build is for the Heir-enabled program", () => {
  const vault = new PublicKey(VAULT), bytes = Uint8Array.from([1, 2, 3]);
  assert.equal(hex(heir.vaultMessage(vault, 7, bytes)), hex(real.vaultMessage(vault, 7, bytes, real.LAMPORT_VAULT_HEIR_PROGRAM_ID)));
  // the vault's own id gives another message: such a signature is refused by the Heir-enabled program
  assert.notEqual(hex(heir.vaultMessage(vault, 7, bytes)), hex(real.vaultMessage(vault, 7, bytes)));
  // and a caller that names a program still gets that program
  assert.equal(hex(heir.vaultMessage(vault, 7, bytes, real.LAMPORT_VAULT_PROGRAM_ID)), hex(real.vaultMessage(vault, 7, bytes)));
});

test("requests become the bytes and the messages of kat/succession_encoding.json", () => {
  let seen = 0;
  for (const [name, v] of Object.entries<any>(kat.actions.vectors)) {
    if (v.action.kind !== "SetSuccession") continue;
    seen++;
    const { claim, windowSecs, waitSecs, checkinKey, contactKey } = v.action;
    const req = { kind: "SetSuccession" as const, claim, windowSecs, waitSecs, checkinKey, contactKey };
    assert.equal(plan.planProblem(req, VAULT), null, name);
    const bytes = heir.encodeAction(plan.planAction(req, BigInt(v.action.issuedSlot), BigInt(v.action.expirySlot)));
    assert.equal(bytes.length, kat.actions.size, name);
    assert.equal(hex(bytes), v.action_hex, name);
    assert.equal(hex(heir.vaultMessage(new PublicKey(VAULT), kat.inputs.generation, bytes)), v.message_hex, name);
  }
  assert.equal(seen, 3);
  // the vault's own actions still encode as they always did
  for (const name of ["transfer_sol", "close"]) assert.ok(kat.actions.vectors[name].action_hex.length > 0);
});

test("a plan the program would refuse is refused before it costs a one-time key", () => {
  const refused = (over: Record<string, unknown>, why: RegExp) => assert.match(plan.planProblem(request(over), VAULT) ?? "accepted", why);
  assert.equal(plan.planProblem(request(), VAULT), null);
  assert.equal(plan.planProblem(request({ checkinKey: KEY, contactKey: KEY }), VAULT), null);
  refused({ claim: "not an address" }, /not a valid address/);
  refused({ claim: ` ${HEIR}` }, /not a valid address/);
  refused({ checkinKey: "" }, /not a valid address/);
  refused({ contactKey: 5 }, /not a valid address/);
  refused({ windowSecs: 365 * DAY }, /whole numbers of seconds/);
  refused({ windowSecs: "1e9" }, /whole numbers of seconds/);
  refused({ waitSecs: "-1" }, /whole numbers of seconds/);
  refused({ windowSecs: "18446744073709551616" }, /whole numbers of seconds/);
  refused({ windowSecs: String(90 * DAY - 1) }, /WindowOutOfRange/);
  refused({ waitSecs: String(30 * DAY - 1) }, /WaitOutOfRange/);
  refused({ windowSecs: String(36_500 * DAY + 1) }, /WindowOutOfRange/);
  refused({ claim: VAULT }, /ClaimIsTheVault/);
  // the program this build talks to. (here that is the vault's own: only the bundler puts heir-sdk.ts in the SDK's place)
  refused({ claim: real.LAMPORT_VAULT_PROGRAM_ID.toBase58() }, /program or a sysvar/);
  refused({ claim: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" }, /program or a sysvar/);
  refused({ claim: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" }, /program or a sysvar/);
  refused({ claim: "BPFLoaderUpgradeab1e11111111111111111111111" }, /program or a sysvar/);
  // floors and ceiling exactly
  assert.equal(plan.planProblem(request({ windowSecs: String(90 * DAY), waitSecs: String(30 * DAY) }), VAULT), null);
  assert.equal(plan.planProblem(request({ windowSecs: String(36_500 * DAY), waitSecs: String(36_500 * DAY) }), VAULT), null);
});

test("removing a plan has one spelling", () => {
  const clear = plan.clearRequest();
  assert.equal(plan.isClear(clear), true);
  assert.equal(plan.planProblem(clear, VAULT), null);
  assert.match(plan.planProblem({ ...clear, windowSecs: String(90 * DAY) }, VAULT) ?? "accepted", /ClearCarriesPlan/);
  assert.match(plan.planProblem({ ...clear, checkinKey: KEY }, VAULT) ?? "accepted", /ClearCarriesPlan/);
  assert.match(plan.planProblem({ ...clear, terms: {} }, VAULT) ?? "accepted", /carries no terms/);
  assert.deepEqual(plan.planLines(clear, VAULT).map(([k]) => k), ["action"]);
  assert.match(plan.planLines(clear, VAULT)[0][1], /remove the inheritance plan/);
  assert.match(plan.describePlan(clear), /^Remove the inheritance plan/);
});

test("the plan is said in full: where, when, the soonest release, and what each key may do", () => {
  const lines = new Map(plan.planLines(request({ checkinKey: KEY }), VAULT));
  assert.equal(lines.get("releases to"), HEIR);
  assert.match(lines.get("who that is")!, /only sees an address/);
  assert.match(lines.get("after")!, /^365 days with no signature/);
  assert.match(lines.get("waiting period")!, /^60 days\./);
  assert.equal(lines.get("soonest release"), "425 days after your last signature");
  assert.match(lines.get("check-in key")!, new RegExp(`^${KEY} · may reset the clock, for at most 730 days`));
  assert.equal(lines.get("trusted contact"), "none");
  assert.equal(lines.has("clock"), false); // only a test build says what its clock is
  const both = new Map(plan.planLines(request({ contactKey: KEY }), VAULT));
  assert.match(both.get("check-in key")!, /^none/);
  assert.match(both.get("trusted contact")!, new RegExp(`^${KEY} · may push the deadline back by 90 days, once`));
  assert.match(plan.describePlan(request()), new RegExp(`release to ${HEIR} after 365 days of silence, then a waiting period of 60 days`));
});

test("durations are days of the program's clock", () => {
  assert.equal(plan.days(String(DAY)), "1 day");
  assert.equal(plan.days(BigInt(90 * DAY)), "90 days");
  assert.equal(plan.days("86401"), "86401 seconds");
});
