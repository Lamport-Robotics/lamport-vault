import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  LAMPORT_VAULT_HEIR_MAINNET_PROGRAM_ID,
  LAMPORT_VAULT_HEIR_PROGRAM_ID,
  LAMPORT_VAULT_HEIR_SHORT_CLOCKS_PROGRAM_ID,
  LAMPORT_VAULT_MAINNET_PROGRAM_ID,
  LAMPORT_VAULT_PROGRAM_ID,
  PQ_REGISTRY_MAINNET_PROGRAM_ID,
  PQ_REGISTRY_PROGRAM_ID,
  SUCCESSION_CLOCK,
  successionClockFor,
  vaultMessage,
} from "../src/index.ts";

const source = (program: string) => readFileSync(new URL(`../../../../programs/${program}/src/lib.rs`, import.meta.url), "utf8");

/** the id a `declare_id!` compiles in under exactly this `#[cfg(...)]` */
function declared(rust: string, cfg: string): string {
  const at = rust.indexOf(`#[cfg(${cfg})] declare_id!("`);
  if (at < 0) throw new Error(`no declare_id! under #[cfg(${cfg})]`);
  return rust.slice(at).match(/declare_id!\("([1-9A-HJ-NP-Za-km-z]+)"\)/)![1]!;
}

describe("mainnet program ids", () => {
  const vault = source("lamport-vault");
  const registry = source("pq-registry");

  it("are the ids the programs compile in with the `mainnet` feature", () => {
    expect(LAMPORT_VAULT_MAINNET_PROGRAM_ID.toBase58()).toBe(declared(vault, 'all(feature = "mainnet", not(feature = "succession"))'));
    expect(LAMPORT_VAULT_HEIR_MAINNET_PROGRAM_ID.toBase58()).toBe(declared(vault, 'all(feature = "mainnet", feature = "succession", not(feature = "short-clocks"))'));
    expect(PQ_REGISTRY_MAINNET_PROGRAM_ID.toBase58()).toBe(declared(registry, 'feature = "mainnet"'));
  });

  it("leave the devnet ids where they were", () => {
    expect(LAMPORT_VAULT_PROGRAM_ID.toBase58()).toBe(declared(vault, 'not(any(feature = "succession", feature = "mainnet"))'));
    expect(LAMPORT_VAULT_HEIR_PROGRAM_ID.toBase58()).toBe(declared(vault, 'all(feature = "succession", not(feature = "short-clocks"), not(feature = "mainnet"))'));
    expect(LAMPORT_VAULT_HEIR_SHORT_CLOCKS_PROGRAM_ID.toBase58()).toBe(declared(vault, 'feature = "short-clocks"'));
    expect(PQ_REGISTRY_PROGRAM_ID.toBase58()).toBe(declared(registry, 'not(feature = "mainnet")'));
  });

  it("are seven different programs: no id is shared between clusters or builds", () => {
    const ids = [
      LAMPORT_VAULT_PROGRAM_ID,
      LAMPORT_VAULT_HEIR_PROGRAM_ID,
      LAMPORT_VAULT_HEIR_SHORT_CLOCKS_PROGRAM_ID,
      PQ_REGISTRY_PROGRAM_ID,
      LAMPORT_VAULT_MAINNET_PROGRAM_ID,
      LAMPORT_VAULT_HEIR_MAINNET_PROGRAM_ID,
      PQ_REGISTRY_MAINNET_PROGRAM_ID,
    ].map((id) => id.toBase58());
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("a mainnet build is never a test build: the source refuses the combination", () => {
    expect(vault).toContain('#[cfg(all(feature = "mainnet", any(feature = "short-clocks", feature = "small-history")))]\ncompile_error!');
    expect(registry).toContain('#[cfg(all(feature = "mainnet", feature = "small-history"))]\ncompile_error!');
  });

  it("the mainnet Heir vault runs on the real clock", () => {
    expect(successionClockFor(LAMPORT_VAULT_HEIR_MAINNET_PROGRAM_ID)).toBe(SUCCESSION_CLOCK);
  });

  it("a signature for a devnet vault is not one for mainnet: the message binds the program id", () => {
    const action = new Uint8Array([1, 2, 3]);
    const devnet = vaultMessage(LAMPORT_VAULT_PROGRAM_ID, 0, action);
    const mainnet = vaultMessage(LAMPORT_VAULT_PROGRAM_ID, 0, action, LAMPORT_VAULT_MAINNET_PROGRAM_ID);
    expect(Buffer.from(devnet).equals(Buffer.from(mainnet))).toBe(false);
  });
});
