/**
 * What a mainnet build is made of, without a browser: the cluster's constants (src/common.ts) and
 * the SDK as that build sees it (src/mainnet-sdk.ts for the vault's own page and signer,
 * src/heir-sdk.ts for the Heir build). The ids are compared with the programs' own source.
 *
 *   node --test test/
 *
 * The page's constants are set by the bundler; here they are set by hand before anything is
 * imported. Each test file runs in a process of its own, so this does not reach heir.test.ts.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

Object.assign(globalThis, { __HEIR__: false, __HEIR_RPC__: "", __HEIR_SHORT_CLOCKS__: false, __MAINNET__: true });

const real = await import("@lamport-robotics/vault");
const { CLUSTERS, deriveLmsInputs } = await import("@lamport-robotics/lms");
const common = await import("../src/common.ts");
const own = await import("../src/mainnet-sdk.ts");
const heir = await import("../src/heir-sdk.ts");

const rust = (program: string) => readFileSync(new URL(`../../programs/${program}/src/lib.rs`, import.meta.url), "utf8");
const declared = (source: string, cfg: string) => {
  const at = source.indexOf(`#[cfg(${cfg})] declare_id!("`);
  assert.ok(at >= 0, `no declare_id! under #[cfg(${cfg})]`);
  return source.slice(at).match(/declare_id!\("([1-9A-HJ-NP-Za-km-z]+)"\)/)![1]!;
};
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

test("a mainnet build names mainnet everywhere a cluster is named", () => {
  assert.equal(common.CLUSTER, "mainnet-beta");
  assert.equal(common.GENESIS_HASH, CLUSTERS.mainnet.genesisHash);
  assert.notEqual(common.GENESIS_HASH, CLUSTERS.devnet.genesisHash);
  assert.equal(common.RPC_URL, "https://api.mainnet-beta.solana.com");
  assert.match(common.EXPLORER_ADDR("11111111111111111111111111111111"), /\?cluster=mainnet-beta$/);
});

test("the vault's own mainnet build operates the mainnet programs", () => {
  assert.equal(own.LAMPORT_VAULT_PROGRAM_ID.toBase58(), declared(rust("lamport-vault"), 'all(feature = "mainnet", not(feature = "succession"))'));
  assert.equal(own.PQ_REGISTRY_PROGRAM_ID.toBase58(), declared(rust("pq-registry"), 'feature = "mainnet"'));
  assert.notEqual(own.LAMPORT_VAULT_PROGRAM_ID.toBase58(), real.LAMPORT_VAULT_PROGRAM_ID.toBase58());
  assert.notEqual(own.PQ_REGISTRY_PROGRAM_ID.toBase58(), real.PQ_REGISTRY_PROGRAM_ID.toBase58());
});

test("the Heir mainnet build operates the mainnet Heir vault and the mainnet registry", () => {
  assert.equal(heir.LAMPORT_VAULT_PROGRAM_ID.toBase58(), declared(rust("lamport-vault"), 'all(feature = "mainnet", feature = "succession", not(feature = "short-clocks"))'));
  assert.equal(heir.PQ_REGISTRY_PROGRAM_ID.toBase58(), own.PQ_REGISTRY_PROGRAM_ID.toBase58());
  assert.notEqual(heir.LAMPORT_VAULT_PROGRAM_ID.toBase58(), own.LAMPORT_VAULT_PROGRAM_ID.toBase58());
});

test("what a mainnet build signs binds its own program id, and nothing made for devnet", () => {
  const vault = real.LAMPORT_VAULT_PROGRAM_ID; // any address will do as the vault
  const action = new Uint8Array([7, 7, 7]);
  assert.equal(hex(own.vaultMessage(vault, 3, action)), hex(real.vaultMessage(vault, 3, action, own.LAMPORT_VAULT_PROGRAM_ID)));
  assert.equal(hex(heir.vaultMessage(vault, 3, action)), hex(real.vaultMessage(vault, 3, action, heir.LAMPORT_VAULT_PROGRAM_ID)));
  const made = new Set([hex(real.vaultMessage(vault, 3, action)), hex(real.vaultMessage(vault, 3, action, real.LAMPORT_VAULT_HEIR_PROGRAM_ID)), hex(own.vaultMessage(vault, 3, action)), hex(heir.vaultMessage(vault, 3, action))]);
  assert.equal(made.size, 4);
});

test("the same words give other keys on mainnet: the derivation binds the genesis hash and the program id", () => {
  const master = new Uint8Array(64).fill(9); // a made-up BIP-39 seed, for this test only
  const identifier = (genesisHash: string, programId: string) => hex(deriveLmsInputs(master, 0, { genesisHash, programId }).I);
  const devnet = identifier(CLUSTERS.devnet.genesisHash, real.LAMPORT_VAULT_PROGRAM_ID.toBase58());
  const mainnet = identifier(common.GENESIS_HASH, own.LAMPORT_VAULT_PROGRAM_ID.toBase58());
  const mainnetHeir = identifier(common.GENESIS_HASH, heir.LAMPORT_VAULT_PROGRAM_ID.toBase58());
  assert.equal(new Set([devnet, mainnet, mainnetHeir]).size, 3);
});
