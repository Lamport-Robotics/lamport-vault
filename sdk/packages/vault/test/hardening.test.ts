import { Keypair, PublicKey } from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { CLUSTERS, deriveKeyMaterial, LMS_SHA256_M32_H5, LmsPrivateKey, mnemonicToMaster, randomKeyMaterial } from "@lamport-robotics/lms";
import { describe, expect, it } from "vitest";
import { encodeVault, firstFreeLeaf, lastFreeLeaf, usedKeyHash } from "../src/accounts.ts";
import { IX } from "../src/discriminator.ts";
import { executeRemainingAccounts, sweepClosedSolInstruction } from "../src/instructions.ts";
import { findVaultPdaForKey, vaultId } from "../src/pda.ts";
import { LAMPORT_VAULT_PROGRAM_ID } from "../src/programIds.ts";
import { ChainBehindJournalError, nextFreshKeyIndex, StaleSignerError, VaultSigner } from "../src/signer.ts";
import { MockChain } from "./mock.ts";

const rnd = () => LmsPrivateKey.generate(randomKeyMaterial(LMS_SHA256_M32_H5, 3));
const used = (bits: number[], bytes = 4) => { const u = new Uint8Array(bytes); for (const q of bits) u[q >> 3] |= 1 << (q & 7); return u; };
const freshVault = (key: { publicKey: Uint8Array }, extra: Partial<Parameters<typeof encodeVault>[0]> = {}) =>
  encodeVault({ version: 2, bump: 0, vaultId: vaultId(key.publicKey), lmsPubkey: key.publicKey, spent: 0, generation: 0, createdSlot: 1n, used: new Uint8Array(4), usedKeys: [], ...extra });

describe("lastFreeLeaf", () => {
  it("is the highest unspent leaf of the lane, or undefined", () => {
    const v = { used: used([31, 30, 7]) };
    expect(lastFreeLeaf(v)).toBe(29);
    expect(firstFreeLeaf(v)).toBe(0);
    expect(lastFreeLeaf(v, 1, 2)).toBe(29); // odd lane: 31 spent, 29 free
    expect(lastFreeLeaf(v, 0, 2)).toBe(28);
    expect(lastFreeLeaf(v, 0, 1, (q) => q >= 8)).toBe(6); // skip covers reserved leaves too
    expect(lastFreeLeaf({ used: used(Array.from({ length: 32 }, (_, i) => i)) })).toBeUndefined();
  });
});

describe("a signer that cannot trust its record", () => {
  it("rotates on the highest free leaf, never the smallest one a lost record may have signed", async () => {
    const rpc = new MockChain();
    const key = rnd(), next = rnd();
    const payer = Keypair.generate();
    const signer = new VaultSigner({ rpc, key, payer, journal: "ephemeral" });
    rpc.accounts.set(signer.vault.toBase58(), freshVault(key));
    // another device spent leaves 0 and 1; this signer's (empty) record is behind the chain
    rpc.spend(signer.vault, [0, 1]);
    const blind = new VaultSigner({ rpc, key, payer, journal: "ephemeral" });
    await blind.syncJournal(await blind.fetchVault()); // fresh record adopts the chain, not stale yet
    rpc.spend(signer.vault, [2]); // now the chain moved under it
    await expect(blind.sign({ kind: "TransferSol", to: payer.publicKey, lamports: 1n, issuedSlot: 0n, expirySlot: 1n })).rejects.toThrow(StaleSignerError);
    const rot = await blind.sign({ kind: "Rotate", newLmsPubkey: next.publicKey, issuedSlot: 0n, expirySlot: 1n }, { allowForeignKey: true });
    expect(rot.q).toBe(31);
  });

  it("refuses to sign on an RPC view that is behind its own record", async () => {
    const rpc = new MockChain();
    const key = rnd(), payer = Keypair.generate();
    const signer = new VaultSigner({ rpc, key, payer, journal: "ephemeral" });
    const before = freshVault(key);
    rpc.accounts.set(signer.vault.toBase58(), before);
    rpc.spend(signer.vault, [0, 1, 2]);
    await signer.syncJournal(await signer.fetchVault()); // journal: spent 3
    rpc.accounts.set(signer.vault.toBase58(), before); // a lagging or lying node: back to 0 spent
    await expect(signer.sign({ kind: "Rotate", newLmsPubkey: rnd().publicKey, issuedSlot: 0n, expirySlot: 1n }, { allowForeignKey: true })).rejects.toThrow(ChainBehindJournalError);
  });

  it("never picks a leaf it once signed, even when a later RPC view shows it clear", async () => {
    const rpc = new MockChain();
    const key = rnd(), payer = Keypair.generate();
    const signer = new VaultSigner({ rpc, key, payer, journal: "ephemeral" });
    rpc.accounts.set(signer.vault.toBase58(), freshVault(key));
    const a = await signer.sign({ kind: "TransferSol", to: payer.publicKey, lamports: 1n, issuedSlot: 0n, expirySlot: 1n });
    expect(a.q).toBe(0);
    rpc.spend(signer.vault, [0]); // it lands
    await signer.syncJournal(await signer.fetchVault()); // reservation 0 moves to settled
    expect((await signer.journal.load())?.settled).toEqual([0]);
    // a forked view: same count, different leaf
    rpc.accounts.set(signer.vault.toBase58(), freshVault(key, { spent: 1, used: used([5]) }));
    const b = await signer.sign({ kind: "TransferSol", to: payer.publicKey, lamports: 1n, issuedSlot: 0n, expirySlot: 1n });
    expect(b.q).toBe(1); // not 0
  });
});

describe("nextFreshKeyIndex", () => {
  const master = mnemonicToMaster("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art");
  const scope = { genesisHash: CLUSTERS.devnet.genesisHash, programId: LAMPORT_VAULT_PROGRAM_ID };
  const keyAt = (k: number) => LmsPrivateKey.generate(deriveKeyMaterial(master, k, scope, LMS_SHA256_M32_H5, 3));

  it("skips a key that a vault seen on the walk rotated to, and one in its history", async () => {
    const rpc = new MockChain();
    const k0 = keyAt(0), k1 = keyAt(1), k2 = keyAt(2);
    // vault 0 was created with k0, rotated to k1, then to k2: k0 is history, k1 is history, k2 is live there
    rpc.accounts.set(findVaultPdaForKey(LAMPORT_VAULT_PROGRAM_ID, k0.publicKey).address.toBase58(), encodeVault({ version: 2, bump: 0, vaultId: vaultId(k0.publicKey), lmsPubkey: k2.publicKey, spent: 0, generation: 2, createdSlot: 1n, used: new Uint8Array(4), usedKeys: [usedKeyHash(k0.publicKey), usedKeyHash(k1.publicKey)] }));
    const fresh = await nextFreshKeyIndex(master, scope, rpc, { lmsType: LMS_SHA256_M32_H5 });
    expect(fresh.k).toBe(3);
    expect(fresh.skipped).toEqual([{ k: 0, state: "vault" }, { k: 1, state: "in-use" }, { k: 2, state: "in-use" }]);
  });

  it("asks the node whether any vault at all holds the key when it can", async () => {
    const rpc = new MockChain() as MockChain & { getProgramAccounts: (p: PublicKey, c: any) => Promise<{ pubkey: PublicKey; account: any }[]> };
    const k0 = keyAt(0);
    const asked: string[] = [];
    rpc.getProgramAccounts = async (_p, c) => { const b = c.filters[0].memcmp.bytes as string; asked.push(b); return b === Buffer.from(k0.publicKey).toString("base64") ? [{ pubkey: Keypair.generate().publicKey, account: {} }] : []; };
    const fresh = await nextFreshKeyIndex(master, scope, rpc, { lmsType: LMS_SHA256_M32_H5 });
    expect(fresh.k).toBe(1);
    expect(fresh.skipped).toEqual([{ k: 0, state: "in-use" }]);
    expect(asked.length).toBe(2);
  });
});

describe("instructions", () => {
  it("sweep_closed_sol: tombstone and heir, anchor discriminator", () => {
    const vault = Keypair.generate().publicKey, heir = Keypair.generate().publicKey;
    const ix = sweepClosedSolInstruction({ programId: LAMPORT_VAULT_PROGRAM_ID, vault, heir });
    expect(Buffer.from(ix.data)).toEqual(Buffer.from(sha256(new TextEncoder().encode("global:sweep_closed_sol")).slice(0, 8)));
    expect(Buffer.from(IX.sweepClosedSol)).toEqual(Buffer.from(ix.data));
    expect(ix.keys.map((k) => [k.pubkey.toBase58(), k.isWritable, k.isSigner])).toEqual([[vault.toBase58(), true, false], [heir.toBase58(), true, false]]);
  });

  it("transfer-hook accounts ride behind the four token accounts", () => {
    const vault = Keypair.generate().publicKey, mint = Keypair.generate().publicKey, to = Keypair.generate().publicKey, hook = Keypair.generate().publicKey;
    const keys = executeRemainingAccounts(vault, { kind: "TransferToken", mint, to, amount: 1n, issuedSlot: 0n, expirySlot: 1n }, undefined, [], undefined, [{ pubkey: hook, isSigner: false, isWritable: false }]);
    expect(keys.length).toBe(5);
    expect(keys[4]!.pubkey.equals(hook)).toBe(true);
  });
});
