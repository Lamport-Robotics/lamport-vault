/**
 * `sweepClosed` against the mock chain: finds a closed vault's token accounts for a mint and sends
 * one `sweep_closed` per account, to the tombstone's heir and nowhere else.
 */
import { Keypair, PublicKey } from "@solana/web3.js";
import { fromHex, LMS_SHA256_M32_H5, LmsPrivateKey, toHex } from "@lamport-robotics/lms";
import { describe, expect, it } from "vitest";
import { encodeTombstone, encodeVault, TOMBSTONE_ACCOUNT_VERSION } from "../src/accounts.ts";
import { IX } from "../src/discriminator.ts";
import { sweepClosedInstruction } from "../src/instructions.ts";
import { associatedTokenAddress, findVaultPdaForKey, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, vaultId } from "../src/pda.ts";
import { LAMPORT_VAULT_PROGRAM_ID } from "../src/programIds.ts";
import { sweepClosed } from "../src/sweep.ts";
import { MockChain } from "./mock.ts";

const key = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H5, lmotsType: 3, seed: fromHex("784bd340367baa20a90c48bf5623171cba34eb7b4022f11ecca2cc1a893cb506"), I: fromHex("00112233445566778899aabbccddeeff") });
const vault = findVaultPdaForKey(LAMPORT_VAULT_PROGRAM_ID, key.publicKey).address;
const heir = Keypair.generate().publicKey;
const tombstone = () => encodeTombstone({ version: TOMBSTONE_ACCOUNT_VERSION, vaultId: vaultId(key.publicKey), closedSlot: 5n, heir });
const liveVault = () => encodeVault({ version: 2, bump: 0, vaultId: vaultId(key.publicKey), lmsPubkey: key.publicKey, spent: 0, generation: 0, createdSlot: 1n, used: new Uint8Array(4), usedKeys: [] });

/** A closed vault that still owns two accounts of `mint` (its ATA and a stray one) and one of another mint. */
function closedWithTokens(rpc: MockChain, program: PublicKey) {
  const mint = Keypair.generate().publicKey;
  const other = Keypair.generate().publicKey;
  rpc.mints.set(mint.toBase58(), program);
  rpc.mints.set(other.toBase58(), program);
  rpc.accounts.set(vault.toBase58(), tombstone());
  const ata = associatedTokenAddress(vault, mint, program);
  const stray = Keypair.generate().publicKey;
  const otherAta = associatedTokenAddress(vault, other, program);
  rpc.tokenAccounts.set(ata.toBase58(), { owner: vault, mint, amount: 700n });
  rpc.tokenAccounts.set(stray.toBase58(), { owner: vault, mint, amount: 300n });
  rpc.tokenAccounts.set(otherAta.toBase58(), { owner: vault, mint: other, amount: 9n });
  return { mint, other, ata, stray, otherAta };
}

describe("sweepClosed", () => {
  it("sweeps every token account of the mint to the heir's ATA, one transaction each, and leaves other mints alone", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const { mint, ata, stray, otherAta } = closedWithTokens(rpc, TOKEN_PROGRAM_ID);
    const seen: [number, number, string][] = [];
    const res = await sweepClosed(rpc, payer, vault, mint, { onTransaction: (i, n, s) => seen.push([i, n, s]) });
    expect(res.heir.equals(heir)).toBe(true);
    const heirAta = associatedTokenAddress(heir, mint, TOKEN_PROGRAM_ID);
    expect(res.heirTokenAccount.equals(heirAta)).toBe(true);
    expect(res.swept.map((s) => [s.account.toBase58(), s.signature])).toEqual([
      [ata.toBase58(), "sig1"],
      [stray.toBase58(), "sig2"],
    ]);
    expect(seen).toEqual([
      [0, 2, "sig1"],
      [1, 2, "sig2"],
    ]);
    // Each transaction is exactly the builder's instruction, signed by the payer.
    expect(rpc.sent.length).toBe(2);
    for (const [i, account] of [ata, stray].entries()) {
      const tx = rpc.sent[i]!;
      expect(tx.instructions.length).toBe(1);
      const want = sweepClosedInstruction({ programId: LAMPORT_VAULT_PROGRAM_ID, payer: payer.publicKey, vault, heir, mint, vaultTokenAccount: account }).instruction;
      expect(toHex(tx.instructions[0]!.data)).toBe(toHex(IX.sweepClosed));
      expect(tx.instructions[0]!.keys.map((k) => k.pubkey.toBase58())).toEqual(want.keys.map((k) => k.pubkey.toBase58()));
      expect(tx.feePayer!.equals(payer.publicKey)).toBe(true);
    }
    // The balance moved, the vault's accounts of that mint are gone, the other mint's is untouched.
    expect(rpc.tokenAccounts.get(heirAta.toBase58())).toEqual({ owner: heir, mint, amount: 1000n });
    expect(rpc.tokenAccounts.has(ata.toBase58())).toBe(false);
    expect(rpc.tokenAccounts.has(stray.toBase58())).toBe(false);
    expect(rpc.tokenAccounts.get(otherAta.toBase58())!.amount).toBe(9n);
    // Nothing left for that mint: no transaction, the heir's ATA still named.
    const again = await sweepClosed(rpc, payer, vault, mint);
    expect(again.swept).toEqual([]);
    expect(again.heirTokenAccount.equals(heirAta)).toBe(true);
    expect(rpc.sent.length).toBe(2);
  });

  it("uses the token program that owns the mint (Token-2022)", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const { mint, ata } = closedWithTokens(rpc, TOKEN_2022_PROGRAM_ID);
    const res = await sweepClosed(rpc, payer, vault, mint);
    expect(res.swept.length).toBe(2);
    expect(res.heirTokenAccount.equals(associatedTokenAddress(heir, mint, TOKEN_2022_PROGRAM_ID))).toBe(true);
    expect(rpc.sent[0]!.instructions[0]!.keys[6]!.pubkey.equals(TOKEN_2022_PROGRAM_ID)).toBe(true);
    expect(rpc.tokenAccounts.has(ata.toBase58())).toBe(false);
    expect(rpc.tokenAccounts.get(res.heirTokenAccount.toBase58())!.amount).toBe(1000n);
  });

  it("refuses before sending: a live vault, a missing account, a mint that is not a token mint", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const { mint } = closedWithTokens(rpc, TOKEN_PROGRAM_ID);
    rpc.accounts.set(vault.toBase58(), liveVault());
    await expect(sweepClosed(rpc, payer, vault, mint)).rejects.toThrow(/not a closed vault/);
    rpc.accounts.delete(vault.toBase58());
    await expect(sweepClosed(rpc, payer, vault, mint)).rejects.toThrow(/nothing to sweep/);
    rpc.accounts.set(vault.toBase58(), tombstone());
    await expect(sweepClosed(rpc, payer, vault, Keypair.generate().publicKey)).rejects.toThrow(/does not exist/);
    const notAMint = Keypair.generate().publicKey;
    rpc.mints.set(notAMint.toBase58(), LAMPORT_VAULT_PROGRAM_ID);
    await expect(sweepClosed(rpc, payer, vault, notAMint)).rejects.toThrow(/not Token or Token-2022/);
    expect(rpc.sent.length).toBe(0);
  });

  it("the mock, like the program, lets funds go to the heir only", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const { mint, ata } = closedWithTokens(rpc, TOKEN_PROGRAM_ID);
    const stranger = Keypair.generate().publicKey;
    const { sendAndConfirm } = await import("../src/signer.ts");
    const wrongHeir = sweepClosedInstruction({ programId: LAMPORT_VAULT_PROGRAM_ID, payer: payer.publicKey, vault, heir: stranger, mint, vaultTokenAccount: ata }).instruction;
    await expect(sendAndConfirm(rpc, [payer], [wrongHeir])).rejects.toThrow(/WrongHeir/);
    const right = sweepClosedInstruction({ programId: LAMPORT_VAULT_PROGRAM_ID, payer: payer.publicKey, vault, heir, mint, vaultTokenAccount: ata }).instruction;
    right.keys[3]!.pubkey = associatedTokenAddress(stranger, mint, TOKEN_PROGRAM_ID);
    await expect(sendAndConfirm(rpc, [payer], [right])).rejects.toThrow(/NotHeirTokenAccount/);
    expect(rpc.tokenAccounts.get(ata.toBase58())!.amount).toBe(700n);
  });
});
