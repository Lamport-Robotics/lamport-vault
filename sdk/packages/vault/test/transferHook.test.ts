/**
 * A Token-2022 transfer hook's accounts: finding the hook in a mint, resolving its list, and what
 * the builders, `sweepClosed` and `VaultSigner` do with the result. The resolution is checked
 * against `@solana/spl-token`'s own (`addExtraAccountMetasForExecute`), entry kind by entry kind;
 * where the two differ on purpose (no account is ever a signer here, and a signer of the
 * transaction is never added), the difference is the test.
 */
import { addExtraAccountMetasForExecute, createTransferCheckedInstruction, getExtraAccountMetaAddress, getTransferHook, unpackMint } from "@solana/spl-token";
import { type AccountInfo, type AccountMeta, type Connection, Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { fromHex, LMS_SHA256_M32_H5, LmsPrivateKey } from "@lamport-robotics/lms";
import { describe, expect, it } from "vitest";
import { encodeTombstone, encodeVault, TOMBSTONE_ACCOUNT_VERSION } from "../src/accounts.ts";
import { executeDirectInstruction } from "../src/direct.ts";
import { IX } from "../src/discriminator.ts";
import { buildStagedExecution, executeRemainingAccounts, sweepClosedInstruction } from "../src/instructions.ts";
import { associatedTokenAddress, findVaultPdaForKey, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, vaultId } from "../src/pda.ts";
import { LAMPORT_VAULT_PROGRAM_ID } from "../src/programIds.ts";
import { VaultSigner } from "../src/signer.ts";
import { sweepClosed } from "../src/sweep.ts";
import { decodeExtraAccountMetas, extraAccountMetasAddress, type HookedTransfer, resolveTransferHookAccounts, transferHookAccounts, transferHookProgramId } from "../src/transferHook.ts";
import { MockChain } from "./mock.ts";

const EXECUTE = [105, 37, 101, 197, 75, 251, 102, 26];
const text = (s: string) => [...new TextEncoder().encode(s)];
const key = () => Keypair.generate().publicKey;

// ---- encoders, written out by hand from the on-chain layouts ----

/** A Token-2022 mint with `extensions` as `[type, value]` pairs, in order. */
function mintData(extensions: [number, number[]][]): Uint8Array {
  const base = new Uint8Array(82);
  base[44] = 6; // decimals
  base[45] = 1; // initialised
  if (extensions.length === 0) return base;
  const tlv = extensions.flatMap(([type, value]) => [type & 0xff, type >> 8, value.length & 0xff, value.length >> 8, ...value]);
  const out = new Uint8Array(166 + tlv.length);
  out.set(base);
  out[165] = 1; // account type: mint
  out.set(tlv, 166);
  return out;
}

/** The transfer-hook extension (type 14): authority, then the hook program (zero for none). */
const hookExtension = (program: PublicKey | null): [number, number[]] => [14, [...new Uint8Array(32), ...(program ? program.toBytes() : new Uint8Array(32))]];

interface Entry {
  discriminator: number;
  config: number[];
  signer?: boolean;
  writable?: boolean;
}
const fixed = (k: PublicKey, flags: { signer?: boolean; writable?: boolean } = {}): Entry => ({ discriminator: 0, config: [...k.toBytes()], ...flags });
const pda = (seeds: number[][], flags: { signer?: boolean; writable?: boolean } = {}, programAt?: number): Entry => ({ discriminator: programAt === undefined ? 1 : 128 + programAt, config: seeds.flat(), ...flags });
const readKey = (source: number[], flags: { signer?: boolean; writable?: boolean } = {}): Entry => ({ discriminator: 2, config: source, ...flags });
const literal = (bytes: number[]) => [1, bytes.length, ...bytes];
const ixData = (index: number, length: number) => [2, index, length];
const accountKey = (index: number) => [3, index];
const accountData = (account: number, index: number, length: number) => [4, account, index, length];

/** A validation account: one type-length-value entry of type `Execute` holding a count and 35-byte entries. */
function validationData(entries: Entry[], type = EXECUTE): Uint8Array {
  const body = entries.flatMap((e) => {
    const config = new Uint8Array(32);
    config.set(e.config);
    return [e.discriminator, ...config, e.signer ? 1 : 0, e.writable ? 1 : 0];
  });
  const u32 = (n: number) => [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
  return Uint8Array.from([...type, ...u32(4 + body.length), ...u32(entries.length), ...body]);
}

/** A token account's first 72 bytes are enough here: mint, owner, amount. */
function tokenAccountData(mint: PublicKey, owner: PublicKey, amount: bigint): Uint8Array {
  const d = Buffer.alloc(165);
  d.set(mint.toBytes(), 0);
  d.set(owner.toBytes(), 32);
  d.writeBigUInt64LE(amount, 64);
  d[108] = 1;
  return d;
}

/** A chain of accounts given whole; counts what is read. */
class Chain {
  accounts = new Map<string, { data: Uint8Array; owner: PublicKey }>();
  reads: string[] = [];
  set(address: PublicKey, data: Uint8Array, owner: PublicKey): void {
    this.accounts.set(address.toBase58(), { data, owner });
  }
  async getAccountInfo(address: PublicKey): Promise<AccountInfo<Buffer> | null> {
    this.reads.push(address.toBase58());
    const a = this.accounts.get(address.toBase58());
    return a ? { data: Buffer.from(a.data), owner: a.owner, executable: false, lamports: 1 } : null;
  }
}

/** A hook mint with `entries` as its list, and a transfer of it out of a vault. */
function hooked(entries: Entry[] | null) {
  const chain = new Chain();
  const hookProgram = key();
  const mint = key();
  const vault = key();
  const transfer: HookedTransfer = { mint, source: key(), destination: key(), authority: vault, amount: 250_000n };
  chain.set(mint, mintData([hookExtension(hookProgram)]), TOKEN_2022_PROGRAM_ID);
  chain.set(transfer.source, tokenAccountData(mint, vault, 1_000_000n), TOKEN_2022_PROGRAM_ID);
  chain.set(transfer.destination, tokenAccountData(mint, key(), 0n), TOKEN_2022_PROGRAM_ID);
  const validation = extraAccountMetasAddress(mint, hookProgram);
  if (entries) chain.set(validation, validationData(entries), hookProgram);
  return { chain, hookProgram, mint, vault, transfer, validation };
}

/** What `@solana/spl-token` appends to a `transfer_checked` for the same transfer: the list's accounts, then the hook program, then the validation account. */
async function reference(chain: Chain, hookProgram: PublicKey, t: HookedTransfer): Promise<AccountMeta[]> {
  const ix = createTransferCheckedInstruction(t.source, t.mint, t.destination, t.authority, t.amount, 6, [], TOKEN_2022_PROGRAM_ID);
  await addExtraAccountMetasForExecute(chain as unknown as Connection, ix, hookProgram, t.source, t.mint, t.destination, t.authority, t.amount);
  return ix.keys.slice(4);
}

const show = (metas: AccountMeta[]) => metas.map((m) => `${m.pubkey.toBase58()} ${m.isSigner ? "s" : "-"}${m.isWritable ? "w" : "-"}`);

describe("transferHookProgramId", () => {
  it("finds the hook program of a Token-2022 mint, as @solana/spl-token does", () => {
    const program = key();
    const data = mintData([hookExtension(program)]);
    expect(transferHookProgramId(data)!.equals(program)).toBe(true);
    const mint = unpackMint(key(), { data: Buffer.from(data), owner: TOKEN_2022_PROGRAM_ID, executable: false, lamports: 1 }, TOKEN_2022_PROGRAM_ID);
    expect(getTransferHook(mint)!.programId.equals(program)).toBe(true);
  });

  it("is null without a hook: a plain mint, other extensions only, an extension that names no program, a token account", () => {
    expect(transferHookProgramId(mintData([]))).toBeNull();
    expect(transferHookProgramId(mintData([[3, new Array(32).fill(7)]]))).toBeNull(); // mint close authority
    expect(transferHookProgramId(mintData([hookExtension(null)]))).toBeNull();
    const account = mintData([hookExtension(key())]);
    account[165] = 2; // account type: token account
    expect(transferHookProgramId(account)).toBeNull();
    expect(transferHookProgramId(new Uint8Array(0))).toBeNull();
  });

  it("steps over extensions it does not know, so a later one in front of the hook does not hide it", () => {
    const program = key();
    const data = mintData([
      [3, new Array(32).fill(7)],
      [0x7777, [1, 2, 3, 4, 5]], // no such extension today
      hookExtension(program),
    ]);
    expect(transferHookProgramId(data)!.equals(program)).toBe(true);
  });

  it("stops at the first unwritten entry and refuses one that runs past the account", () => {
    const data = mintData([[0, []], hookExtension(key())]);
    expect(transferHookProgramId(data)).toBeNull();
    const cut = mintData([hookExtension(key())]).slice(0, 200);
    expect(() => transferHookProgramId(cut)).toThrow(/past the end/);
  });
});

describe("resolveTransferHookAccounts", () => {
  const stranger = key();
  const other = key();
  // each list is resolved here and by @solana/spl-token; the accounts and their writable flags must agree
  const lists: [string, Entry[]][] = [
    ["an address of the hook program from a literal and the mint's key, writable", [pda([literal(text("counter")), accountKey(1)], { writable: true })]],
    ["fixed addresses, read-only and writable", [fixed(stranger), fixed(other, { writable: true })]],
    ["an address derived from the amount", [pda([literal(text("by-amount")), ixData(8, 8)])]],
    ["an address derived from the destination's owner (account data)", [pda([accountData(2, 32, 32)], { writable: true })]],
    ["an address read out of the source account's data: its owner", [readKey([2, 0, 32])]],
    ["an address of another program on the list", [fixed(stranger), pda([literal(text("theirs")), accountKey(0)], {}, 5)]],
    ["an address derived from an earlier entry's key", [fixed(stranger), pda([accountKey(5), accountKey(3)], { writable: true })]],
    ["the mint, read out of the source account and asked for writable: a hook gets the transfer's own accounts read-only", [readKey([2, 0, 0], { writable: true })]],
    ["the same address twice, read-only first: the second stays read-only", [fixed(stranger), fixed(stranger, { writable: true })]],
    ["the same address twice, writable first", [fixed(stranger, { writable: true }), fixed(stranger)]],
    ["an empty list", []],
  ];

  for (const [name, entries] of lists) {
    it(`agrees with @solana/spl-token: ${name}`, async () => {
      const { chain, hookProgram, transfer, validation } = hooked(entries);
      const got = await resolveTransferHookAccounts(chain, hookProgram, transfer);
      const want = await reference(chain, hookProgram, transfer);
      // the list's accounts, in the list's order
      expect(show(got.slice(0, -2))).toEqual(show(want.slice(0, -2)));
      expect(got.length).toBe(entries.length + 2);
      // then the validation account and the hook program (the reference has them the other way round; the token program looks them up by address)
      expect(show(got.slice(-2))).toEqual(show([
        { pubkey: validation, isSigner: false, isWritable: false },
        { pubkey: hookProgram, isSigner: false, isWritable: false },
      ]));
      expect(show(want.slice(-2)).sort()).toEqual(show(got.slice(-2)).sort());
      expect(got.every((m) => !m.isSigner)).toBe(true);
    });
  }

  it("the mint listed as writable comes back read-only, and an address from the amount changes with it", async () => {
    const { chain, hookProgram, transfer, mint } = hooked([fixed(key()), pda([literal(text("by-amount")), ixData(8, 8)])]);
    chain.set(extraAccountMetasAddress(mint, hookProgram), validationData([fixed(mint, { writable: true }), pda([literal(text("by-amount")), ixData(8, 8)])]), hookProgram);
    const a = await resolveTransferHookAccounts(chain, hookProgram, transfer);
    expect(a[0]).toEqual({ pubkey: mint, isSigner: false, isWritable: false });
    expect(show(a.slice(0, 2))).toEqual(show((await reference(chain, hookProgram, transfer)).slice(0, 2)));
    const b = await resolveTransferHookAccounts(chain, hookProgram, { ...transfer, amount: transfer.amount + 1n });
    expect(b[1]!.pubkey.equals(a[1]!.pubkey)).toBe(false);
  });

  it("never returns a signer, where @solana/spl-token would", async () => {
    const wanted = key();
    const { chain, hookProgram, transfer } = hooked([fixed(wanted, { signer: true, writable: true }), pda([literal(text("signer-pda"))], { signer: true })]);
    const want = await reference(chain, hookProgram, transfer);
    expect(want.slice(0, 2).map((m) => m.isSigner)).toEqual([true, true]);
    const got = await resolveTransferHookAccounts(chain, hookProgram, transfer);
    expect(got.map((m) => m.isSigner)).toEqual([false, false, false, false]);
    // the same accounts, writable as the list says
    expect(got.slice(0, 2).map((m) => [m.pubkey.toBase58(), m.isWritable])).toEqual(want.slice(0, 2).map((m) => [m.pubkey.toBase58(), m.isWritable]));
  });

  it("refuses a list that names a signer of the transaction, whether or not it asks for the signature", async () => {
    const payer = key();
    const second = key();
    for (const entry of [fixed(payer, { signer: true, writable: true }), fixed(payer), fixed(payer, { writable: true })]) {
      const { chain, hookProgram, transfer } = hooked([pda([literal(text("counter")), accountKey(1)], { writable: true }), entry]);
      await expect(resolveTransferHookAccounts(chain, hookProgram, transfer, { signers: [payer] })).rejects.toThrow(/signs this transaction/);
      await expect(resolveTransferHookAccounts(chain, hookProgram, transfer, { signers: [second, payer] })).rejects.toThrow(new RegExp(payer.toBase58()));
      // told of no signers, it has nothing to refuse, and still returns the key unsigned
      const got = await resolveTransferHookAccounts(chain, hookProgram, transfer);
      expect(got[1]).toEqual({ pubkey: payer, isSigner: false, isWritable: entry.writable === true });
      // a key that does not sign is no reason either
      expect((await resolveTransferHookAccounts(chain, hookProgram, transfer, { signers: [second] })).length).toBe(4);
    }
    // an address read from account data that turns out to be the payer's: the owner of the destination
    const { chain, hookProgram, transfer, mint } = hooked([readKey([2, 2, 32])]);
    chain.set(transfer.destination, tokenAccountData(mint, payer, 0n), TOKEN_2022_PROGRAM_ID);
    await expect(resolveTransferHookAccounts(chain, hookProgram, transfer, { signers: [payer] })).rejects.toThrow(/signs this transaction/);
  });

  it("a hook with no validation account gets its program alone", async () => {
    const { chain, hookProgram, transfer } = hooked(null);
    expect(await resolveTransferHookAccounts(chain, hookProgram, transfer)).toEqual([{ pubkey: hookProgram, isSigner: false, isWritable: false }]);
  });

  it("says what is wrong with a list it cannot resolve", async () => {
    const cases: [Entry[], RegExp][] = [
      [[pda([accountData(5, 0, 8)])], /account 5, and only 5 come before/],
      [[pda([accountKey(9)])], /account 9/],
      [[pda([literal(text("x"))], {}, 7)], /account 7/],
      [[fixed(key()), pda([accountData(5, 0, 8)])], /does not exist yet/],
      [[pda([accountData(0, 160, 32)])], /reads 32 bytes at 160 of 165/],
      [[readKey([1, 0])], /reads 32 bytes at 0 of 16/],
      [[readKey([7])], /unknown address source 7/],
      [[{ discriminator: 5, config: [] }], /unknown kind 5/],
      [[pda([[9, 1, 2]])], /unknown seed kind 9/],
    ];
    for (const [entries, message] of cases) {
      const { chain, hookProgram, transfer } = hooked(entries);
      await expect(resolveTransferHookAccounts(chain, hookProgram, transfer)).rejects.toThrow(message);
    }
    const { chain, hookProgram, transfer, validation } = hooked([]);
    chain.set(validation, validationData([], [1, 2, 3, 4, 5, 6, 7, 8]), hookProgram);
    await expect(resolveTransferHookAccounts(chain, hookProgram, transfer)).rejects.toThrow(/no list for Execute/);
    chain.set(validation, new Uint8Array(0), hookProgram);
    await expect(resolveTransferHookAccounts(chain, hookProgram, transfer)).rejects.toThrow(/no list for Execute/);
    await expect(resolveTransferHookAccounts(chain, hookProgram, { ...transfer, amount: 1n << 64n })).rejects.toThrow(RangeError);
  });

  it("decodes a list after other entries in the validation account", () => {
    const k = key();
    const first = validationData([fixed(key())], [9, 9, 9, 9, 9, 9, 9, 9]);
    const second = validationData([fixed(k, { signer: true, writable: true })]);
    const metas = decodeExtraAccountMetas(Uint8Array.from([...first, ...second]));
    expect(metas.map((m) => ({ ...m, addressConfig: [...m.addressConfig] }))).toEqual([{ discriminator: 0, addressConfig: [...k.toBytes()], isSigner: true, isWritable: true }]);
    expect(extraAccountMetasAddress(k, SystemProgram.programId).equals(getExtraAccountMetaAddress(k, SystemProgram.programId))).toBe(true);
  });
});

describe("transferHookAccounts", () => {
  it("is empty, after one read, for a mint that is not Token-2022's, has no hook, or does not exist", async () => {
    const chain = new Chain();
    const transfer: HookedTransfer = { mint: key(), source: key(), destination: key(), authority: key(), amount: 1n };
    expect(await transferHookAccounts(chain, transfer)).toEqual([]);
    chain.set(transfer.mint, mintData([]), TOKEN_PROGRAM_ID);
    expect(await transferHookAccounts(chain, transfer)).toEqual([]);
    chain.set(transfer.mint, mintData([hookExtension(key())]), TOKEN_PROGRAM_ID); // the bytes of a hook, under the wrong program
    expect(await transferHookAccounts(chain, transfer)).toEqual([]);
    chain.set(transfer.mint, mintData([hookExtension(null)]), TOKEN_2022_PROGRAM_ID);
    expect(await transferHookAccounts(chain, transfer)).toEqual([]);
    expect(chain.reads).toEqual(new Array(4).fill(transfer.mint.toBase58()));
  });

  it("resolves the hook of a Token-2022 mint that has one", async () => {
    const { chain, hookProgram, transfer, validation, mint } = hooked([pda([literal(text("counter")), accountKey(1)], { writable: true })]);
    const counter = PublicKey.findProgramAddressSync([Buffer.from("counter"), mint.toBytes()], hookProgram)[0];
    expect(show(await transferHookAccounts(chain, transfer))).toEqual(show([
      { pubkey: counter, isSigner: false, isWritable: true },
      { pubkey: validation, isSigner: false, isWritable: false },
      { pubkey: hookProgram, isSigner: false, isWritable: false },
    ]));
  });
});

describe("the builders add a hook's accounts unsigned", () => {
  const vault = key();
  const payer = key();
  const mint = key();
  const to = key();
  // what a careless caller might pass: the list's flags as they stand, a signer among them
  const extra: AccountMeta[] = [
    { pubkey: key(), isSigner: false, isWritable: true },
    { pubkey: payer, isSigner: true, isWritable: true },
    { pubkey: key(), isSigner: true, isWritable: false },
  ];
  const unsigned = extra.map((m) => ({ ...m, isSigner: false }));
  const action = { kind: "TransferToken" as const, mint, to, amount: 5n, issuedSlot: 0n, expirySlot: 1n };

  it("execute and execute_direct: after the four token accounts", () => {
    const keys = executeRemainingAccounts(vault, action, TOKEN_2022_PROGRAM_ID, [], undefined, extra);
    expect(keys.length).toBe(7);
    expect(keys.slice(4)).toEqual(unsigned);
    const from = key();
    const bound = executeRemainingAccounts(vault, { ...action, kind: "TransferTokenFrom", from }, TOKEN_2022_PROGRAM_ID, [], undefined, extra);
    expect(bound.slice(4)).toEqual(unsigned);
    const direct = executeDirectInstruction({ programId: LAMPORT_VAULT_PROGRAM_ID, vault, payer, action, signature: new Uint8Array(2348), tokenProgram: TOKEN_2022_PROGRAM_ID, extraAccounts: extra });
    expect(direct.keys.slice(7)).toEqual(unsigned);
    // the payer signs as the instruction's own payer, and only there
    expect(direct.keys.filter((k) => k.isSigner).map((k) => k.pubkey.toBase58())).toEqual([payer.toBase58()]);
    expect(direct.keys.findIndex((k) => k.isSigner)).toBe(1);
  });

  it("the staged execution carries them in its execute, and only there", () => {
    const staged = buildStagedExecution({ programId: LAMPORT_VAULT_PROGRAM_ID, vault, payer, nonce: 1n, action, signature: new Uint8Array(2348), tokenProgram: TOKEN_2022_PROGRAM_ID, extraAccounts: extra });
    const execute = staged.execute[1]!;
    expect(execute.keys.slice(7)).toEqual(unsigned);
    expect(execute.keys.some((k) => k.isSigner)).toBe(false);
    expect(staged.open.keys.length).toBe(4);
    const without = buildStagedExecution({ programId: LAMPORT_VAULT_PROGRAM_ID, vault, payer, nonce: 1n, action, signature: new Uint8Array(2348), tokenProgram: TOKEN_2022_PROGRAM_ID });
    expect(without.execute[1]!.keys.length).toBe(7);
  });

  it("sweep_closed: after its nine accounts", () => {
    const { instruction } = sweepClosedInstruction({ programId: LAMPORT_VAULT_PROGRAM_ID, payer, vault, heir: key(), mint, vaultTokenAccount: key(), tokenProgram: TOKEN_2022_PROGRAM_ID, extraAccounts: extra });
    expect(instruction.keys.slice(9)).toEqual(unsigned);
    expect(instruction.keys.filter((k) => k.isSigner).length).toBe(1);
    expect(instruction.keys[0]).toEqual({ pubkey: payer, isSigner: true, isWritable: true });
  });
});

// ---- the two clients that send transactions ----

const lmsKey = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H5, lmotsType: 3, seed: fromHex("784bd340367baa20a90c48bf5623171cba34eb7b4022f11ecca2cc1a893cb506"), I: fromHex("00112233445566778899aabbccddeeff") });
const vaultAddress = findVaultPdaForKey(LAMPORT_VAULT_PROGRAM_ID, lmsKey.publicKey).address;
const liveVault = () => encodeVault({ version: 2, bump: 0, vaultId: vaultId(lmsKey.publicKey), lmsPubkey: lmsKey.publicKey, spent: 0, generation: 0, createdSlot: 1n, used: new Uint8Array(4), usedKeys: [] });

/** A hook mint on the mock chain: the mint with its extension, and the hook's validation account. */
function hookMint(rpc: MockChain, entries: Entry[]) {
  const mint = key();
  const hookProgram = key();
  rpc.mints.set(mint.toBase58(), TOKEN_2022_PROGRAM_ID);
  rpc.raw.set(mint.toBase58(), { data: mintData([hookExtension(hookProgram)]), owner: TOKEN_2022_PROGRAM_ID });
  const validation = extraAccountMetasAddress(mint, hookProgram);
  rpc.raw.set(validation.toBase58(), { data: validationData(entries), owner: hookProgram });
  return { mint, hookProgram, validation };
}

const counterOf = (mint: PublicKey, hookProgram: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from("counter"), mint.toBytes()], hookProgram)[0];
const byAmount = (amount: bigint, hookProgram: PublicKey) => {
  const le = Buffer.alloc(8);
  le.writeBigUInt64LE(amount);
  return PublicKey.findProgramAddressSync([Buffer.from("by-amount"), le], hookProgram)[0];
};
const theList = [pda([literal(text("counter")), accountKey(1)], { writable: true }), pda([literal(text("by-amount")), ixData(8, 8)])];

describe("sweepClosed with a transfer hook", () => {
  const heir = key();
  const tombstone = () => encodeTombstone({ version: TOMBSTONE_ACCOUNT_VERSION, vaultId: vaultId(lmsKey.publicKey), closedSlot: 5n, heir });

  it("gives each sweep the hook's accounts for that account's balance, and none to an empty account", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const { mint, hookProgram, validation } = hookMint(rpc, theList);
    rpc.accounts.set(vaultAddress.toBase58(), tombstone());
    const ata = associatedTokenAddress(vaultAddress, mint, TOKEN_2022_PROGRAM_ID);
    const stray = key();
    const empty = key();
    rpc.tokenAccounts.set(ata.toBase58(), { owner: vaultAddress, mint, amount: 700n });
    rpc.tokenAccounts.set(stray.toBase58(), { owner: vaultAddress, mint, amount: 300n });
    rpc.tokenAccounts.set(empty.toBase58(), { owner: vaultAddress, mint, amount: 0n });
    const res = await sweepClosed(rpc, payer, vaultAddress, mint);
    expect(res.swept.length).toBe(3);
    for (const [i, amount] of [700n, 300n].entries()) {
      const keys = rpc.sent[i]!.instructions[0]!.keys;
      expect(keys.length).toBe(13);
      expect(keys[6]!.pubkey.equals(TOKEN_2022_PROGRAM_ID)).toBe(true);
      expect(show(keys.slice(9))).toEqual(show([
        { pubkey: counterOf(mint, hookProgram), isSigner: false, isWritable: true },
        { pubkey: byAmount(amount, hookProgram), isSigner: false, isWritable: false },
        { pubkey: validation, isSigner: false, isWritable: false },
        { pubkey: hookProgram, isSigner: false, isWritable: false },
      ]));
      expect(keys.filter((k) => k.isSigner).map((k) => k.pubkey.toBase58())).toEqual([payer.publicKey.toBase58()]);
    }
    expect(rpc.sent[2]!.instructions[0]!.keys.length).toBe(9); // nothing to transfer: the program only closes it
    expect(rpc.tokenAccounts.get(res.heirTokenAccount.toBase58())!.amount).toBe(1000n);
  });

  it("refuses, before sending anything, a hook whose list names the payer", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const { mint } = hookMint(rpc, [...theList, fixed(payer.publicKey, { signer: true, writable: true })]);
    rpc.accounts.set(vaultAddress.toBase58(), tombstone());
    const ata = associatedTokenAddress(vaultAddress, mint, TOKEN_2022_PROGRAM_ID);
    rpc.tokenAccounts.set(ata.toBase58(), { owner: vaultAddress, mint, amount: 700n });
    await expect(sweepClosed(rpc, payer, vaultAddress, mint)).rejects.toThrow(/signs this transaction/);
    expect(rpc.sent.length).toBe(0);
    expect(rpc.tokenAccounts.get(ata.toBase58())!.amount).toBe(700n);
    // somebody else can sweep it: the list does not name them
    const other = Keypair.generate();
    const res = await sweepClosed(rpc, other, vaultAddress, mint);
    expect(res.swept.length).toBe(1);
    const keys = rpc.sent[0]!.instructions[0]!.keys;
    expect(keys.find((k) => k.pubkey.equals(payer.publicKey))).toEqual({ pubkey: payer.publicKey, isSigner: false, isWritable: true });
    expect(keys.filter((k) => k.isSigner).map((k) => k.pubkey.toBase58())).toEqual([other.publicKey.toBase58()]);
  });

  it("leaves a mint without a hook exactly as it was: nine accounts", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const mint = key();
    rpc.mints.set(mint.toBase58(), TOKEN_2022_PROGRAM_ID);
    rpc.accounts.set(vaultAddress.toBase58(), tombstone());
    const ata = associatedTokenAddress(vaultAddress, mint, TOKEN_2022_PROGRAM_ID);
    rpc.tokenAccounts.set(ata.toBase58(), { owner: vaultAddress, mint, amount: 5n });
    await sweepClosed(rpc, payer, vaultAddress, mint);
    const want = sweepClosedInstruction({ programId: LAMPORT_VAULT_PROGRAM_ID, payer: payer.publicKey, vault: vaultAddress, heir, mint, vaultTokenAccount: ata, tokenProgram: TOKEN_2022_PROGRAM_ID }).instruction;
    expect(rpc.sent[0]!.instructions[0]!.keys).toEqual(want.keys);
    expect(want.keys.length).toBe(9);
  });
});

describe("VaultSigner with a transfer hook", () => {
  const executeOf = (rpc: MockChain) => rpc.sent.flatMap((tx) => tx.instructions).find((ix) => Buffer.from(ix.data.subarray(0, 8)).equals(Buffer.from(IX.execute)))!;

  it("a Token-2022 signer resolves the hook's accounts and puts them behind the four", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const { mint, hookProgram, validation } = hookMint(rpc, theList);
    rpc.accounts.set(vaultAddress.toBase58(), liveVault());
    const signer = new VaultSigner({ rpc, key: lmsKey, payer, adoptChainState: true, journal: "ephemeral", tokenProgram: TOKEN_2022_PROGRAM_ID });
    const to = key();
    await signer.execute({ kind: "TransferToken", mint, to, amount: 42n });
    const keys = executeOf(rpc).keys;
    expect(keys[3]!.pubkey.equals(associatedTokenAddress(vaultAddress, mint, TOKEN_2022_PROGRAM_ID))).toBe(true);
    expect(show(keys.slice(7))).toEqual(show([
      { pubkey: counterOf(mint, hookProgram), isSigner: false, isWritable: true },
      { pubkey: byAmount(42n, hookProgram), isSigner: false, isWritable: false },
      { pubkey: validation, isSigner: false, isWritable: false },
      { pubkey: hookProgram, isSigner: false, isWritable: false },
    ]));
    // TransferTokenFrom: the same, for the source the action names
    const from = key();
    await signer.execute({ kind: "TransferTokenFrom", from, mint, to, amount: 43n });
    const again = rpc.sent.flatMap((tx) => tx.instructions).filter((ix) => Buffer.from(ix.data.subarray(0, 8)).equals(Buffer.from(IX.execute)))[1]!;
    expect(again.keys[3]!.pubkey.equals(from)).toBe(true);
    expect(again.keys[8]!.pubkey.equals(byAmount(43n, hookProgram))).toBe(true);
  });

  it("refuses a hook whose list names the payer before a leaf is spent or anything is sent", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const { mint } = hookMint(rpc, [...theList, fixed(payer.publicKey, { signer: true, writable: true })]);
    rpc.accounts.set(vaultAddress.toBase58(), liveVault());
    const signer = new VaultSigner({ rpc, key: lmsKey, payer, adoptChainState: true, journal: "ephemeral", tokenProgram: TOKEN_2022_PROGRAM_ID });
    await expect(signer.execute({ kind: "TransferToken", mint, to: key(), amount: 42n })).rejects.toThrow(/signs this transaction/);
    expect(rpc.sent.length).toBe(0);
    expect(await signer.nextQ()).toBe(0);
    // Accounts given by the caller are used instead, and nothing is resolved. They go in unsigned
    // whatever the caller marked: this key signs nothing, and the transaction does not ask it to.
    const given = [{ pubkey: key(), isSigner: true, isWritable: true }];
    await signer.execute({ kind: "TransferToken", mint, to: key(), amount: 42n }, { extraAccounts: given });
    expect(executeOf(rpc).keys.slice(7)).toEqual([{ ...given[0]!, isSigner: false }]);
    // (read back off the wire, the fee payer is a signer wherever it appears: the reason it is never added for a hook)
    expect(executeOf(rpc).keys.filter((k) => k.isSigner).map((k) => k.pubkey.toBase58())).toEqual([payer.publicKey.toBase58()]);
  });

  it("adds nothing for a mint under the Token program, whatever its bytes say", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const { mint } = hookMint(rpc, theList);
    rpc.accounts.set(vaultAddress.toBase58(), liveVault());
    const signer = new VaultSigner({ rpc, key: lmsKey, payer, adoptChainState: true, journal: "ephemeral" });
    await signer.execute({ kind: "TransferToken", mint, to: key(), amount: 42n });
    expect(executeOf(rpc).keys.length).toBe(7);
  });

  it("adds nothing for a Token-2022 mint without a hook, and nothing for an action that moves no token", async () => {
    const rpc = new MockChain();
    const payer = Keypair.generate();
    const plain = key();
    rpc.mints.set(plain.toBase58(), TOKEN_2022_PROGRAM_ID);
    rpc.accounts.set(vaultAddress.toBase58(), liveVault());
    const signer = new VaultSigner({ rpc, key: lmsKey, payer, adoptChainState: true, journal: "ephemeral", tokenProgram: TOKEN_2022_PROGRAM_ID });
    await signer.execute({ kind: "TransferToken", mint: plain, to: key(), amount: 1n });
    expect(executeOf(rpc).keys.length).toBe(7);
    const to = key();
    await signer.execute({ kind: "TransferSol", to, lamports: 1n });
    const sol = rpc.sent.flatMap((tx) => tx.instructions).filter((ix) => Buffer.from(ix.data.subarray(0, 8)).equals(Buffer.from(IX.execute)))[1]!;
    expect(sol.keys.map((k) => k.pubkey.toBase58()).slice(3)).toEqual([to.toBase58()]);
  });
});
