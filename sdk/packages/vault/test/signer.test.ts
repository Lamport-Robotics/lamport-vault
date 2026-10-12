/**
 * VaultSigner / RegistryClient against a mock RPC: no cluster. The mock records every transaction,
 * decodes the instructions and reassembles the staged signature so we can check it verifies.
 */
import { Connection, Keypair, PublicKey, Transaction, type AccountInfo } from "@solana/web3.js";
import { fromHex, LMS_SHA256_M32_H5, LmsPrivateKey, lmsVerify, toHex } from "@lamport-robotics/lms";
import { describe, expect, it } from "vitest";
import { encodeCommitment, encodeVault, usedKeyHash, type VaultAccount } from "../src/accounts.ts";
import { decodeAction } from "../src/action.ts";
import { IX } from "../src/discriminator.ts";
import { registryMessage, vaultMessage } from "../src/message.ts";
import { findCommitmentPda, findVaultPdaForKey, vaultId } from "../src/pda.ts";
import { LAMPORT_VAULT_PROGRAM_ID, PQ_REGISTRY_PROGRAM_ID } from "../src/programIds.ts";
import { RegistryClient, type Rpc, VaultSigner } from "../src/signer.ts";

class MockRpc implements Rpc {
  accounts = new Map<string, Uint8Array>();
  sent: Transaction[] = [];
  slot = 1000;
  failAt: number | null = null;

  async getAccountInfo(pk: PublicKey): Promise<AccountInfo<Buffer> | null> {
    const data = this.accounts.get(pk.toBase58());
    if (!data) return null;
    return { data: Buffer.from(data), executable: false, lamports: 1, owner: LAMPORT_VAULT_PROGRAM_ID };
  }
  async getLatestBlockhash() {
    return { blockhash: Keypair.generate().publicKey.toBase58(), lastValidBlockHeight: 10 };
  }
  async sendRawTransaction(raw: Buffer | Uint8Array | number[]): Promise<string> {
    const tx = Transaction.from(Buffer.from(raw as Uint8Array));
    if (!tx.verifySignatures()) throw new Error("bad signature");
    this.sent.push(tx);
    return "sig" + this.sent.length;
  }
  async confirmTransaction(strategy: { signature: string }) {
    const idx = Number(strategy.signature.slice(3)) - 1;
    return { value: { err: this.failAt === idx ? { InstructionError: [0, "Custom"] } : null } };
  }
  async getSlot(): Promise<number> {
    return this.slot;
  }
}

const KAT_SEED = fromHex("784bd340367baa20a90c48bf5623171cba34eb7b4022f11ecca2cc1a893cb506");
const KAT_I = fromHex("00112233445566778899aabbccddeeff");
const key = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H5, lmotsType: 3, seed: KAT_SEED, I: KAT_I });

/** An H5 vault for `key` with the given leaves already spent. */
function vaultAccount(spentLeaves: number[], extra: Partial<VaultAccount> = {}): Uint8Array {
  const used = new Uint8Array(4);
  for (const q of spentLeaves) used[q >> 3]! |= 1 << (q & 7);
  return encodeVault({
    version: 2,
    bump: 0,
    vaultId: vaultId(key.publicKey),
    lmsPubkey: key.publicKey,
    spent: spentLeaves.length,
    generation: 0,
    createdSlot: 1n,
    used,
    usedKeys: [],
    ...extra,
  });
}
const range = (n: number) => Array.from({ length: n }, (_, i) => i);

/** Reassemble the staged signature from an open (first_chunk) and write_sig instructions. */
function reassemble(txs: Transaction[], openDisc: Uint8Array, writeDisc: Uint8Array, openFixedLen: (d: Buffer) => number): { bytes: Buffer; offsets: number[] } {
  const parts: Buffer[] = [];
  const offsets: number[] = [];
  for (const tx of txs) {
    const ix = tx.instructions[0]!;
    const disc = toHex(ix.data.subarray(0, 8));
    if (disc === toHex(openDisc)) {
      const o = openFixedLen(ix.data);
      const len = ix.data.readUInt32LE(o);
      parts.push(ix.data.subarray(o + 4, o + 4 + len));
      offsets.push(0);
    } else if (disc === toHex(writeDisc)) {
      offsets.push(ix.data.readUInt16LE(8));
      const len = ix.data.readUInt32LE(10);
      parts.push(ix.data.subarray(14, 14 + len));
    }
  }
  return { bytes: Buffer.concat(parts), offsets };
}

describe("Rpc interface", () => {
  it("is satisfied by @solana/web3.js Connection", () => {
    const rpc: Rpc = new Connection("http://127.0.0.1:8899");
    expect(typeof rpc.getAccountInfo).toBe("function");
  });
});

describe("VaultSigner", () => {
  it("reads next_q, signs with it, stages (first chunk in open, rest in write_sig) and executes", async () => {
    const rpc = new MockRpc();
    const payer = Keypair.generate();
    const vault = findVaultPdaForKey(LAMPORT_VAULT_PROGRAM_ID, key.publicKey).address;
    rpc.accounts.set(vault.toBase58(), vaultAccount(range(5)));
    const signer = new VaultSigner({ rpc, key, payer });
    expect(signer.programId.equals(LAMPORT_VAULT_PROGRAM_ID)).toBe(true);
    expect(signer.vault.equals(vault)).toBe(true);
    expect(await signer.nextQ()).toBe(5);

    const to = Keypair.generate().publicKey;
    const seen: number[] = [];
    const res = await signer.execute({ kind: "TransferSol", to, lamports: 1_000_000n }, { nonce: 42n, onTransaction: (i) => seen.push(i) });

    expect(res.q).toBe(5);
    expect(res.signatures).toEqual(["sig1", "sig2", "sig3", "sig4"]); // open(+chunk), write, write, execute
    expect(seen).toEqual([0, 1, 2, 3]);
    expect(res.action.expirySlot).toBe(1300n); // slot 1000 + default 300
    expect(res.generation).toBe(0);
    expect(toHex(res.message)).toBe(toHex(vaultMessage(vault, 0, res.actionBytes)));
    expect(lmsVerify(key.publicKey, res.message, res.lmsSignature)).toBe(true);

    // open: discriminator, nonce, action, sig_len, first_chunk
    const open = rpc.sent[0]!.instructions[0]!;
    expect(toHex(open.data.subarray(0, 8))).toBe(toHex(IX.openSigBuffer));
    expect(open.data.readBigUInt64LE(8)).toBe(42n);
    const actionLen = open.data.readUInt32LE(16);
    const action = decodeAction(new Uint8Array(open.data.subarray(20, 20 + actionLen)));
    expect(action.kind).toBe("TransferSol");
    if (action.kind === "TransferSol") expect(action.to.equals(to)).toBe(true);
    expect(open.data.readUInt16LE(20 + actionLen)).toBe(2348);
    expect(open.keys[2]!.pubkey.equals(res.sigBuffer)).toBe(true);

    const { bytes, offsets } = reassemble(rpc.sent.slice(0, 3), IX.openSigBuffer, IX.writeSig, (d) => 20 + d.readUInt32LE(16) + 2);
    expect(toHex(bytes)).toBe(toHex(res.lmsSignature));
    expect(offsets[0]).toBe(0);
    expect(offsets[1]).toBe(open.data.readUInt32LE(20 + actionLen + 2));
    expect(offsets[2]).toBe(offsets[1]! + 900);

    // execute: compute budget then execute with vault, buffer, payer, to
    const exec = rpc.sent[3]!;
    expect(exec.instructions.length).toBe(2);
    expect(toHex(exec.instructions[1]!.data)).toBe(toHex(IX.execute));
    expect(exec.instructions[1]!.keys.map((k) => k.pubkey.toBase58())).toEqual([vault, res.sigBuffer, payer.publicKey, to].map((k) => k.toBase58()));
    for (const tx of rpc.sent) expect(tx.feePayer!.equals(payer.publicKey)).toBe(true);
  });

  it("firstChunkSize 0 falls back to three write_sig transactions", async () => {
    const rpc = new MockRpc();
    const payer = Keypair.generate();
    const signer = new VaultSigner({ rpc, key, payer, firstChunkSize: 0 });
    rpc.accounts.set(signer.vault.toBase58(), vaultAccount([]));
    const res = await signer.execute({ kind: "Close", to: payer.publicKey, expirySlot: 5n });
    expect(res.signatures.length).toBe(5);
    const { bytes } = reassemble(rpc.sent.slice(0, 4), IX.openSigBuffer, IX.writeSig, (d) => 20 + d.readUInt32LE(16) + 2);
    expect(toHex(bytes)).toBe(toHex(res.lmsSignature));
  });

  it("never reuses a leaf within a process even if the chain has not advanced", async () => {
    const rpc = new MockRpc();
    const payer = Keypair.generate();
    const signer = new VaultSigner({ rpc, key, payer });
    rpc.accounts.set(signer.vault.toBase58(), vaultAccount([]));
    const a = await signer.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n });
    const b = await signer.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n });
    expect(a.q).toBe(0);
    expect(b.q).toBe(1);
    expect(await signer.nextQ()).toBe(2);
    await expect(signer.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n }, { q: 1 })).rejects.toThrow(/already signed/);
  });

  it("skips spent leaves in any order (bitmap) and refuses a spent or out-of-range leaf", async () => {
    const rpc = new MockRpc();
    const payer = Keypair.generate();
    const signer = new VaultSigner({ rpc, key, payer });
    rpc.accounts.set(signer.vault.toBase58(), vaultAccount([0, 1, 2, 5, 9]));
    expect(await signer.nextQ()).toBe(3);
    await expect(signer.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n }, { q: 5 })).rejects.toThrow(/already spent/);
    await expect(signer.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n }, { q: 32 })).rejects.toThrow(/beyond/);
    const a = await signer.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n }, { q: 20 });
    expect(a.q).toBe(20);
    const b = await signer.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n });
    expect(b.q).toBe(3);
  });

  it("lanes: signer k of n only uses leaves q ≡ k (mod n)", async () => {
    const rpc = new MockRpc();
    const payer = Keypair.generate();
    const even = new VaultSigner({ rpc, key, payer, lane: 0, lanes: 2 });
    const odd = new VaultSigner({ rpc, key, payer, lane: 1, lanes: 2 });
    rpc.accounts.set(even.vault.toBase58(), vaultAccount([0, 3]));
    expect(await even.nextQ()).toBe(2);
    expect(await odd.nextQ()).toBe(1);
    const e1 = await even.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n });
    const o1 = await odd.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n });
    const e2 = await even.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n });
    const o2 = await odd.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n });
    expect([e1.q, o1.q, e2.q, o2.q]).toEqual([2, 1, 4, 5]);
    expect(() => new VaultSigner({ rpc, key, payer, lane: 2, lanes: 2 })).toThrow(RangeError);
    // a lane with no leaf left
    rpc.accounts.set(even.vault.toBase58(), vaultAccount(range(32).filter((q) => q % 2 === 0)));
    expect(await even.nextQ()).toBeUndefined();
    await expect(even.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n })).rejects.toThrow(/no free leaf/);
    expect(await odd.nextQ()).toBe(3); // 1 and 5 are reserved by this odd signer
  });

  it("calls reserve(q) before signing and signs nothing if it throws", async () => {
    const rpc = new MockRpc();
    const payer = Keypair.generate();
    const store = new Set<number>([4]); // "persisted" from an earlier run that crashed after signing q=4
    const order: string[] = [];
    const signer = new VaultSigner({
      rpc,
      key: {
        ...key,
        publicKey: key.publicKey,
        sign: (q: number, m: Uint8Array, o?: { C?: Uint8Array }) => {
          order.push(`sign ${q}`);
          return key.sign(q, m, o);
        },
      } as unknown as LmsPrivateKey,
      payer,
      reserve: async (q) => {
        order.push(`reserve ${q}`);
        if (store.has(q)) throw new Error(`leaf ${q} was reserved before`);
        store.add(q);
      },
    });
    rpc.accounts.set(signer.vault.toBase58(), vaultAccount([0, 1, 2, 3]));
    await expect(signer.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n })).rejects.toThrow(/reserved before/);
    expect(order).toEqual(["reserve 4"]);
    const ok = await signer.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n }, { q: 5 });
    expect(ok.q).toBe(5);
    expect(order).toEqual(["reserve 4", "reserve 5", "sign 5"]);
    expect([...store].sort()).toEqual([4, 5]);
  });

  it("enforces the exhaustion rule (last free leaf is Rotate only) and Rotate preconditions", async () => {
    const rpc = new MockRpc();
    const payer = Keypair.generate();
    const signer = new VaultSigner({ rpc, key, payer });
    rpc.accounts.set(signer.vault.toBase58(), vaultAccount(range(32).filter((q) => q !== 7)));
    expect(await signer.nextQ()).toBe(7);
    await expect(signer.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n })).rejects.toThrow(/Rotate/);
    await expect(signer.sign({ kind: "Rotate", newLmsPubkey: key.publicKey, expirySlot: 1n })).rejects.toThrow(/used before/);
    const h10 = LmsPrivateKey.generate({ lmsType: 6, lmotsType: 3, seed: new Uint8Array(32).fill(4), I: KAT_I });
    await expect(signer.sign({ kind: "Rotate", newLmsPubkey: h10.publicKey, expirySlot: 1n })).rejects.toThrow(/typecodes/);
    const next = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H5, lmotsType: 3, seed: new Uint8Array(32).fill(5), I: KAT_I });
    const rot = await signer.sign({ kind: "Rotate", newLmsPubkey: next.publicKey, expirySlot: 1n });
    expect(rot.q).toBe(7);
    expect(lmsVerify(key.publicKey, rot.message, rot.lmsSignature)).toBe(true);
    // a past key is refused too
    rpc.accounts.set(signer.vault.toBase58(), vaultAccount([], { generation: 1, usedKeys: [usedKeyHash(next.publicKey)] }));
    await expect(signer.sign({ kind: "Rotate", newLmsPubkey: next.publicKey, expirySlot: 1n })).rejects.toThrow(/used before/);
  });

  it("binds the message to the vault's generation", async () => {
    const rpc = new MockRpc();
    const payer = Keypair.generate();
    const signer = new VaultSigner({ rpc, key, payer });
    rpc.accounts.set(signer.vault.toBase58(), vaultAccount([], { generation: 3 }));
    const res = await signer.sign({ kind: "Close", to: payer.publicKey, expirySlot: 1n });
    expect(res.generation).toBe(3);
    expect(toHex(res.message)).toBe(toHex(vaultMessage(signer.vault, 3, res.actionBytes)));
    expect(toHex(res.message)).not.toBe(toHex(vaultMessage(signer.vault, 2, res.actionBytes)));
  });

  it("refuses to sign for a vault whose key has rotated away, or that does not exist", async () => {
    const rpc = new MockRpc();
    const payer = Keypair.generate();
    const signer = new VaultSigner({ rpc, key, payer });
    await expect(signer.nextQ()).rejects.toThrow(/does not exist/);
    const other = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H5, lmotsType: 3, seed: new Uint8Array(32).fill(9), I: KAT_I });
    rpc.accounts.set(
      signer.vault.toBase58(),
      encodeVault({
        version: 2,
        bump: 0,
        vaultId: vaultId(key.publicKey),
        lmsPubkey: other.publicKey,
        spent: 0,
        generation: 1,
        createdSlot: 1n,
        used: new Uint8Array(4),
        usedKeys: [usedKeyHash(key.publicKey)],
      }),
    );
    await expect(signer.nextQ()).rejects.toThrow(/not this key/);
  });

  it("surfaces a failed transaction and stops the sequence", async () => {
    const rpc = new MockRpc();
    rpc.failAt = 1;
    const payer = Keypair.generate();
    const signer = new VaultSigner({ rpc, key, payer });
    rpc.accounts.set(signer.vault.toBase58(), vaultAccount([]));
    await expect(signer.execute({ kind: "Close", to: payer.publicKey, expirySlot: 1n })).rejects.toThrow(/sig2 failed/);
    expect(rpc.sent.length).toBe(2);
  });

  it("createVault sends one create_vault transaction", async () => {
    const rpc = new MockRpc();
    const payer = Keypair.generate();
    const signer = new VaultSigner({ rpc, key, payer });
    const { vault, signature } = await signer.createVault();
    expect(signature).toBe("sig1");
    expect(vault.equals(signer.vault)).toBe(true);
    expect(toHex(rpc.sent[0]!.instructions[0]!.data)).toBe(toHex(IX.createVault) + toHex(vaultId(key.publicKey)) + toHex(key.publicKey));
  });
});

describe("RegistryClient", () => {
  it("commit signs with owner and payer; rotatePq stages an LMS signature over the registry message", async () => {
    const rpc = new MockRpc();
    const payer = Keypair.generate();
    const owner = Keypair.generate();
    const client = new RegistryClient({ rpc, payer });
    expect(client.programId.equals(PQ_REGISTRY_PROGRAM_ID)).toBe(true);

    const { commitment, signature } = await client.commit(owner, key.publicKey);
    expect(signature).toBe("sig1");
    expect(commitment.equals(findCommitmentPda(PQ_REGISTRY_PROGRAM_ID, owner.publicKey).address)).toBe(true);
    const tx = rpc.sent[0]!;
    expect(tx.signatures.map((s) => s.publicKey.toBase58()).sort()).toEqual([payer.publicKey.toBase58(), owner.publicKey.toBase58()].sort());
    expect(tx.feePayer!.equals(payer.publicKey)).toBe(true);

    rpc.accounts.set(
      commitment.toBase58(),
      encodeCommitment({
        version: 2,
        bump: 0,
        owner: owner.publicKey,
        scheme: 1,
        pqPubkey: key.publicKey,
        nextQ: 4,
        generation: 2,
        createdSlot: 1n,
        updatedSlot: 1n,
        usedKeys: [usedKeyHash(new Uint8Array(56).fill(9)), usedKeyHash(new Uint8Array(56).fill(8))],
      }),
    );
    const next = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H5, lmotsType: 3, seed: new Uint8Array(32).fill(1), I: new Uint8Array(16).fill(2) });
    const res = await client.rotatePq(owner.publicKey, key, next.publicKey, { nonce: 1n });
    expect(res.q).toBe(4);
    expect(res.generation).toBe(2);
    expect(res.signatures).toEqual(["sig2", "sig3", "sig4", "sig5", "sig6"]);
    expect(toHex(res.message)).toBe(toHex(registryMessage(owner.publicKey, 2, next.publicKey)));
    expect(toHex(res.message)).not.toBe(toHex(registryMessage(owner.publicKey, 1, next.publicKey)));
    expect(lmsVerify(key.publicKey, res.message, res.lmsSignature)).toBe(true);
    const open = rpc.sent[1]!.instructions[0]!;
    expect(toHex(open.data.subarray(0, 8))).toBe(toHex(IX.openPqBuffer));
    expect(open.data.length).toBe(8 + 8 + 56 + 2);
    expect(toHex(open.data.subarray(16, 72))).toBe(toHex(next.publicKey));
    const { bytes, offsets } = reassemble(rpc.sent.slice(2, 5), IX.openPqBuffer, IX.writePqSig, () => 0);
    expect(toHex(bytes)).toBe(toHex(res.lmsSignature));
    expect(offsets).toEqual([0, 900, 1800]);
    expect(toHex(rpc.sent[5]!.instructions[1]!.data)).toBe(toHex(IX.rotatePq));

    await expect(client.rotatePq(owner.publicKey, next, key.publicKey)).rejects.toThrow(/not this key/);
    await expect(client.rotatePq(owner.publicKey, key, next.publicKey, { q: 3 })).rejects.toThrow(/below/);
    await expect(client.rotatePq(owner.publicKey, key, key.publicKey)).rejects.toThrow(/committed before/);
    await expect(client.rotatePq(owner.publicKey, key, new Uint8Array(56).fill(9))).rejects.toThrow(/committed before/);
  });

  it("commit with owner == payer signs once", async () => {
    const rpc = new MockRpc();
    const owner = Keypair.generate();
    const client = new RegistryClient({ rpc, payer: owner });
    await client.commit(owner, key.publicKey);
    expect(rpc.sent[0]!.signatures.length).toBe(1);
  });
});
