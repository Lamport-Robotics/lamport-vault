import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
import { Keypair, PublicKey, SystemProgram, Transaction, LAMPORTS_PER_SOL } from "@solana/web3.js";
import * as spl from "@solana/spl-token";
import { expect } from "chai";
import { LamportVault } from "../target/types/lamport_vault";
import {
  Action,
  CHUNK,
  COMPUTE_BUDGET_IX,
  FIRST_CHUNK,
  LMS_H10,
  LMS_H5,
  LmsKey,
  consumedUnits,
  currentSlot,
  expectError,
  expectRejects,
  expiredWindow,
  fund,
  keyHash,
  leafUsed,
  loadSdk,
  meta,
  provider as makeProvider,
  randomNonce,
  sha256,
  sigBufferPda,
  vaultMessage,
  vaultPda,
  window,
} from "./helpers";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

describe("lamport-vault", () => {
  const provider = makeProvider();
  const program = anchor.workspace.lamportVault as Program<LamportVault>;
  const connection = provider.connection;

  // The classical key that pays for staging buffers. It never controls funds.
  const payer = Keypair.generate();
  // The vault owner's hash-based key (H10, the default).
  const keyA = LmsKey.random(LMS_H10);
  // The key the vault rotates to in the "rotate" test.
  const keyC = LmsKey.random(LMS_H10);
  let vault: PublicKey;
  const recipient = Keypair.generate();

  /** `MAX_KEY_HISTORY` of the deployed build (128, or 2 with `--features small-history`). */
  const MAX_KEY_HISTORY = Number(program.idl.constants.find((c) => c.name === "maxKeyHistory")!.value);
  /** `MAX_VALIDITY_SLOTS`: the longest window the program accepts (216 000, about a day). */
  const MAX_VALIDITY_SLOTS = Number(program.idl.constants.find((c) => c.name === "maxValiditySlots")!.value);

  /** A window issued now, open for 5 000 slots. */
  const FAR = () => window(provider);

  async function createVault(key: LmsKey): Promise<PublicKey> {
    const [pda] = vaultPda(program.programId, key.pubkey());
    await program.methods
      .createVault(Array.from(sha256(key.pubkey())), Array.from(key.pubkey()))
      .accounts({ payer: provider.wallet.publicKey, vault: pda })
      .rpc({ commitment: "confirmed" });
    return pda;
  }

  async function fetchVault(vaultKey: PublicKey) {
    const v = await program.account.vault.fetch(vaultKey);
    return { ...v, used: Buffer.from(v.used), usedKeys: v.usedKeys.map((k) => Buffer.from(k)) };
  }

  /** Signs `actionBytes` with `key` at leaf `q` for `vault` (bound to the vault's current generation unless given) and stages it. */
  async function stage(
    vaultKey: PublicKey,
    key: LmsKey,
    q: number,
    actionBytes: Buffer,
    opts: { message?: Buffer; generation?: number; sig?: Buffer; sigLen?: number; skipLast?: boolean } = {},
  ): Promise<PublicKey> {
    const generation = opts.generation ?? (await fetchVault(vaultKey)).generation;
    const sig = opts.sig ?? key.sign(q, opts.message ?? vaultMessage(program.programId, vaultKey, generation, actionBytes));
    const nonce = randomNonce();
    const [buf] = sigBufferPda(program.programId, vaultKey, payer.publicKey, nonce);
    await program.methods
      .openSigBuffer(nonce, actionBytes, opts.sigLen ?? sig.length, sig.subarray(0, FIRST_CHUNK))
      .accounts({ payer: payer.publicKey, vault: vaultKey, sigBuffer: buf })
      .signers([payer])
      .rpc({ commitment: "confirmed" });
    for (let off = FIRST_CHUNK; off < sig.length; off += CHUNK) {
      if (opts.skipLast && off + CHUNK >= sig.length) break;
      await program.methods
        .writeSig(off, sig.subarray(off, off + CHUNK))
        .accounts({ payer: payer.publicKey, sigBuffer: buf })
        .signers([payer])
        .rpc({ commitment: "confirmed" });
    }
    return buf;
  }

  /** Submits `execute` from the provider wallet (anyone may). Returns the tx signature. */
  async function execute(vaultKey: PublicKey, buf: PublicKey, remaining: anchor.web3.AccountMeta[]) {
    return program.methods
      .execute()
      .accounts({ vault: vaultKey, sigBuffer: buf, payer: payer.publicKey })
      .remainingAccounts(remaining)
      .preInstructions([COMPUTE_BUDGET_IX])
      .rpc({ commitment: "confirmed" });
  }

  /** Stage + execute a 1000-lamport TransferSol at leaf `q`. */
  async function spendLeaf(vaultKey: PublicKey, key: LmsKey, q: number) {
    const buf = await stage(vaultKey, key, q, Action.transferSol(recipient.publicKey, 1000, await FAR()));
    return execute(vaultKey, buf, [meta(recipient.publicKey, true)]);
  }

  async function spent(vaultKey: PublicKey): Promise<number> {
    return (await fetchVault(vaultKey)).spent;
  }

  async function isUsed(vaultKey: PublicKey, q: number): Promise<boolean> {
    return leafUsed((await fetchVault(vaultKey)).used, q);
  }

  /** First unspent leaf. */
  async function freeLeaf(vaultKey: PublicKey): Promise<number> {
    const used = (await fetchVault(vaultKey)).used;
    for (let q = 0; q < used.length * 8; q++) if (!leafUsed(used, q)) return q;
    throw new Error("no free leaf");
  }

  before(async () => {
    await fund(provider, payer.publicKey, 5);
    await fund(provider, recipient.publicKey, 0.01);
  });

  it("create", async () => {
    vault = await createVault(keyA);
    const v = await fetchVault(vault);
    expect(v.version).to.eq(2);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(keyA.pubkey());
    expect(v.spent).to.eq(0);
    expect(v.generation).to.eq(0);
    expect(v.used.length).to.eq(128); // H10: 1024 leaves / 8
    expect(v.used.every((b) => b === 0)).to.eq(true);
    expect(v.usedKeys).to.deep.eq([]);
    expect(v.createdSlot.toNumber()).to.be.greaterThan(0);
    const info = await connection.getAccountInfo(vault, "confirmed");
    expect(info!.data.length).to.eq(8 + 1 + 1 + 32 + 56 + 4 + 4 + 8 + (4 + 128) + 4);
  });

  it("bad typecodes", async () => {
    const badOts = Buffer.from(keyA.pubkey());
    badOts.writeUInt32BE(4, 4); // W8
    const [pda1] = vaultPda(program.programId, badOts);
    await expectError(
      program.methods
        .createVault(Array.from(sha256(badOts)), Array.from(badOts))
        .accounts({ payer: provider.wallet.publicKey, vault: pda1 })
        .rpc(),
      "InvalidLmotsType",
    );
    for (const code of [8, 9]) {
      // H20 is refused by the vault (128 KB bitmap); H25 is unknown.
      const badLms = Buffer.from(keyA.pubkey());
      badLms.writeUInt32BE(code, 0);
      const [pda2] = vaultPda(program.programId, badLms);
      await expectError(
        program.methods
          .createVault(Array.from(sha256(badLms)), Array.from(badLms))
          .accounts({ payer: provider.wallet.publicKey, vault: pda2 })
          .rpc(),
        "InvalidLmsType",
      );
    }
  });

  it("dup vault / bad vault_id", async () => {
    await expectError(
      program.methods
        .createVault(Array.from(sha256(keyA.pubkey())), Array.from(keyA.pubkey()))
        .accounts({ payer: provider.wallet.publicKey, vault })
        .rpc(),
      "AlreadyInUse",
    );
    const other = LmsKey.random(LMS_H5);
    const wrongId = sha256(Buffer.from("not the key"));
    const [pda] = PublicKey.findProgramAddressSync([Buffer.from("vault"), wrongId], program.programId);
    await expectError(
      program.methods
        .createVault(Array.from(wrongId), Array.from(other.pubkey()))
        .accounts({ payer: provider.wallet.publicKey, vault: pda })
        .rpc(),
      "VaultIdMismatch",
    );
  });

  it("create on funded address", async () => {
    const early = LmsKey.random(LMS_H5);
    const [pda] = vaultPda(program.programId, early.pubkey());
    await fund(provider, pda, 0.3);
    await createVault(early);
    const v = await fetchVault(pda);
    expect(v.spent).to.eq(0);
    expect(v.used.length).to.eq(4); // H5: 32 leaves / 8
    // The deposit already covered rent, so init only allocated and assigned; nothing was moved.
    expect(await connection.getBalance(pda, "confirmed")).to.be.greaterThanOrEqual(0.3 * LAMPORTS_PER_SOL);
  });

  it("deposit", async () => {
    const tx = new Transaction().add(
      SystemProgram.transfer({ fromPubkey: provider.wallet.publicKey, toPubkey: vault, lamports: 2 * LAMPORTS_PER_SOL }),
    );
    await provider.sendAndConfirm(tx, [], { commitment: "confirmed" });
    const bal = await connection.getBalance(vault, "confirmed");
    expect(bal).to.be.greaterThan(2 * LAMPORTS_PER_SOL);
  });

  it("transfer sol (h10)", async () => {
    const amount = 0.5 * LAMPORTS_PER_SOL;
    const action = Action.transferSol(recipient.publicKey, amount, await FAR());
    const buf = await stage(vault, keyA, 0, action);
    const staged = await program.account.sigBuffer.fetch(buf);
    expect(staged.filled).to.eq(staged.sigLen);
    expect(staged.sigLen).to.eq(2508);

    const before = await connection.getBalance(recipient.publicKey, "confirmed");
    const payerBefore = await connection.getBalance(payer.publicKey, "confirmed");
    const sig = await execute(vault, buf, [meta(recipient.publicKey, true)]);
    const after = await connection.getBalance(recipient.publicKey, "confirmed");
    expect(after - before).to.eq(amount);
    expect(await spent(vault)).to.eq(1);
    expect(await isUsed(vault, 0)).to.eq(true);
    expect(await isUsed(vault, 1)).to.eq(false);
    // Buffer closed, rent back to payer.
    expect(await connection.getAccountInfo(buf, "confirmed")).to.eq(null);
    const payerAfter = await connection.getBalance(payer.publicKey, "confirmed");
    expect(payerAfter).to.be.greaterThan(payerBefore);

    const cu = await consumedUnits(provider, sig, program.programId);
    console.log(`      execute(TransferSol, H10/W4) consumed ${cu} compute units`);
    expect(cu).to.be.lessThan(400_000);
  });

  it("execute_direct: wiring on a legacy transaction (a full signature needs a v1 transaction)", async () => {
    // Agave 2.3 on the local validator has no transaction v1, and a W4 signature
    // (2348+ bytes) does not fit a 1232-byte legacy transaction, so only the
    // instruction's wiring and early checks run here; the full path is covered
    // by the host unit tests of the shared verify code and the devnet benchmark.
    const action = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const direct = (actionBytes: Buffer, sig: Buffer) =>
      program.methods
        .executeDirect(actionBytes, sig)
        .accounts({ vault, payer: provider.wallet.publicKey })
        .remainingAccounts([meta(recipient.publicKey, true)])
        .preInstructions([COMPUTE_BUDGET_IX])
        .rpc({ commitment: "confirmed" });
    await expectError(direct(Buffer.alloc(0), Buffer.alloc(16)), "ActionTooLarge");
    // Typecodes are checked before the length: zeros are a type mismatch.
    await expectError(direct(action, Buffer.alloc(600)), "SignatureTypeMismatch");
    // A truncated real signature (right typecodes, wrong length) is malformed, and nothing is spent.
    const sig = keyA.sign(1, vaultMessage(program.programId, vault, 0, action));
    await expectError(direct(action, sig.subarray(0, 600)), "SignatureMalformed");
    expect(await isUsed(vault, 1)).to.eq(false);
    expect(await spent(vault)).to.eq(1);
  });

  it("replay", async () => {
    const action = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const buf = await stage(vault, keyA, 0, action);
    await expectError(execute(vault, buf, [meta(recipient.publicKey, true)]), "LeafAlreadyUsed");
    expect(await spent(vault)).to.eq(1);
    // Clean up the buffer: refund goes to the payer.
    await program.methods.closeSigBuffer().accounts({ payer: payer.publicKey, sigBuffer: buf }).signers([payer]).rpc();
    expect(await connection.getAccountInfo(buf)).to.eq(null);
  });

  it("leaves in any order (bitmap), each once", async () => {
    await spendLeaf(vault, keyA, 5);
    expect(await spent(vault)).to.eq(2);
    // A lower leaf is still fine: the bitmap has no ordering.
    await spendLeaf(vault, keyA, 3);
    expect(await spent(vault)).to.eq(3);
    const v = await fetchVault(vault);
    expect([0, 3, 5].map((q) => leafUsed(v.used, q))).to.deep.eq([true, true, true]);
    expect([1, 2, 4, 6].map((q) => leafUsed(v.used, q))).to.deep.eq([false, false, false, false]);
    // But never twice.
    const again = await stage(vault, keyA, 3, Action.transferSol(recipient.publicKey, 1000, await FAR()));
    await expectError(execute(vault, again, [meta(recipient.publicKey, true)]), "LeafAlreadyUsed");
    expect(await spent(vault)).to.eq(3);
  });

  it("lanes: two signers interleaved (q even / q odd)", async () => {
    // Device 0 owns even leaves, device 1 odd leaves; each picks its own first free leaf.
    const laneFree = async (lane: number) => {
      const used = (await fetchVault(vault)).used;
      for (let q = lane; q < used.length * 8; q += 2) if (!leafUsed(used, q)) return q;
      throw new Error("lane exhausted");
    };
    const q0 = await laneFree(0); // 2
    const q1 = await laneFree(1); // 1
    expect([q0, q1]).to.deep.eq([2, 1]);
    // Both sign before either submits, then submit interleaved.
    const b0 = await stage(vault, keyA, q0, Action.transferSol(recipient.publicKey, 1000, await FAR()));
    const b1 = await stage(vault, keyA, q1, Action.transferSol(recipient.publicKey, 1000, await FAR()));
    await execute(vault, b1, [meta(recipient.publicKey, true)]);
    await execute(vault, b0, [meta(recipient.publicKey, true)]);
    const q0b = await laneFree(0); // 4
    const q1b = await laneFree(1); // 7 (3 and 5 are spent)
    expect([q0b, q1b]).to.deep.eq([4, 7]);
    await spendLeaf(vault, keyA, q0b);
    await spendLeaf(vault, keyA, q1b);
    expect(await spent(vault)).to.eq(7);
  });

  it("crash recovery: a signed-but-unsubmitted leaf stays valid, and is single-use", async () => {
    // Signer signs q=8 and crashes before submitting, restarts, signs q=9 and submits.
    const bufLost = await stage(vault, keyA, 8, Action.transferSol(recipient.publicKey, 1000, await FAR()));
    await spendLeaf(vault, keyA, 9);
    expect(await isUsed(vault, 8)).to.eq(false);
    // The q=8 signature turns up later: still valid (unexpired, leaf unspent).
    await execute(vault, bufLost, [meta(recipient.publicKey, true)]);
    expect(await isUsed(vault, 8)).to.eq(true);
    // Submitting q=8 again is refused. (What the chain cannot prevent is the signer *signing* q=8
    // twice after a crash; that is the SDK's persistent reserve(q) hook's job.)
    const replay = await stage(vault, keyA, 8, Action.transferSol(recipient.publicKey, 1000, await FAR()));
    await expectError(execute(vault, replay, [meta(recipient.publicKey, true)]), "LeafAlreadyUsed");
    expect(await spent(vault)).to.eq(9);
  });

  it("expired", async () => {
    const action = Action.transferSol(recipient.publicKey, 1000, await expiredWindow(provider));
    const buf = await stage(vault, keyA, 10, action);
    await expectError(execute(vault, buf, [meta(recipient.publicKey, true)]), "ActionExpired");
    expect(await isUsed(vault, 10)).to.eq(false);
  });

  it("issued in the future", async () => {
    const slot = await currentSlot(provider);
    const action = Action.transferSol(recipient.publicKey, 1000, { issued: slot + 1000, expiry: slot + 2000 });
    const buf = await stage(vault, keyA, 10, action);
    await expectError(execute(vault, buf, [meta(recipient.publicKey, true)]), "IssuedInFuture");
    expect(await isUsed(vault, 10)).to.eq(false);
    // a zero-length window ahead of the clock: still not issued (staging takes a few slots, so stay well ahead)
    const far = Action.transferSol(recipient.publicKey, 1000, { issued: slot + 500, expiry: slot + 500 });
    const buf2 = await stage(vault, keyA, 10, far);
    await expectError(execute(vault, buf2, [meta(recipient.publicKey, true)]), "IssuedInFuture");
    expect(await isUsed(vault, 10)).to.eq(false);
  });

  it("wrong vault", async () => {
    const keyB = LmsKey.random(LMS_H5);
    const vaultB = await createVault(keyB);
    const action = Action.transferSol(recipient.publicKey, 1000, await FAR());
    // Key A signs the message for vault B, staged on vault A: wrong binding.
    const buf = await stage(vault, keyA, 10, action, { message: vaultMessage(program.programId, vaultB, 0, action) });
    await expectError(execute(vault, buf, [meta(recipient.publicKey, true)]), "InvalidSignature");
    expect(await isUsed(vault, 10)).to.eq(false);

    // A buffer opened on vault B cannot be executed against vault A.
    const bufB = await stage(vaultB, keyB, 0, action);
    await expectError(execute(vault, bufB, [meta(recipient.publicKey, true)]), "VaultMismatch");
  });

  it("wrong program id in the message", async () => {
    const action = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const buf = await stage(vault, keyA, 10, action, { message: vaultMessage(SystemProgram.programId, vault, 0, action) });
    await expectError(execute(vault, buf, [meta(recipient.publicKey, true)]), "InvalidSignature");
    expect(await isUsed(vault, 10)).to.eq(false);
  });

  it("tampered sig / wrong dest / short buffer", async () => {
    const action = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const good = keyA.sign(10, vaultMessage(program.programId, vault, 0, action));
    const bad = Buffer.from(good);
    bad[100] ^= 0x01;
    const buf = await stage(vault, keyA, 10, action, { sig: bad });
    await expectError(execute(vault, buf, [meta(recipient.publicKey, true)]), "InvalidSignature");

    const buf2 = await stage(vault, keyA, 10, action, { sig: good });
    const other = Keypair.generate().publicKey;
    await expectError(execute(vault, buf2, [meta(other, true)]), "WrongDestination");
    await expectError(execute(vault, buf2, []), "MissingAccount");

    const buf3 = await stage(vault, keyA, 10, action, { sig: good, skipLast: true });
    await expectError(execute(vault, buf3, [meta(recipient.publicKey, true)]), "SignatureIncomplete");
    // Writing at the wrong offset is refused; someone else cannot write at all.
    const staged = await program.account.sigBuffer.fetch(buf3);
    await expectError(
      program.methods
        .writeSig(staged.filled + 1, good.subarray(staged.filled, staged.filled + 10))
        .accounts({ payer: payer.publicKey, sigBuffer: buf3 })
        .signers([payer])
        .rpc(),
      "OffsetMismatch",
    );
    const stranger = Keypair.generate();
    await fund(provider, stranger.publicKey, 0.1);
    await expectError(
      program.methods
        .writeSig(staged.filled, good.subarray(staged.filled, staged.filled + 10))
        .accounts({ payer: stranger.publicKey, sigBuffer: buf3 })
        .signers([stranger])
        .rpc(),
      "WrongPayer",
    );
    // Completing the buffer afterwards makes it executable; the good sig at q=10 goes through.
    await program.methods
      .writeSig(staged.filled, good.subarray(staged.filled))
      .accounts({ payer: payer.publicKey, sigBuffer: buf3 })
      .signers([payer])
      .rpc({ commitment: "confirmed" });
    await execute(vault, buf3, [meta(recipient.publicKey, true)]);
    expect(await isUsed(vault, 10)).to.eq(true);
    // The other two buffers now carry a used leaf.
    await expectError(execute(vault, buf2, [meta(recipient.publicKey, true)]), "LeafAlreadyUsed");
  });

  it("bad sig_len, rent floor", async () => {
    const action = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const nonce = randomNonce();
    const [buf] = sigBufferPda(program.programId, vault, payer.publicKey, nonce);
    await expectError(
      program.methods
        .openSigBuffer(nonce, action, 2348, Buffer.alloc(0))
        .accounts({ payer: payer.publicKey, vault, sigBuffer: buf })
        .signers([payer])
        .rpc(),
      "SignatureLengthMismatch",
    );
    const balance = await connection.getBalance(vault, "confirmed");
    const greedy = Action.transferSol(recipient.publicKey, balance, await FAR());
    const q = await freeLeaf(vault);
    const buf2 = await stage(vault, keyA, q, greedy);
    await expectError(execute(vault, buf2, [meta(recipient.publicKey, true)]), "InsufficientFunds");
    expect(await isUsed(vault, q)).to.eq(false);
  });

  for (const [label, tokenProgram] of [
    ["Token", spl.TOKEN_PROGRAM_ID],
    ["Token-2022", spl.TOKEN_2022_PROGRAM_ID],
  ] as const) {
    it(`executes TransferToken with ${label}`, async () => {
      const wallet = (provider.wallet as anchor.Wallet).payer;
      const mint = await spl.createMint(connection, wallet, wallet.publicKey, null, 6, undefined, { commitment: "confirmed" }, tokenProgram);
      const vaultAta = await spl.createAssociatedTokenAccount(connection, wallet, mint, vault, { commitment: "confirmed" }, tokenProgram, spl.ASSOCIATED_TOKEN_PROGRAM_ID, true);
      const destAta = await spl.createAssociatedTokenAccount(connection, wallet, mint, recipient.publicKey, { commitment: "confirmed" }, tokenProgram);
      await spl.mintTo(connection, wallet, mint, vaultAta, wallet, 1_000_000, [], { commitment: "confirmed" }, tokenProgram);

      const q = await freeLeaf(vault);
      const action = Action.transferToken(mint, destAta, 250_000, await FAR());
      const buf = await stage(vault, keyA, q, action);
      const sig = await execute(vault, buf, [meta(vaultAta, true), meta(destAta, true), meta(mint, false), meta(tokenProgram, false)]);
      const dest = await spl.getAccount(connection, destAta, "confirmed", tokenProgram);
      expect(Number(dest.amount)).to.eq(250_000);
      const src = await spl.getAccount(connection, vaultAta, "confirmed", tokenProgram);
      expect(Number(src.amount)).to.eq(750_000);
      const cu = await consumedUnits(provider, sig, program.programId);
      console.log(`      execute(TransferToken ${label}, H10/W4) consumed ${cu} compute units`);

      // Wrong mint / wrong destination / wrong program are refused.
      const q2 = await freeLeaf(vault);
      const action2 = Action.transferToken(mint, destAta, 1, await FAR());
      const buf2 = await stage(vault, keyA, q2, action2);
      const otherAta = await spl.createAssociatedTokenAccount(connection, wallet, mint, Keypair.generate().publicKey, { commitment: "confirmed" }, tokenProgram);
      await expectError(execute(vault, buf2, [meta(vaultAta, true), meta(otherAta, true), meta(mint, false), meta(tokenProgram, false)]), "WrongDestination");
      await expectError(execute(vault, buf2, [meta(vaultAta, true), meta(destAta, true), meta(vaultAta, false), meta(tokenProgram, false)]), "WrongMint");
      await expectError(execute(vault, buf2, [meta(vaultAta, true), meta(destAta, true), meta(mint, false), meta(SystemProgram.programId, false)]), "InvalidTokenProgram");
      await program.methods.closeSigBuffer().accounts({ payer: payer.publicKey, sigBuffer: buf2 }).signers([payer]).rpc();
    });
  }

  it("rotate: fresh bitmap, generation + 1, old key in history, buffer payer pays the 16 bytes", async () => {
    const q = await freeLeaf(vault);
    const action = Action.rotate(keyC.pubkey(), await FAR());
    const buf = await stage(vault, keyA, q, action);
    const sizeBefore = (await connection.getAccountInfo(vault, "confirmed"))!.data.length;
    const vaultLamportsBefore = await connection.getBalance(vault, "confirmed");
    const bufferLamports = await connection.getBalance(buf, "confirmed");
    const payerBefore = await connection.getBalance(payer.publicKey, "confirmed");
    const sig = await execute(vault, buf, []);
    const v = await fetchVault(vault);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(keyC.pubkey());
    expect(v.spent).to.eq(0);
    expect(v.generation).to.eq(1);
    expect(v.used.every((b) => b === 0)).to.eq(true);
    expect(v.usedKeys).to.deep.eq([keyHash(keyA.pubkey())]);
    expect(Buffer.from(v.vaultId)).to.deep.eq(sha256(keyA.pubkey())); // vault_id and address unchanged
    // One 16-byte history entry: the rent delta moved from the buffer to the vault; the payer got the rest.
    const info = await connection.getAccountInfo(vault, "confirmed");
    expect(info!.data.length).to.eq(sizeBefore + 16);
    const delta = (await connection.getMinimumBalanceForRentExemption(sizeBefore + 16)) - (await connection.getMinimumBalanceForRentExemption(sizeBefore));
    expect(delta).to.be.greaterThan(0);
    expect(info!.lamports).to.eq(vaultLamportsBefore + delta);
    const payerAfter = await connection.getBalance(payer.publicKey, "confirmed");
    expect(payerAfter - payerBefore).to.eq(bufferLamports - delta);
    const cu = await consumedUnits(provider, sig, program.programId);
    console.log(`      execute(Rotate, H10/W4) consumed ${cu} compute units`);

    // Old key: its signature no longer verifies under the new public key.
    const spend = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const bufOld = await stage(vault, keyA, 50, spend);
    await expectError(execute(vault, bufOld, [meta(recipient.publicKey, true)]), "InvalidSignature");

    // New key, leaf 0.
    const bufNew = await stage(vault, keyC, 0, spend);
    await execute(vault, bufNew, [meta(recipient.publicKey, true)]);
    expect(await spent(vault)).to.eq(1);

    // Rotating to the key already in use, or back to a past key (A -> C -> A), is refused.
    const same = await stage(vault, keyC, 1, Action.rotate(keyC.pubkey(), await FAR()));
    await expectError(execute(vault, same, []), "KeyReused");
    const back = await stage(vault, keyC, 1, Action.rotate(keyA.pubkey(), await FAR()));
    await expectError(execute(vault, back, []), "KeyReused");
    expect(await isUsed(vault, 1)).to.eq(false);
    // Rotating to another height is refused (the bitmap is sized for H10); H20 keys are refused outright.
    const h5 = await stage(vault, keyC, 1, Action.rotate(LmsKey.random(LMS_H5).pubkey(), await FAR()));
    await expectError(execute(vault, h5, []), "RotateTypeMismatch");
    const h20 = Buffer.from(LmsKey.random(LMS_H10).pubkey());
    h20.writeUInt32BE(8, 0);
    const bufH20 = await stage(vault, keyC, 1, Action.rotate(h20, await FAR()));
    await expectError(execute(vault, bufH20, []), "InvalidLmsType");
    expect((await fetchVault(vault)).generation).to.eq(1);
  });

  it("old-generation signature is refused even on a fresh leaf", async () => {
    const v = await fetchVault(vault);
    expect(v.generation).to.eq(1);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(keyC.pubkey());
    const spend = Action.transferSol(recipient.publicKey, 1000, await FAR());
    // Signed by the current key over the generation-0 message: wrong binding.
    const stale = await stage(vault, keyC, 1, spend, { generation: 0 });
    await expectError(execute(vault, stale, [meta(recipient.publicKey, true)]), "InvalidSignature");
    expect(await isUsed(vault, 1)).to.eq(false);
    // The same leaf with the current generation goes through.
    const fresh = await stage(vault, keyC, 1, spend, { generation: 1 });
    await execute(vault, fresh, [meta(recipient.publicKey, true)]);
    expect(await isUsed(vault, 1)).to.eq(true);
  });

  it("last free leaf only rotate (h5), then close", async () => {
    const keyD = LmsKey.random(LMS_H5);
    const vaultD = await createVault(keyD);
    await fund(provider, vaultD, 0.2);

    // Spend 31 of the 32 leaves, high to low, leaving q = 0 free.
    for (let q = 31; q >= 1; q--) await spendLeaf(vaultD, keyD, q);
    expect(await spent(vaultD)).to.eq(31);
    expect(await isUsed(vaultD, 0)).to.eq(false);

    const spend = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const buf = await stage(vaultD, keyD, 0, spend);
    await expectError(execute(vaultD, buf, [meta(recipient.publicKey, true)]), "LastLeafReservedForRotate");
    expect(await spent(vaultD)).to.eq(31);

    // q = 32 does not exist in an H5 tree.
    const sig0 = keyD.sign(0, vaultMessage(program.programId, vaultD, 0, spend));
    const sig32 = Buffer.from(sig0);
    sig32.writeUInt32BE(32, 0);
    const bufOut = await stage(vaultD, keyD, 0, spend, { sig: sig32 });
    await expectError(execute(vaultD, bufOut, [meta(recipient.publicKey, true)]), "LeafOutOfRange");

    const keyE = LmsKey.random(LMS_H5);
    const rotate = Action.rotate(keyE.pubkey(), await FAR());
    const bufRot = await stage(vaultD, keyD, 0, rotate);
    await execute(vaultD, bufRot, []);
    const v = await fetchVault(vaultD);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(keyE.pubkey());
    expect(v.spent).to.eq(0);
    expect(v.generation).to.eq(1);
    expect(v.used).to.deep.eq(Buffer.alloc(4));

    // Close: all lamports to `to`, an empty vault token account is closed too,
    // a non-empty one blocks the close.
    const wallet = (provider.wallet as anchor.Wallet).payer;
    const mint = await spl.createMint(connection, wallet, wallet.publicKey, null, 0, undefined, { commitment: "confirmed" });
    const emptyAta = await spl.createAssociatedTokenAccount(connection, wallet, mint, vaultD, { commitment: "confirmed" }, spl.TOKEN_PROGRAM_ID, spl.ASSOCIATED_TOKEN_PROGRAM_ID, true);
    const mint2 = await spl.createMint(connection, wallet, wallet.publicKey, null, 0, undefined, { commitment: "confirmed" });
    const fullAta = await spl.createAssociatedTokenAccount(connection, wallet, mint2, vaultD, { commitment: "confirmed" }, spl.TOKEN_PROGRAM_ID, spl.ASSOCIATED_TOKEN_PROGRAM_ID, true);
    await spl.mintTo(connection, wallet, mint2, fullAta, wallet, 5, [], { commitment: "confirmed" });

    const heir = Keypair.generate().publicKey;
    const close = Action.close(heir, await FAR());
    const bufClose = await stage(vaultD, keyE, 0, close);
    await expectError(
      execute(vaultD, bufClose, [meta(heir, true), meta(fullAta, true), meta(spl.TOKEN_PROGRAM_ID, false)]),
      "TokenAccountNotEmpty",
    );
    const vaultLamports = await connection.getBalance(vaultD, "confirmed");
    const ataLamports = await connection.getBalance(emptyAta, "confirmed");
    await execute(vaultD, bufClose, [meta(heir, true), meta(emptyAta, true), meta(spl.TOKEN_PROGRAM_ID, false)]);
    expect(await connection.getAccountInfo(vaultD, "confirmed")).to.eq(null);
    expect(await connection.getAccountInfo(emptyAta, "confirmed")).to.eq(null);
    expect(await connection.getAccountInfo(bufClose, "confirmed")).to.eq(null);
    expect(await connection.getBalance(heir, "confirmed")).to.eq(vaultLamports + ataLamports);
  });

  it("history full: after MAX_KEY_HISTORY rotations only spending and Close remain", async function () {
    if (MAX_KEY_HISTORY > 4) {
      console.log(`      MAX_KEY_HISTORY = ${MAX_KEY_HISTORY}; run \`anchor test -- --features small-history\` to exercise HistoryFull`);
      expect(MAX_KEY_HISTORY).to.eq(128);
      this.skip();
    }
    let key = LmsKey.random(LMS_H5);
    const vaultF = await createVault(key);
    await fund(provider, vaultF, 0.2);
    const keys = [key];
    for (let i = 0; i < MAX_KEY_HISTORY; i++) {
      const next = LmsKey.random(LMS_H5);
      const buf = await stage(vaultF, key, 0, Action.rotate(next.pubkey(), await FAR()));
      await execute(vaultF, buf, []);
      key = next;
      keys.push(key);
    }
    const v = await fetchVault(vaultF);
    expect(v.generation).to.eq(MAX_KEY_HISTORY);
    expect(v.usedKeys).to.deep.eq(keys.slice(0, -1).map((k) => keyHash(k.pubkey())));
    // Every past key is refused, the next fresh key too: the history is full.
    for (const past of keys.slice(0, -1)) {
      const b = await stage(vaultF, key, 0, Action.rotate(past.pubkey(), await FAR()));
      await expectError(execute(vaultF, b, []), "KeyReused");
    }
    const bFull = await stage(vaultF, key, 0, Action.rotate(LmsKey.random(LMS_H5).pubkey(), await FAR()));
    await expectError(execute(vaultF, bFull, []), "HistoryFull");
    expect(await spent(vaultF)).to.eq(0);
    // Funds still move, and the vault can be closed.
    await spendLeaf(vaultF, key, 0);
    expect(await spent(vaultF)).to.eq(1);
    const heir = Keypair.generate().publicKey;
    const bufClose = await stage(vaultF, key, 1, Action.close(heir, await FAR()));
    await execute(vaultF, bufClose, [meta(heir, true)]);
    expect(await connection.getAccountInfo(vaultF, "confirmed")).to.eq(null);
  });

  // Failure-and-recovery scenarios. Each uses its own H5 vault (32 leaves) so the order of the
  // tests above does not matter to them.

  it("last leaf signed twice", async () => {
    const keyP = LmsKey.random(LMS_H5);
    const vaultP = await createVault(keyP);
    await fund(provider, vaultP, 0.2);
    for (let q = 0; q <= 30; q++) await spendLeaf(vaultP, keyP, q);
    expect(await spent(vaultP)).to.eq(31);
    expect(await isUsed(vaultP, 31)).to.eq(false);

    // The owner signs two different rotations with the last leaf (both over the generation-0
    // message) before either reaches the chain: a retried UI, two devices, a leaked signature.
    const keyB = LmsKey.random(LMS_H5);
    const keyC2 = LmsKey.random(LMS_H5);
    const toB = await stage(vaultP, keyP, 31, Action.rotate(keyB.pubkey(), await FAR()));
    const toC = await stage(vaultP, keyP, 31, Action.rotate(keyC2.pubkey(), await FAR()));
    await execute(vaultP, toB, []);
    let v = await fetchVault(vaultP);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(keyB.pubkey());
    expect(v.generation).to.eq(1);
    expect(v.spent).to.eq(0);
    expect(v.used).to.deep.eq(Buffer.alloc(4));

    // The second rotation. Which error fires: the Rotate zeroed the bitmap, so leaf 31 reads as
    // free again and LeafAlreadyUsed cannot be what stops it. What does is the binding: the
    // signature was made by key P over the generation-0 message, and the vault now verifies
    // under key B over the generation-1 message, so it fails InvalidSignature. Nothing changes.
    await expectError(execute(vaultP, toC, []), "InvalidSignature");
    v = await fetchVault(vaultP);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(keyB.pubkey());
    expect(v.generation).to.eq(1);
    expect(leafUsed(v.used, 31)).to.eq(false);
    expect(v.usedKeys).to.deep.eq([keyHash(keyP.pubkey())]);
    // Re-signing it with the retired key over the generation-1 message is no better: wrong key.
    const toC1 = await stage(vaultP, keyP, 31, Action.rotate(keyC2.pubkey(), await FAR()), { generation: 1 });
    await expectError(execute(vaultP, toC1, []), "InvalidSignature");
    expect(await isUsed(vaultP, 31)).to.eq(false);
    // The leaf really is free under the new key: B rotates to C with q = 31 (no longer the last free leaf).
    const byB = await stage(vaultP, keyB, 31, Action.rotate(keyC2.pubkey(), await FAR()));
    await execute(vaultP, byB, []);
    v = await fetchVault(vaultP);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(keyC2.pubkey());
    expect(v.generation).to.eq(2);
    expect(v.usedKeys).to.deep.eq([keyHash(keyP.pubkey()), keyHash(keyB.pubkey())]);
  });

  it("rotate signature made, device dies, then resumed", async () => {
    const keyP = LmsKey.random(LMS_H5);
    const keyQ = LmsKey.random(LMS_H5);
    const vaultP = await createVault(keyP);
    await fund(provider, vaultP, 0.2);

    // Leaf 0: a Rotate is signed and staged, then the device dies before `execute`.
    const rotate = await stage(vaultP, keyP, 0, Action.rotate(keyQ.pubkey(), await FAR()));
    // Resumed from the next leaf: a transfer with q = 1 goes through first.
    await spendLeaf(vaultP, keyP, 1);
    expect(await spent(vaultP)).to.eq(1);
    expect(await isUsed(vaultP, 0)).to.eq(false);
    expect((await fetchVault(vaultP)).generation).to.eq(0);

    // The old Rotate turns up: unexpired, leaf unspent, generation unchanged, so it succeeds.
    await execute(vaultP, rotate, []);
    const v = await fetchVault(vaultP);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(keyQ.pubkey());
    expect(v.generation).to.eq(1);
    expect(v.spent).to.eq(0);
    expect(v.used).to.deep.eq(Buffer.alloc(4));
    expect(v.usedKeys).to.deep.eq([keyHash(keyP.pubkey())]);

    // Everything signed under the old generation is dead now. By the retired key...
    const spend = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const byOldKey = await stage(vaultP, keyP, 2, spend, { generation: 0 });
    await expectError(execute(vaultP, byOldKey, [meta(recipient.publicKey, true)]), "InvalidSignature");
    // ...and by the new key over a generation-0 message (a signer that cached the old generation).
    const byOldGen = await stage(vaultP, keyQ, 2, spend, { generation: 0 });
    await expectError(execute(vaultP, byOldGen, [meta(recipient.publicKey, true)]), "InvalidSignature");
    expect(await isUsed(vaultP, 2)).to.eq(false);
    expect(await spent(vaultP)).to.eq(0);
    // The new key under generation 1 spends normally, from leaf 0 again.
    await spendLeaf(vaultP, keyQ, 0);
    await spendLeaf(vaultP, keyQ, 2);
    expect(await spent(vaultP)).to.eq(2);
    expect(await isUsed(vaultP, 1)).to.eq(false); // leaf 1 of the old key means nothing to the new bitmap
  });

  it("stale signer state", async () => {
    // The SDK's VaultSigner against the real chain. A signer "restored from an old backup" has
    // no memory of the leaves another signer spent; it must take the bitmap from the vault.
    const { vault: sdk, lms } = loadSdk();
    const key = lms.LmsPrivateKey.generate(lms.randomKeyMaterial(lms.LMS_SHA256_M32_H5));
    const signer = () => new sdk.VaultSigner({ rpc: connection, key, payer, commitment: "confirmed" });
    const live = signer();
    const created = await live.createVault();
    const vaultS = new PublicKey(created.vault.toBase58());
    await fund(provider, vaultS, 0.2);
    const transfer = { kind: "TransferSol", to: recipient.publicKey, lamports: 1000n };
    for (let i = 0; i < 4; i++) {
      const res = await live.execute(transfer);
      expect(res.q).to.eq(i);
      expect(res.mode).to.eq("staged");
    }
    expect(await spent(vaultS)).to.eq(4);
    const used = (await fetchVault(vaultS)).used;
    expect([0, 1, 2, 3, 4].map((q) => leafUsed(used, q))).to.deep.eq([true, true, true, true, false]);

    // Fresh object, same key, nothing remembered: it reads 0..3 as spent and picks 4.
    const restored = signer();
    expect(await restored.nextQ()).to.eq(4);
    await expectRejects(restored.sign(transfer, { q: 2 }), /already spent on chain/);
    const res = await restored.execute(transfer);
    expect(res.q).to.eq(4);
    expect(res.generation).to.eq(0);
    expect(await isUsed(vaultS, 4)).to.eq(true);
    expect(await spent(vaultS)).to.eq(5);
    // Both objects now agree on what comes next, whatever they remember.
    expect(await restored.nextQ()).to.eq(5);
    expect(await live.nextQ()).to.eq(5);
  });

  it("expired rotation", async () => {
    const keyP = LmsKey.random(LMS_H5);
    const keyQ = LmsKey.random(LMS_H5);
    const vaultP = await createVault(keyP);
    await fund(provider, vaultP, 0.2);
    const sizeBefore = (await connection.getAccountInfo(vaultP, "confirmed"))!.data.length;

    const expiredRotate = async () => Action.rotate(keyQ.pubkey(), await expiredWindow(provider));
    const stale = await stage(vaultP, keyP, 0, await expiredRotate());
    await expectError(execute(vaultP, stale, []), "ActionExpired");
    let v = await fetchVault(vaultP);
    expect(leafUsed(v.used, 0)).to.eq(false); // the leaf was not burned
    expect(v.spent).to.eq(0);
    expect(v.generation).to.eq(0);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(keyP.pubkey());
    expect(v.usedKeys).to.deep.eq([]);
    expect((await connection.getAccountInfo(vaultP, "confirmed"))!.data.length).to.eq(sizeBefore);

    // The same on the last free leaf, where burning it would strand the vault: still not burned.
    for (let q = 1; q <= 31; q++) await spendLeaf(vaultP, keyP, q);
    expect(await spent(vaultP)).to.eq(31);
    const staleLast = await stage(vaultP, keyP, 0, await expiredRotate());
    await expectError(execute(vaultP, staleLast, []), "ActionExpired");
    v = await fetchVault(vaultP);
    expect(leafUsed(v.used, 0)).to.eq(false);
    expect(v.spent).to.eq(31);
    expect(v.generation).to.eq(0);
    // A fresh, unexpired rotation on that leaf goes through.
    const fresh = await stage(vaultP, keyP, 0, Action.rotate(keyQ.pubkey(), await FAR()));
    await execute(vaultP, fresh, []);
    v = await fetchVault(vaultP);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(keyQ.pubkey());
    expect(v.generation).to.eq(1);
    expect(v.spent).to.eq(0);
  });
  it("validity window: at most one day; a far expiry on an old signature is unrepresentable", async () => {
    expect(MAX_VALIDITY_SLOTS).to.eq(216_000);
    const keyW = LmsKey.random(LMS_H5);
    const vaultW = await createVault(keyW);
    await fund(provider, vaultW, 0.2);
    const slot = await currentSlot(provider);

    // One slot past the cap: refused, the leaf is not burned.
    const tooLong = Action.transferSol(recipient.publicKey, 1000, { issued: slot, expiry: slot + MAX_VALIDITY_SLOTS + 1 });
    const b1 = await stage(vaultW, keyW, 0, tooLong);
    await expectError(execute(vaultW, b1, [meta(recipient.publicKey, true)]), "InvalidValidityWindow");
    expect(await isUsed(vaultW, 0)).to.eq(false);
    // Issued at 0 with the largest expiry the field holds: the signer cannot grant itself a far future.
    const forever = Action.transferSol(recipient.publicKey, 1000, { issued: 0, expiry: new BN("18446744073709551615") });
    const b2 = await stage(vaultW, keyW, 0, forever);
    await expectError(execute(vaultW, b2, [meta(recipient.publicKey, true)]), "InvalidValidityWindow");
    expect(await isUsed(vaultW, 0)).to.eq(false);
    // Issued a day ago with a far expiry: the window, not the clock, is what fails.
    const issuedBefore = Math.max(0, slot - 10);
    const longTail = Action.transferSol(recipient.publicKey, 1000, { issued: issuedBefore, expiry: issuedBefore + MAX_VALIDITY_SLOTS + 1 });
    const b3 = await stage(vaultW, keyW, 0, longTail);
    await expectError(execute(vaultW, b3, [meta(recipient.publicKey, true)]), "InvalidValidityWindow");
    expect(await isUsed(vaultW, 0)).to.eq(false);

    // Exactly one day is accepted (the clock has moved a few slots since `slot`, the window has not).
    const now = await currentSlot(provider);
    const day = Action.transferSol(recipient.publicKey, 1000, { issued: now, expiry: now + MAX_VALIDITY_SLOTS });
    const b4 = await stage(vaultW, keyW, 0, day);
    await execute(vaultW, b4, [meta(recipient.publicKey, true)]);
    expect(await isUsed(vaultW, 0)).to.eq(true);
    // A window that closes in the signing slot is the shortest one; it is accepted when it still holds.
    const rotateWindow = await window(provider, 0);
    rotateWindow.expiry = Number(rotateWindow.issued) + 200; // leave time for the three staging transactions
    const b5 = await stage(vaultW, keyW, 1, Action.transferSol(recipient.publicKey, 1000, rotateWindow));
    await execute(vaultW, b5, [meta(recipient.publicKey, true)]);
    expect(await spent(vaultW)).to.eq(2);
    // The same rules apply to Rotate, with the same error.
    const keyX = LmsKey.random(LMS_H5);
    const b6 = await stage(vaultW, keyW, 2, Action.rotate(keyX.pubkey(), { issued: now, expiry: now + MAX_VALIDITY_SLOTS + 1 }));
    await expectError(execute(vaultW, b6, []), "InvalidValidityWindow");
    expect((await fetchVault(vaultW)).generation).to.eq(0);
  });

  it("signer journal: restored from an old backup, only Rotate; after it lands, fresh", async () => {
    // The SDK's VaultSigner with a FileLeafJournal against the real chain.
    const { vault: sdk, lms } = loadSdk();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lamport-journal-"));
    const journalPath = path.join(dir, "journal.json");
    const key = lms.LmsPrivateKey.generate(lms.randomKeyMaterial(lms.LMS_SHA256_M32_H5));
    const signer = () => new sdk.VaultSigner({ rpc: connection, key, payer, commitment: "confirmed", journal: new sdk.FileLeafJournal(journalPath) });
    const live = signer();
    const created = await live.createVault();
    const vaultJ = new PublicKey(created.vault.toBase58());
    await fund(provider, vaultJ, 0.2);
    const transfer = { kind: "TransferSol", to: recipient.publicKey, lamports: 1000n };
    const r0 = await live.execute(transfer);
    expect(r0.q).to.eq(0);
    expect(r0.action.issuedSlot).to.be.a("bigint");
    expect(Number(r0.action.expirySlot - r0.action.issuedSlot)).to.eq(300); // the default window
    const backup = fs.readFileSync(journalPath, "utf8");
    expect(JSON.parse(backup)).to.deep.eq({ v: 1, generation: 0, spent: 0, reserved: [0] });
    const r1 = await live.execute(transfer);
    expect(r1.q).to.eq(1);
    expect(await spent(vaultJ)).to.eq(2);

    // Restore the day-1 backup: the chain shows a spent leaf the journal never reserved.
    fs.writeFileSync(journalPath, backup);
    const restored = signer();
    await expectRejects(restored.execute(transfer), /stale signer state.*Only Rotate/);
    await expectRejects(restored.sign({ kind: "Close", to: recipient.publicKey }), /stale signer state/);
    expect(await spent(vaultJ)).to.eq(2);
    expect(JSON.parse(fs.readFileSync(journalPath, "utf8"))).to.deep.eq({ v: 1, generation: 0, spent: 0, reserved: [0] });
    // Rotate goes through (staged), and once it lands the journal is fresh for generation 1.
    const next = lms.LmsPrivateKey.generate(lms.randomKeyMaterial(lms.LMS_SHA256_M32_H5));
    const rot = await restored.execute({ kind: "Rotate", newLmsPubkey: next.publicKey }, { allowForeignKey: true });
    expect(rot.q).to.eq(2);
    const v = await fetchVault(vaultJ);
    expect(v.generation).to.eq(1);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(Buffer.from(next.publicKey));
    expect(JSON.parse(fs.readFileSync(journalPath, "utf8"))).to.deep.eq({ v: 1, generation: 1, spent: 0, reserved: [] });
    const fresh = new sdk.VaultSigner({ rpc: connection, key: next, payer, vault: vaultJ, commitment: "confirmed", journal: new sdk.FileLeafJournal(journalPath) });
    const r2 = await fresh.execute(transfer);
    expect(r2.q).to.eq(0);
    expect(r2.generation).to.eq(1);
    expect(await spent(vaultJ)).to.eq(1);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
