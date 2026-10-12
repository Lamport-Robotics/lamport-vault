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
  fund,
  meta,
  provider as makeProvider,
  randomNonce,
  sha256,
  sigBufferPda,
  vaultMessage,
  vaultPda,
} from "./helpers";

describe("lamport-vault", () => {
  const provider = makeProvider();
  const program = anchor.workspace.lamportVault as Program<LamportVault>;
  const connection = provider.connection;

  // The classical key that pays for staging buffers. It never controls funds.
  const payer = Keypair.generate();
  // The vault owner's hash-based key (H10, the default).
  const keyA = LmsKey.random(LMS_H10);
  let vault: PublicKey;
  const recipient = Keypair.generate();

  const FAR = () => currentSlot(provider).then((s) => s + 5000);

  async function createVault(key: LmsKey): Promise<PublicKey> {
    const [pda] = vaultPda(program.programId, key.pubkey());
    await program.methods
      .createVault(Array.from(sha256(key.pubkey())), Array.from(key.pubkey()))
      .accounts({ payer: provider.wallet.publicKey, vault: pda })
      .rpc({ commitment: "confirmed" });
    return pda;
  }

  /** Signs `actionBytes` with `key` at leaf `q` for `vault` and stages it in chunks. */
  async function stage(
    vaultKey: PublicKey,
    key: LmsKey,
    q: number,
    actionBytes: Buffer,
    opts: { message?: Buffer; sig?: Buffer; sigLen?: number; skipLast?: boolean } = {},
  ): Promise<PublicKey> {
    const sig = opts.sig ?? key.sign(q, opts.message ?? vaultMessage(vaultKey, actionBytes));
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

  async function nextQ(vaultKey: PublicKey): Promise<number> {
    return (await program.account.vault.fetch(vaultKey)).nextQ;
  }

  before(async () => {
    await fund(provider, payer.publicKey, 5);
    await fund(provider, recipient.publicKey, 0.01);
  });

  it("create", async () => {
    vault = await createVault(keyA);
    const v = await program.account.vault.fetch(vault);
    expect(v.version).to.eq(1);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(keyA.pubkey());
    expect(v.nextQ).to.eq(0);
    expect(v.rotations).to.eq(0);
    expect(v.createdSlot.toNumber()).to.be.greaterThan(0);
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
    const badLms = Buffer.from(keyA.pubkey());
    badLms.writeUInt32BE(9, 0); // H25
    const [pda2] = vaultPda(program.programId, badLms);
    await expectError(
      program.methods
        .createVault(Array.from(sha256(badLms)), Array.from(badLms))
        .accounts({ payer: provider.wallet.publicKey, vault: pda2 })
        .rpc(),
      "InvalidLmsType",
    );
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
    const v = await program.account.vault.fetch(pda);
    expect(v.nextQ).to.eq(0);
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
    expect(await nextQ(vault)).to.eq(1);
    // Buffer closed, rent back to payer.
    expect(await connection.getAccountInfo(buf, "confirmed")).to.eq(null);
    const payerAfter = await connection.getBalance(payer.publicKey, "confirmed");
    expect(payerAfter).to.be.greaterThan(payerBefore);

    const cu = await consumedUnits(provider, sig, program.programId);
    console.log(`      execute(TransferSol, H10/W4) consumed ${cu} compute units`);
    expect(cu).to.be.lessThan(400_000);
  });

  it("replay", async () => {
    const action = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const buf = await stage(vault, keyA, 0, action);
    await expectError(execute(vault, buf, [meta(recipient.publicKey, true)]), "LeafAlreadyUsed");
    expect(await nextQ(vault)).to.eq(1);
    // Clean up the buffer: refund goes to the payer.
    await program.methods.closeSigBuffer().accounts({ payer: payer.publicKey, sigBuffer: buf }).signers([payer]).rpc();
    expect(await connection.getAccountInfo(buf)).to.eq(null);
  });

  it("gap then stale q", async () => {
    const action = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const buf = await stage(vault, keyA, 5, action);
    await execute(vault, buf, [meta(recipient.publicKey, true)]);
    expect(await nextQ(vault)).to.eq(6);

    const action2 = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const buf2 = await stage(vault, keyA, 3, action2);
    await expectError(execute(vault, buf2, [meta(recipient.publicKey, true)]), "LeafAlreadyUsed");
    expect(await nextQ(vault)).to.eq(6);
  });

  it("expired", async () => {
    const slot = await currentSlot(provider);
    const action = Action.transferSol(recipient.publicKey, 1000, Math.max(0, slot - 1));
    const buf = await stage(vault, keyA, 6, action);
    await expectError(execute(vault, buf, [meta(recipient.publicKey, true)]), "ActionExpired");
    expect(await nextQ(vault)).to.eq(6);
  });

  it("wrong vault", async () => {
    const keyB = LmsKey.random(LMS_H5);
    const vaultB = await createVault(keyB);
    const action = Action.transferSol(recipient.publicKey, 1000, await FAR());
    // Key A signs the message for vault B, staged on vault A: wrong binding.
    const buf = await stage(vault, keyA, 6, action, { message: vaultMessage(vaultB, action) });
    await expectError(execute(vault, buf, [meta(recipient.publicKey, true)]), "InvalidSignature");
    expect(await nextQ(vault)).to.eq(6);

    // A buffer opened on vault B cannot be executed against vault A.
    const bufB = await stage(vaultB, keyB, 0, action);
    await expectError(execute(vault, bufB, [meta(recipient.publicKey, true)]), "VaultMismatch");
  });

  it("tampered sig / wrong dest / short buffer", async () => {
    const action = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const good = keyA.sign(6, vaultMessage(vault, action));
    const bad = Buffer.from(good);
    bad[100] ^= 0x01;
    const buf = await stage(vault, keyA, 6, action, { sig: bad });
    await expectError(execute(vault, buf, [meta(recipient.publicKey, true)]), "InvalidSignature");

    const buf2 = await stage(vault, keyA, 6, action, { sig: good });
    const other = Keypair.generate().publicKey;
    await expectError(execute(vault, buf2, [meta(other, true)]), "WrongDestination");
    await expectError(execute(vault, buf2, []), "MissingAccount");

    const buf3 = await stage(vault, keyA, 6, action, { sig: good, skipLast: true });
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
    // Completing the buffer afterwards makes it executable; the good sig at q=6 goes through.
    await program.methods
      .writeSig(staged.filled, good.subarray(staged.filled))
      .accounts({ payer: payer.publicKey, sigBuffer: buf3 })
      .signers([payer])
      .rpc({ commitment: "confirmed" });
    await execute(vault, buf3, [meta(recipient.publicKey, true)]);
    expect(await nextQ(vault)).to.eq(7);
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
    const buf2 = await stage(vault, keyA, 7, greedy);
    await expectError(execute(vault, buf2, [meta(recipient.publicKey, true)]), "InsufficientFunds");
    expect(await nextQ(vault)).to.eq(7);
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

      const q = await nextQ(vault);
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
      const q2 = await nextQ(vault);
      const action2 = Action.transferToken(mint, destAta, 1, await FAR());
      const buf2 = await stage(vault, keyA, q2, action2);
      const otherAta = await spl.createAssociatedTokenAccount(connection, wallet, mint, Keypair.generate().publicKey, { commitment: "confirmed" }, tokenProgram);
      await expectError(execute(vault, buf2, [meta(vaultAta, true), meta(otherAta, true), meta(mint, false), meta(tokenProgram, false)]), "WrongDestination");
      await expectError(execute(vault, buf2, [meta(vaultAta, true), meta(destAta, true), meta(vaultAta, false), meta(tokenProgram, false)]), "WrongMint");
      await expectError(execute(vault, buf2, [meta(vaultAta, true), meta(destAta, true), meta(mint, false), meta(SystemProgram.programId, false)]), "InvalidTokenProgram");
      await program.methods.closeSigBuffer().accounts({ payer: payer.publicKey, sigBuffer: buf2 }).signers([payer]).rpc();
    });
  }

  it("rotate", async () => {
    const keyC = LmsKey.random(LMS_H10);
    const q = await nextQ(vault);
    const action = Action.rotate(keyC.pubkey(), await FAR());
    const buf = await stage(vault, keyA, q, action);
    const sig = await execute(vault, buf, []);
    const v = await program.account.vault.fetch(vault);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(keyC.pubkey());
    expect(v.nextQ).to.eq(0);
    expect(v.rotations).to.eq(1);
    // vault_id and address are unchanged.
    expect(Buffer.from(v.vaultId)).to.deep.eq(Buffer.from((await program.account.vault.fetch(vault)).vaultId));
    const cu = await consumedUnits(provider, sig, program.programId);
    console.log(`      execute(Rotate, H10/W4) consumed ${cu} compute units`);

    // Old key: its signature no longer verifies under the new public key.
    const spend = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const bufOld = await stage(vault, keyA, 50, spend);
    await expectError(execute(vault, bufOld, [meta(recipient.publicKey, true)]), "InvalidSignature");

    // New key, leaf 0.
    const bufNew = await stage(vault, keyC, 0, spend);
    await execute(vault, bufNew, [meta(recipient.publicKey, true)]);
    expect(await nextQ(vault)).to.eq(1);

    // Rotating to the key already in use is refused.
    const same = Action.rotate(keyC.pubkey(), await FAR());
    const bufSame = await stage(vault, keyC, 1, same);
    await expectError(execute(vault, bufSame, []), "SameKeyRotation");
  });

  it("last leaf only rotate", async () => {
    const keyD = LmsKey.random(LMS_H5);
    const vaultD = await createVault(keyD);
    await fund(provider, vaultD, 0.2);

    const spend = Action.transferSol(recipient.publicKey, 1000, await FAR());
    const buf = await stage(vaultD, keyD, 31, spend);
    await expectError(execute(vaultD, buf, [meta(recipient.publicKey, true)]), "LastLeafReservedForRotate");
    expect(await nextQ(vaultD)).to.eq(0);

    // q = 32 does not exist in an H5 tree.
    const sig31 = keyD.sign(31, vaultMessage(vaultD, spend));
    const sig32 = Buffer.from(sig31);
    sig32.writeUInt32BE(32, 0);
    const bufOut = await stage(vaultD, keyD, 31, spend, { sig: sig32 });
    await expectError(execute(vaultD, bufOut, [meta(recipient.publicKey, true)]), "LeafOutOfRange");

    const keyE = LmsKey.random(LMS_H5);
    const rotate = Action.rotate(keyE.pubkey(), await FAR());
    const bufRot = await stage(vaultD, keyD, 31, rotate);
    await execute(vaultD, bufRot, []);
    const v = await program.account.vault.fetch(vaultD);
    expect(Buffer.from(v.lmsPubkey)).to.deep.eq(keyE.pubkey());
    expect(v.nextQ).to.eq(0);
    expect(v.rotations).to.eq(1);

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
});
