import * as anchor from "@coral-xyz/anchor";
import { BN, Program } from "@coral-xyz/anchor";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { expect } from "chai";
import { PqRegistry } from "../target/types/pq_registry";
import {
  CHUNK,
  COMPUTE_BUDGET_IX,
  LMS_H5,
  LmsKey,
  type Window,
  commitmentPda,
  consumedUnits,
  currentSlot,
  expectError,
  expiredWindow,
  fund,
  keyHash,
  provider as makeProvider,
  randomNonce,
  registryMessage,
  rotationBufferPda,
  window,
} from "./helpers";

describe("pq-registry", () => {
  const provider = makeProvider();
  const program = anchor.workspace.pqRegistry as Program<PqRegistry>;
  const connection = provider.connection;

  const owner = Keypair.generate();
  const payer = Keypair.generate();
  const key1 = LmsKey.random(LMS_H5);
  const key2 = LmsKey.random(LMS_H5);
  const key3 = LmsKey.random(LMS_H5);
  let commitment: PublicKey;

  /** `MAX_KEY_HISTORY` of the deployed build (32, or 2 with `--features small-history`). */
  const MAX_KEY_HISTORY = Number(program.idl.constants.find((c) => c.name === "maxKeyHistory")!.value);
  /** `MAX_VALIDITY_SLOTS`: the longest rotation window the program accepts. */
  const MAX_VALIDITY_SLOTS = Number(program.idl.constants.find((c) => c.name === "maxValiditySlots")!.value);

  async function fetchCommitment(c = commitment) {
    const v = await program.account.commitment.fetch(c);
    return { ...v, usedKeys: v.usedKeys.map((k) => Buffer.from(k)) };
  }

  /**
   * Signs the rotation to `newPubkey` with `key` at leaf `q`, bound to the commitment's generation
   * unless given and to a window (default: issued now, 5 000 slots), and stages it.
   */
  async function stageRotation(
    key: LmsKey,
    q: number,
    newPubkey: Buffer,
    opts: { sig?: Buffer; generation?: number; owner?: PublicKey; commitment?: PublicKey; message?: Buffer; window?: Window } = {},
  ): Promise<PublicKey> {
    const own = opts.owner ?? owner.publicKey;
    const c = opts.commitment ?? commitment;
    const generation = opts.generation ?? (await fetchCommitment(c)).generation;
    const w = opts.window ?? (await window(provider));
    const s = opts.sig ?? key.sign(q, opts.message ?? registryMessage(program.programId, own, generation, newPubkey, w));
    const nonce = randomNonce();
    const [buf] = rotationBufferPda(program.programId, own, payer.publicKey, nonce);
    await program.methods
      .openPqBuffer(nonce, Array.from(newPubkey), s.length, new BN(w.issued), new BN(w.expiry))
      .accounts({ payer: payer.publicKey, commitment: c, pqSigBuffer: buf })
      .signers([payer])
      .rpc({ commitment: "confirmed" });
    for (let off = 0; off < s.length; off += CHUNK) {
      await program.methods
        .writePqSig(off, s.subarray(off, off + CHUNK))
        .accounts({ payer: payer.publicKey, pqSigBuffer: buf })
        .signers([payer])
        .rpc({ commitment: "confirmed" });
    }
    return buf;
  }

  async function rotate(buf: PublicKey) {
    return program.methods
      .rotatePq()
      .accounts({ commitment, pqSigBuffer: buf, payer: payer.publicKey })
      .preInstructions([COMPUTE_BUDGET_IX])
      .rpc({ commitment: "confirmed" });
  }

  before(async () => {
    await fund(provider, owner.publicKey, 0.1);
    await fund(provider, payer.publicKey, 2);
    [commitment] = commitmentPda(program.programId, owner.publicKey);
  });

  it("commit", async () => {
    await program.methods
      .commit(Array.from(key1.pubkey()))
      .accounts({ owner: owner.publicKey, payer: payer.publicKey, commitment })
      .signers([owner, payer])
      .rpc({ commitment: "confirmed" });
    const c = await fetchCommitment();
    expect(c.version).to.eq(2);
    expect(c.owner.toBase58()).to.eq(owner.publicKey.toBase58());
    expect(c.scheme).to.eq(1);
    expect(Buffer.from(c.pqPubkey)).to.deep.eq(key1.pubkey());
    expect(c.nextQ).to.eq(0);
    expect(c.generation).to.eq(0);
    expect(c.usedKeys).to.deep.eq([]);
    expect(c.createdSlot.toNumber()).to.eq(c.updatedSlot.toNumber());
    expect((await connection.getAccountInfo(commitment, "confirmed"))!.data.length).to.eq(127);
  });

  it("second commit", async () => {
    await expectError(
      program.methods
        .commit(Array.from(key2.pubkey()))
        .accounts({ owner: owner.publicKey, payer: payer.publicKey, commitment })
        .signers([owner, payer])
        .rpc(),
      "AlreadyInUse",
    );
    const c = await fetchCommitment();
    expect(Buffer.from(c.pqPubkey)).to.deep.eq(key1.pubkey());
  });

  it("rotate_pq wrong key / wrong program id", async () => {
    const impostor = LmsKey.random(LMS_H5);
    const buf = await stageRotation(impostor, 0, key2.pubkey());
    await expectError(rotate(buf), "InvalidSignature");
    const w = await window(provider);
    const other = await stageRotation(key1, 0, key2.pubkey(), {
      window: w,
      message: registryMessage(SystemProgram.programId, owner.publicKey, 0, key2.pubkey(), w),
    });
    await expectError(rotate(other), "InvalidSignature");
    const c = await fetchCommitment();
    expect(Buffer.from(c.pqPubkey)).to.deep.eq(key1.pubkey());
    expect(c.nextQ).to.eq(0);
    await program.methods.closePqBuffer().accounts({ payer: payer.publicKey, pqSigBuffer: buf }).signers([payer]).rpc();
    await program.methods.closePqBuffer().accounts({ payer: payer.publicKey, pqSigBuffer: other }).signers([payer]).rpc();
  });

  it("rotate_pq: generation + 1, old key in history, buffer payer pays the 16 bytes", async () => {
    const buf = await stageRotation(key1, 3, key2.pubkey());
    const lamportsBefore = await connection.getBalance(commitment, "confirmed");
    const bufferLamports = await connection.getBalance(buf, "confirmed");
    const payerBefore = await connection.getBalance(payer.publicKey, "confirmed");
    const sig = await rotate(buf);
    const c = await fetchCommitment();
    expect(Buffer.from(c.pqPubkey)).to.deep.eq(key2.pubkey());
    expect(c.nextQ).to.eq(0);
    expect(c.generation).to.eq(1);
    expect(c.usedKeys).to.deep.eq([keyHash(key1.pubkey())]);
    expect(c.updatedSlot.toNumber()).to.be.greaterThanOrEqual(c.createdSlot.toNumber());
    expect(await connection.getAccountInfo(buf, "confirmed")).to.eq(null);
    const info = await connection.getAccountInfo(commitment, "confirmed");
    expect(info!.data.length).to.eq(127 + 16);
    const delta = (await connection.getMinimumBalanceForRentExemption(127 + 16)) - (await connection.getMinimumBalanceForRentExemption(127));
    expect(info!.lamports).to.eq(lamportsBefore + delta);
    expect((await connection.getBalance(payer.publicKey, "confirmed")) - payerBefore).to.eq(bufferLamports - delta);
    const cu = await consumedUnits(provider, sig, program.programId);
    console.log(`      rotate_pq(H5/W4) consumed ${cu} compute units`);

    // The replaced key cannot rotate any more; the new key can.
    const stale = await stageRotation(key1, 4, key3.pubkey());
    await expectError(rotate(stale), "InvalidSignature");
    const fresh = await stageRotation(key2, 0, key3.pubkey());
    await rotate(fresh);
    const c2 = await fetchCommitment();
    expect(Buffer.from(c2.pqPubkey)).to.deep.eq(key3.pubkey());
    expect(c2.generation).to.eq(2);
    expect(c2.usedKeys).to.deep.eq([keyHash(key1.pubkey()), keyHash(key2.pubkey())]);
  });

  it("rotate_pq refuses the committed key and every past key (1 -> 2 -> 3 -> 1)", async () => {
    const same = await stageRotation(key3, 0, key3.pubkey());
    await expectError(rotate(same), "KeyReused");
    const back1 = await stageRotation(key3, 0, key1.pubkey());
    await expectError(rotate(back1), "KeyReused");
    const back2 = await stageRotation(key3, 0, key2.pubkey());
    await expectError(rotate(back2), "KeyReused");
    const c = await fetchCommitment();
    expect(Buffer.from(c.pqPubkey)).to.deep.eq(key3.pubkey());
    expect(c.nextQ).to.eq(0);
    expect(c.generation).to.eq(2);
  });

  it("old-generation signature is refused even on a fresh leaf", async () => {
    // Own commitment (so this works under any MAX_KEY_HISTORY): commit kA, rotate to kB (generation 1).
    const own = Keypair.generate();
    await fund(provider, own.publicKey, 0.1);
    const [c] = commitmentPda(program.programId, own.publicKey);
    const kA = LmsKey.random(LMS_H5);
    const kB = LmsKey.random(LMS_H5);
    const kC = LmsKey.random(LMS_H5);
    await program.methods
      .commit(Array.from(kA.pubkey()))
      .accounts({ owner: own.publicKey, payer: payer.publicKey, commitment: c })
      .signers([own, payer])
      .rpc({ commitment: "confirmed" });
    const rotateOwn = (buf: PublicKey) =>
      program.methods
        .rotatePq()
        .accounts({ commitment: c, pqSigBuffer: buf, payer: payer.publicKey })
        .preInstructions([COMPUTE_BUDGET_IX])
        .rpc({ commitment: "confirmed" });
    await rotateOwn(await stageRotation(kA, 0, kB.pubkey(), { owner: own.publicKey, commitment: c }));
    expect((await fetchCommitment(c)).generation).to.eq(1);
    // kB is committed at generation 1; its signature over the generation-0 message is worthless.
    const stale = await stageRotation(kB, 0, kC.pubkey(), { owner: own.publicKey, commitment: c, generation: 0 });
    await expectError(rotateOwn(stale), "InvalidSignature");
    expect((await fetchCommitment(c)).nextQ).to.eq(0);
    // Same leaf, current generation: accepted.
    await rotateOwn(await stageRotation(kB, 0, kC.pubkey(), { owner: own.publicKey, commitment: c, generation: 1 }));
    const after = await fetchCommitment(c);
    expect(Buffer.from(after.pqPubkey)).to.deep.eq(kC.pubkey());
    expect(after.generation).to.eq(2);
    expect(after.usedKeys).to.deep.eq([keyHash(kA.pubkey()), keyHash(kB.pubkey())]);
  });

  it("validity window: expired, issued in the future, too long; one day accepted; the window is signed", async () => {
    expect(MAX_VALIDITY_SLOTS).to.eq(216_000);
    const own = Keypair.generate();
    await fund(provider, own.publicKey, 0.1);
    const [c] = commitmentPda(program.programId, own.publicKey);
    const kA = LmsKey.random(LMS_H5);
    const kB = LmsKey.random(LMS_H5);
    await program.methods
      .commit(Array.from(kA.pubkey()))
      .accounts({ owner: own.publicKey, payer: payer.publicKey, commitment: c })
      .signers([own, payer])
      .rpc({ commitment: "confirmed" });
    const rotateOwn = (buf: PublicKey) =>
      program.methods
        .rotatePq()
        .accounts({ commitment: c, pqSigBuffer: buf, payer: payer.publicKey })
        .preInstructions([COMPUTE_BUDGET_IX])
        .rpc({ commitment: "confirmed" });
    const slot = await currentSlot(provider);
    const stage = (w: Window) => stageRotation(kA, 0, kB.pubkey(), { owner: own.publicKey, commitment: c, window: w });

    await expectError(rotateOwn(await stage(await expiredWindow(provider))), "RotationExpired");
    await expectError(rotateOwn(await stage({ issued: slot + 1000, expiry: slot + 2000 })), "IssuedInFuture");
    await expectError(rotateOwn(await stage({ issued: slot, expiry: slot + MAX_VALIDITY_SLOTS + 1 })), "InvalidValidityWindow");
    await expectError(rotateOwn(await stage({ issued: 0, expiry: new BN("18446744073709551615") })), "InvalidValidityWindow");
    // The buffer's window must be the signed one: a buffer opened with another window than the signature covers fails to verify.
    const signedW = await window(provider);
    const sig = kA.sign(0, registryMessage(program.programId, own.publicKey, 0, kB.pubkey(), signedW));
    const swapped = await stageRotation(kA, 0, kB.pubkey(), { owner: own.publicKey, commitment: c, sig, window: { issued: signedW.issued, expiry: Number(signedW.expiry) + 1 } });
    await expectError(rotateOwn(swapped), "InvalidSignature");
    let st = await fetchCommitment(c);
    expect(st.generation).to.eq(0);
    expect(st.nextQ).to.eq(0);
    expect(Buffer.from(st.pqPubkey)).to.deep.eq(kA.pubkey());

    // Exactly one day is accepted.
    const now = await currentSlot(provider);
    await rotateOwn(await stage({ issued: now, expiry: now + MAX_VALIDITY_SLOTS }));
    st = await fetchCommitment(c);
    expect(st.generation).to.eq(1);
    expect(Buffer.from(st.pqPubkey)).to.deep.eq(kB.pubkey());
    expect(st.updatedSlot.toNumber()).to.be.greaterThanOrEqual(now);
  });

  it("foreign buffer", async () => {
    const other = Keypair.generate();
    await fund(provider, other.publicKey, 0.1);
    const otherKey = LmsKey.random(LMS_H5);
    const [otherCommitment] = commitmentPda(program.programId, other.publicKey);
    await program.methods
      .commit(Array.from(otherKey.pubkey()))
      .accounts({ owner: other.publicKey, payer: payer.publicKey, commitment: otherCommitment })
      .signers([other, payer])
      .rpc({ commitment: "confirmed" });
    const target = LmsKey.random(LMS_H5).pubkey();
    const buf = await stageRotation(otherKey, 0, target, { owner: other.publicKey, commitment: otherCommitment });
    await expectError(rotate(buf), "OwnerMismatch");
  });

  it("history full: after MAX_KEY_HISTORY rotations no further rotation", async function () {
    if (MAX_KEY_HISTORY > 4) {
      console.log(`      MAX_KEY_HISTORY = ${MAX_KEY_HISTORY}; run \`anchor test -- --features small-history\` to exercise HistoryFull`);
      expect(MAX_KEY_HISTORY).to.eq(32);
      this.skip();
    }
    const own = Keypair.generate();
    await fund(provider, own.publicKey, 0.1);
    const [c] = commitmentPda(program.programId, own.publicKey);
    let key = LmsKey.random(LMS_H5);
    await program.methods
      .commit(Array.from(key.pubkey()))
      .accounts({ owner: own.publicKey, payer: payer.publicKey, commitment: c })
      .signers([own, payer])
      .rpc({ commitment: "confirmed" });
    const rotateOwn = (buf: PublicKey) =>
      program.methods
        .rotatePq()
        .accounts({ commitment: c, pqSigBuffer: buf, payer: payer.publicKey })
        .preInstructions([COMPUTE_BUDGET_IX])
        .rpc({ commitment: "confirmed" });
    for (let i = 0; i < MAX_KEY_HISTORY; i++) {
      const next = LmsKey.random(LMS_H5);
      await rotateOwn(await stageRotation(key, 0, next.pubkey(), { owner: own.publicKey, commitment: c }));
      key = next;
    }
    expect((await fetchCommitment(c)).generation).to.eq(MAX_KEY_HISTORY);
    const full = await stageRotation(key, 0, LmsKey.random(LMS_H5).pubkey(), { owner: own.publicKey, commitment: c });
    await expectError(rotateOwn(full), "HistoryFull");
    expect((await fetchCommitment(c)).nextQ).to.eq(0);
  });
});
