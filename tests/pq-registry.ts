import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Keypair, PublicKey } from "@solana/web3.js";
import { expect } from "chai";
import { PqRegistry } from "../target/types/pq_registry";
import {
  CHUNK,
  COMPUTE_BUDGET_IX,
  LMS_H5,
  LmsKey,
  commitmentPda,
  consumedUnits,
  expectError,
  fund,
  provider as makeProvider,
  randomNonce,
  registryMessage,
  rotationBufferPda,
} from "./helpers";

describe("pq-registry", () => {
  const provider = makeProvider();
  const program = anchor.workspace.pqRegistry as Program<PqRegistry>;

  const owner = Keypair.generate();
  const payer = Keypair.generate();
  const key1 = LmsKey.random(LMS_H5);
  const key2 = LmsKey.random(LMS_H5);
  let commitment: PublicKey;

  async function stageRotation(key: LmsKey, q: number, newPubkey: Buffer, sig?: Buffer): Promise<PublicKey> {
    const s = sig ?? key.sign(q, registryMessage(owner.publicKey, newPubkey));
    const nonce = randomNonce();
    const [buf] = rotationBufferPda(program.programId, owner.publicKey, payer.publicKey, nonce);
    await program.methods
      .openPqBuffer(nonce, Array.from(newPubkey), s.length)
      .accounts({ payer: payer.publicKey, commitment, pqSigBuffer: buf })
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
    const c = await program.account.commitment.fetch(commitment);
    expect(c.owner.toBase58()).to.eq(owner.publicKey.toBase58());
    expect(c.scheme).to.eq(1);
    expect(Buffer.from(c.pqPubkey)).to.deep.eq(key1.pubkey());
    expect(c.nextQ).to.eq(0);
    expect(c.createdSlot.toNumber()).to.eq(c.updatedSlot.toNumber());
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
    const c = await program.account.commitment.fetch(commitment);
    expect(Buffer.from(c.pqPubkey)).to.deep.eq(key1.pubkey());
  });

  it("rotate_pq wrong key", async () => {
    const impostor = LmsKey.random(LMS_H5);
    const buf = await stageRotation(impostor, 0, key2.pubkey());
    await expectError(rotate(buf), "InvalidSignature");
    const c = await program.account.commitment.fetch(commitment);
    expect(Buffer.from(c.pqPubkey)).to.deep.eq(key1.pubkey());
    expect(c.nextQ).to.eq(0);
    await program.methods.closePqBuffer().accounts({ payer: payer.publicKey, pqSigBuffer: buf }).signers([payer]).rpc();
  });

  it("rotate_pq", async () => {
    const buf = await stageRotation(key1, 3, key2.pubkey());
    const sig = await rotate(buf);
    const c = await program.account.commitment.fetch(commitment);
    expect(Buffer.from(c.pqPubkey)).to.deep.eq(key2.pubkey());
    expect(c.nextQ).to.eq(0);
    expect(c.updatedSlot.toNumber()).to.be.greaterThanOrEqual(c.createdSlot.toNumber());
    expect(await provider.connection.getAccountInfo(buf, "confirmed")).to.eq(null);
    const cu = await consumedUnits(provider, sig, program.programId);
    console.log(`      rotate_pq(H5/W4) consumed ${cu} compute units`);

    // The replaced key cannot rotate any more; the new key can.
    const key3 = LmsKey.random(LMS_H5);
    const stale = await stageRotation(key1, 4, key3.pubkey());
    await expectError(rotate(stale), "InvalidSignature");
    const fresh = await stageRotation(key2, 0, key3.pubkey());
    await rotate(fresh);
    const c2 = await program.account.commitment.fetch(commitment);
    expect(Buffer.from(c2.pqPubkey)).to.deep.eq(key3.pubkey());

    // Rotating to the key already committed is refused.
    const same = await stageRotation(key3, 0, key3.pubkey());
    await expectError(rotate(same), "SameKeyRotation");
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
    const nonce = randomNonce();
    const [buf] = rotationBufferPda(program.programId, other.publicKey, payer.publicKey, nonce);
    const s = otherKey.sign(0, registryMessage(other.publicKey, target));
    await program.methods
      .openPqBuffer(nonce, Array.from(target), s.length)
      .accounts({ payer: payer.publicKey, commitment: otherCommitment, pqSigBuffer: buf })
      .signers([payer])
      .rpc({ commitment: "confirmed" });
    for (let off = 0; off < s.length; off += CHUNK) {
      await program.methods
        .writePqSig(off, s.subarray(off, off + CHUNK))
        .accounts({ payer: payer.publicKey, pqSigBuffer: buf })
        .signers([payer])
        .rpc({ commitment: "confirmed" });
    }
    await expectError(rotate(buf), "OwnerMismatch");
  });
});
