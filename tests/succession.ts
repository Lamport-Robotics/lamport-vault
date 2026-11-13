import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Keypair, PublicKey, Transaction, TransactionInstruction } from "@solana/web3.js";
import { expect } from "chai";
import { LamportVault } from "../target/types/lamport_vault";
import { expectError, expectRejects, fund, loadSdk, provider as makeProvider } from "./helpers";

// The SDK against the Heir-enabled build on a real validator (docs/SUCCESSION.md): a plan signed
// with the vault's own signing flow, and the four instructions that need no vault signature. A
// test validator cannot jump its clock, so everything that needs months to pass (the waiting
// period, the release) is tested in LiteSVM instead (tests/svm/tests/succession*.rs). What this
// adds is the path those tests do not take: the TypeScript signer and builders, real transactions.
//
// The suite exists only for a build with the `succession` feature. Against the vault as it is,
// nothing is registered here, so that run reports exactly the tests it always had.
const provider = makeProvider();
const program = anchor.workspace.lamportVault as Program<LamportVault>;
const SUCCESSION = program.idl.instructions.some((i) => (i.name as string) === "checkin");

if (SUCCESSION) {
  describe("succession: the SDK against the Heir-enabled build", () => {
    const connection = provider.connection;
    const DAY = 86_400n;
    const WINDOW = 90n * DAY;
    const WAIT = 30n * DAY;

    // Classical keys. None of them can move funds: one pays fees, one may check in, one may extend once.
    const payer = Keypair.generate();
    const checkinKey = Keypair.generate();
    const contactKey = Keypair.generate();
    const stranger = Keypair.generate();
    const claim = Keypair.generate().publicKey;
    const recipient = Keypair.generate().publicKey;

    let sdk: any;
    let signer: any;
    let vault: PublicKey;

    /** Sends `ix` with the provider wallet paying: whoever signs the instruction never has to hold SOL. */
    async function send(ix: TransactionInstruction, signers: Keypair[] = []): Promise<string> {
      return provider.sendAndConfirm(new Transaction().add(ix), signers, { commitment: "confirmed" });
    }

    async function succession() {
      const info = await connection.getAccountInfo(vault, "confirmed");
      const decoded = sdk.decodeVault(new Uint8Array(info!.data));
      expect(decoded.version).to.eq(3);
      return decoded.succession;
    }

    /** The cluster's clock, as the program reads it. */
    async function now(): Promise<bigint> {
      const info = await connection.getAccountInfo(anchor.web3.SYSVAR_CLOCK_PUBKEY, "confirmed");
      return info!.data.readBigInt64LE(32); // Clock.unix_timestamp
    }

    const plan = () => ({ claim, windowSecs: WINDOW, waitSecs: WAIT, checkinKey: checkinKey.publicKey, contactKey: contactKey.publicKey });

    before(async () => {
      const loaded = loadSdk();
      sdk = loaded.vault;
      await fund(provider, payer.publicKey, 1);
      const key = loaded.lms.LmsPrivateKey.generate(loaded.lms.randomKeyMaterial(loaded.lms.LMS_SHA256_M32_H5));
      signer = new sdk.VaultSigner({ rpc: connection, programId: program.programId, key, payer, journal: "ephemeral", commitment: "confirmed" });
      const created = await signer.createVault();
      vault = new PublicKey(created.vault.toBase58());
      await fund(provider, vault, 0.2);
    });

    it("a new vault carries an empty plan, and nothing runs without one", async () => {
      const s = await succession();
      expect(s.claim.equals(PublicKey.default)).to.eq(true);
      expect(s.windowSecs).to.eq(0n);
      expect(s.waitOpen).to.eq(false);
      expect(sdk.successionStatus(s, await now()).phase).to.eq("unarmed");

      await expectError(send(sdk.checkinInstruction({ programId: program.programId, vault, checkinKey: checkinKey.publicKey }), [checkinKey]), "NotArmed");
      await expectError(send(sdk.contactExtendInstruction({ programId: program.programId, vault, contactKey: contactKey.publicKey }), [contactKey]), "NotArmed");
      await expectError(send(sdk.startSuccessionInstruction({ programId: program.programId, vault })), "NotArmed");
      await expectError(send(sdk.executeSuccessionInstruction({ programId: program.programId, vault, claim })), "NotArmed");
    });

    it("the signer refuses a plan the program would refuse, before it costs a leaf", async () => {
      await expectRejects(signer.execute({ kind: "SetSuccession", ...plan(), windowSecs: WINDOW - 1n }), /WindowOutOfRange/);
      await expectRejects(signer.execute({ kind: "SetSuccession", ...plan(), waitSecs: WAIT - 1n }), /WaitOutOfRange/);
      await expectRejects(signer.execute({ kind: "SetSuccession", ...plan(), claim: vault }), /ClaimIsTheVault/);
      await expectRejects(signer.execute({ kind: "SetSuccession", ...plan(), claim: program.programId }), /ClaimNotUsable/);
      await expectRejects(signer.execute({ kind: "SetSuccession", ...sdk.CLEAR_SUCCESSION_PLAN, windowSecs: WINDOW }), /ClearCarriesPlan/);
      expect(await signer.nextQ()).to.eq(0);
      expect((await succession()).claim.equals(PublicKey.default)).to.eq(true);
    });

    it("SetSuccession, signed like any other action, arms the plan and starts the clock", async () => {
      const before = await now();
      const res = await signer.execute({ kind: "SetSuccession", ...plan() });
      expect(res.q).to.eq(0);
      const after = await now();

      const s = await succession();
      expect(s.claim.equals(claim)).to.eq(true);
      expect(s.windowSecs).to.eq(WINDOW);
      expect(s.waitSecs).to.eq(WAIT);
      expect(s.checkinKey.equals(checkinKey.publicKey)).to.eq(true);
      expect(s.contactKey.equals(contactKey.publicKey)).to.eq(true);
      expect(s.contactUsed).to.eq(false);
      expect(s.waitOpen).to.eq(false);
      expect(s.lastSignedTs >= before && s.lastSignedTs <= after, `last_signed_ts ${s.lastSignedTs} outside ${before}..${after}`).to.eq(true);

      const status = sdk.successionStatus(s, after);
      expect(status.phase).to.eq("quiet");
      expect(status.deadline).to.eq(s.lastSignedTs + WINDOW);
      // nothing is released sooner than window + wait after the signature
      expect(status.earliestRelease).to.eq(s.lastSignedTs + WINDOW + 1n + WAIT);
    });

    it("only the check-in key checks in; whoever pays the fee is nobody", async () => {
      const ix = (key: PublicKey) => sdk.checkinInstruction({ programId: program.programId, vault, checkinKey: key });
      await expectError(send(ix(stranger.publicKey), [stranger]), "WrongCheckinKey");
      await expectError(send(ix(contactKey.publicKey), [contactKey]), "WrongCheckinKey");

      const before = await succession();
      await send(ix(checkinKey.publicKey), [checkinKey]);
      const s = await succession();
      expect(s.lastCheckinTs >= before.lastSignedTs).to.eq(true);
      expect(s.lastCheckinTs <= (await now())).to.eq(true);
      expect(s.lastSignedTs).to.eq(before.lastSignedTs); // a check-in is not a signature
      expect(sdk.successionStatus(s, await now()).deadline).to.eq(s.lastCheckinTs + WINDOW);
    });

    it("nobody opens a waiting period or releases the vault while the owner is within the window", async () => {
      await expectError(send(sdk.startSuccessionInstruction({ programId: program.programId, vault })), "BeforeDeadline");
      await expectError(send(sdk.executeSuccessionInstruction({ programId: program.programId, vault, claim })), "NoWaitOpen");
      // and never to another address, whatever the clock says
      await expectError(send(sdk.executeSuccessionInstruction({ programId: program.programId, vault, claim: stranger.publicKey })), "NoWaitOpen");
      expect((await succession()).waitOpen).to.eq(false);
    });

    it("the contact extends the deadline by 90 days, once", async () => {
      const ix = (key: PublicKey) => sdk.contactExtendInstruction({ programId: program.programId, vault, contactKey: key });
      await expectError(send(ix(stranger.publicKey), [stranger]), "WrongContactKey");
      await expectError(send(ix(checkinKey.publicKey), [checkinKey]), "WrongContactKey");

      const before = await succession();
      const deadline = sdk.successionStatus(before, await now()).deadline as bigint;
      await send(ix(contactKey.publicKey), [contactKey]);
      const s = await succession();
      expect(s.contactUsed).to.eq(true);
      expect(s.extendedUntilTs).to.eq(deadline + 90n * DAY);
      expect(sdk.successionStatus(s, await now()).deadline).to.eq(deadline + 90n * DAY);

      await expectError(send(ix(contactKey.publicKey), [contactKey]), "ContactAlreadyUsed");
    });

    it("any signed action is a sign of life: it restarts the window and ends the extension", async () => {
      const before = await succession();
      const res = await signer.execute({ kind: "TransferSol", to: recipient, lamports: 1_000_000n });
      expect(res.q).to.eq(1);
      const s = await succession();
      expect(s.lastSignedTs >= before.lastSignedTs).to.eq(true);
      expect(s.extendedUntilTs).to.eq(0n);
      expect(s.contactUsed).to.eq(true); // the extension is spent until the plan is set again
      expect(s.claim.equals(claim)).to.eq(true);
      expect(s.windowSecs).to.eq(WINDOW);
      expect(sdk.successionStatus(s, await now()).phase).to.eq("quiet");
    });

    it("setting the plan again gives the contact one more extension; a clear disarms it", async () => {
      await signer.execute({ kind: "SetSuccession", ...plan() });
      expect((await succession()).contactUsed).to.eq(false);

      const res = await signer.execute({ kind: "SetSuccession", ...sdk.CLEAR_SUCCESSION_PLAN });
      expect(res.q).to.eq(3);
      const s = await succession();
      expect(s.claim.equals(PublicKey.default)).to.eq(true);
      expect(s.windowSecs).to.eq(0n);
      expect(s.checkinKey.equals(PublicKey.default)).to.eq(true);
      expect(sdk.successionStatus(s, await now()).phase).to.eq("unarmed");
      await expectError(send(sdk.checkinInstruction({ programId: program.programId, vault, checkinKey: checkinKey.publicKey }), [checkinKey]), "NotArmed");
      await expectError(send(sdk.startSuccessionInstruction({ programId: program.programId, vault })), "NotArmed");
    });
  });
}
