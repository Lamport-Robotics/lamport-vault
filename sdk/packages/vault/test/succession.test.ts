/**
 * The succession feature in the SDK: the `SetSuccession` action, the version-3 vault, the clock
 * rules mirrored from `programs/lamport-vault/src/succession.rs`, the four instructions, and what
 * `VaultSigner` refuses before it spends a leaf. The vectors in kat/succession_encoding.json are
 * read by the Rust tests too, so the two sides cannot drift apart.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Keypair, PublicKey, type AccountInfo } from "@solana/web3.js";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { fromHex, LMS_SHA256_M32_H10, LMS_SHA256_M32_H15, LMS_SHA256_M32_H5, LmsPrivateKey, toHex } from "@lamport-robotics/lms";
import {
  decodeSuccessionBlock,
  decodeVault,
  emptySuccession,
  encodeTombstone,
  encodeVault,
  SUCCESSION_BLOCK_OFFSET,
  SUCCESSION_BLOCK_SIZE,
  type SuccessionState,
  TOMBSTONE_ACCOUNT_VERSION,
  type VaultAccount,
  vaultAccountSize,
} from "../src/accounts.ts";
import { ACTION_SIZES, decodeAction, encodeAction, MAX_ACTION_BYTES } from "../src/action.ts";
import { ByteReader, ByteWriter } from "../src/borsh.ts";
import { readBool, readI64, writeBool, writeI64 } from "../src/borshExtra.ts";
import { IX, instructionDiscriminator } from "../src/discriminator.ts";
import { executeRemainingAccounts } from "../src/instructions.ts";
import { MemoryLeafJournal } from "../src/journal.ts";
import { vaultMessage } from "../src/message.ts";
import { findVaultPdaForKey, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, vaultId } from "../src/pda.ts";
import { LAMPORT_VAULT_PROGRAM_ID } from "../src/programIds.ts";
import { VaultSigner } from "../src/signer.ts";
import {
  checkinCountsUntil,
  checkinInstruction,
  checkSuccessionPlan,
  CLEAR_SUCCESSION_PLAN,
  contactExtendInstruction,
  decodeHeirAction,
  encodeHeirAction,
  type HeirAction,
  SET_SUCCESSION_ACTION_SIZE,
  SET_SUCCESSION_VARIANT,
  executeSuccessionInstruction,
  isSuccessionArmed,
  SHORT_SUCCESSION_CLOCK,
  startSuccessionInstruction,
  SUCCESSION_CLOCK,
  successionActivity,
  successionClockFor,
  successionDeadline,
  successionLimits,
  type SuccessionPlan,
  successionReleaseAt,
  successionStatus,
  LAMPORT_VAULT_HEIR_PROGRAM_ID,
  LAMPORT_VAULT_HEIR_SHORT_CLOCKS_PROGRAM_ID,
} from "../src/succession.ts";
import { buildSuccessionKat } from "../scripts/succession-kat.ts";
import { MockChain } from "./mock.ts";

beforeAll(() => {
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

const DAY = 86_400n;
const T0 = 1_800_000_000n;
const CLAIM = new PublicKey(new Uint8Array(32).fill(0x11));
const CHECKIN = new PublicKey(new Uint8Array(32).fill(0x44));
const CONTACT = new PublicKey(new Uint8Array(32).fill(0x55));
const WINDOW = { issuedSlot: 1000n, expirySlot: 1300n };

const armed = (over: Partial<SuccessionState> = {}): SuccessionState => ({
  ...emptySuccession(),
  claim: CLAIM,
  windowSecs: 365n * DAY,
  waitSecs: 60n * DAY,
  lastSignedTs: T0,
  checkinKey: CHECKIN,
  contactKey: CONTACT,
  ...over,
});

const plan = (over: Partial<SuccessionPlan> = {}): SuccessionPlan => ({ claim: CLAIM, windowSecs: 365n * DAY, waitSecs: 60n * DAY, checkinKey: CHECKIN, contactKey: CONTACT, ...over });

describe("kat/succession_encoding.json", () => {
  it("is what the SDK builds today", () => {
    const onDisk = JSON.parse(readFileSync(fileURLToPath(new URL("../../../../kat/succession_encoding.json", import.meta.url)), "utf8"));
    expect(JSON.parse(JSON.stringify(buildSuccessionKat()))).toEqual(onDisk);
  });
});

describe("the SetSuccession action", () => {
  const a: HeirAction = { kind: "SetSuccession", ...plan(), ...WINDOW };

  it("is variant 5, 129 bytes, and round-trips", () => {
    const bytes = encodeHeirAction(a);
    expect(SET_SUCCESSION_VARIANT).toBe(5);
    expect(bytes[0]).toBe(5);
    expect(bytes.length).toBe(129);
    expect(SET_SUCCESSION_ACTION_SIZE).toBe(129);
    expect(bytes.length).toBeLessThanOrEqual(MAX_ACTION_BYTES);
    expect(decodeHeirAction(bytes)).toEqual(a);
    // claim || window || wait || check-in key || contact key || issued || expiry
    expect(toHex(bytes.subarray(1, 33))).toBe("11".repeat(32));
    expect(new ByteReader(bytes.subarray(33, 49)).u64()).toBe(365n * DAY);
    expect(toHex(bytes.subarray(49, 81))).toBe("44".repeat(32));
    expect(toHex(bytes.subarray(81, 113))).toBe("55".repeat(32));
    expect(new ByteReader(bytes.subarray(121, 129)).u64()).toBe(1300n);
  });

  it("refuses a byte too many or too few", () => {
    const bytes = encodeHeirAction(a);
    expect(() => decodeHeirAction(Uint8Array.of(...bytes, 0))).toThrow(/trailing/);
    expect(() => decodeHeirAction(bytes.subarray(0, 128))).toThrow();
  });

  it("clears with every field zero", () => {
    const clear: HeirAction = { kind: "SetSuccession", ...CLEAR_SUCCESSION_PLAN, ...WINDOW };
    const bytes = encodeHeirAction(clear);
    expect(bytes.subarray(1, 113).every((b) => b === 0)).toBe(true);
    expect(decodeHeirAction(bytes)).toEqual(clear);
  });

  it("belongs to the Heir-enabled program only: the vault's own codec does not know it", () => {
    expect(() => decodeAction(encodeHeirAction(a))).toThrow(/unknown Action variant 5/);
    expect("SetSuccession" in ACTION_SIZES).toBe(false);
    // and the vault's five actions encode the same through either codec
    const close = { kind: "Close" as const, to: CLAIM, ...WINDOW };
    expect(toHex(encodeHeirAction(close))).toBe(toHex(encodeAction(close)));
    expect(decodeHeirAction(encodeAction(close))).toEqual(close);
    expect(() => decodeHeirAction(Uint8Array.of(6, 0, 0))).toThrow(/unknown Action variant 6/);
  });

  it("passes the claim account to execute, and nothing when clearing", () => {
    const vault = Keypair.generate().publicKey;
    expect(executeRemainingAccounts(vault, a)).toEqual([{ pubkey: CLAIM, isSigner: false, isWritable: false }]);
    expect(executeRemainingAccounts(vault, { kind: "SetSuccession", ...CLEAR_SUCCESSION_PLAN, ...WINDOW })).toEqual([]);
  });
});

describe("the version-3 vault", () => {
  const key = fromHex("000000050000000300112233445566778899aabbccddeeffcd079a17aad0d1f9554c1812f20a4d465dd0503acd83608f890a58d715e20253");
  const v3 = (succession: SuccessionState): VaultAccount => ({
    version: 3,
    bump: 254,
    vaultId: vaultId(key),
    lmsPubkey: key,
    spent: 1,
    generation: 0,
    createdSlot: 77n,
    succession,
    used: Uint8Array.of(1, 0, 0, 0),
    usedKeys: [],
  });

  it("carries a 200-byte block at offset 114 and round-trips", () => {
    const s = armed({ lastCheckinTs: T0 + 5n, contactUsed: true, extendedUntilTs: T0 + 9n, waitOpen: true, waitStartedTs: T0 + 11n });
    const bytes = encodeVault(v3(s));
    expect(bytes.length).toBe(vaultAccountSize(LMS_SHA256_M32_H5, 0, 3));
    expect(bytes.length).toBe(126 + 200);
    expect(decodeVault(bytes)).toEqual(v3(s));
    expect([SUCCESSION_BLOCK_OFFSET, SUCCESSION_BLOCK_SIZE]).toEqual([114, 200]);
    expect(decodeSuccessionBlock(bytes.subarray(114, 314))).toEqual(s);
    // an unarmed block is all zero
    const empty = encodeVault(v3(emptySuccession()));
    expect(empty.subarray(114, 314).every((b) => b === 0)).toBe(true);
    expect(isSuccessionArmed(decodeVault(empty).succession!)).toBe(false);
  });

  it("has the sizes the program allocates", () => {
    expect(vaultAccountSize(LMS_SHA256_M32_H5, 0, 3)).toBe(326);
    expect(vaultAccountSize(LMS_SHA256_M32_H10, 0, 3)).toBe(450);
    expect(vaultAccountSize(LMS_SHA256_M32_H15, 2, 3)).toBe(4418 + 32);
    // the vault program's own sizes did not move
    expect(vaultAccountSize(LMS_SHA256_M32_H5)).toBe(126);
    expect(vaultAccountSize(LMS_SHA256_M32_H10, 3)).toBe(250 + 48);
  });

  it("leaves a version-2 vault exactly as it was", () => {
    const { succession: _, ...rest } = v3(emptySuccession());
    const v2: VaultAccount = { ...rest, version: 2 };
    const bytes = encodeVault(v2);
    expect(bytes.length).toBe(126);
    const back = decodeVault(bytes);
    expect(back).toEqual(v2);
    expect("succession" in back).toBe(false);
  });

  it("refuses a layout that does not match its version", () => {
    const { succession: _, ...noBlock } = v3(emptySuccession());
    expect(() => encodeVault(noBlock as VaultAccount)).toThrow(/version-3 vault carries a succession block/);
    expect(() => encodeVault({ ...v3(emptySuccession()), version: 2 })).toThrow(/version-2 vault has no succession block/);
    const bytes = encodeVault(v3(emptySuccession()));
    const v4 = Uint8Array.from(bytes);
    v4[8] = 4;
    expect(() => decodeVault(v4)).toThrow(/version 4 is not supported/);
    // version 3 bytes read as version 2 leave 200 bytes over
    const as2 = Uint8Array.from(bytes);
    as2[8] = 2;
    expect(() => decodeVault(as2)).toThrow();
    // a bool that is neither 0 nor 1
    const badBool = Uint8Array.from(bytes);
    badBool[114 + 128] = 2;
    expect(() => decodeVault(badBool)).toThrow(/bool/);
    expect(() => decodeSuccessionBlock(new Uint8Array(199))).toThrow(/200 bytes/);
  });

  it("reads and writes signed 64-bit times", () => {
    for (const x of [0n, 1n, -1n, T0, -T0, (1n << 63n) - 1n, -(1n << 63n)]) {
      expect(readI64(new ByteReader(writeI64(new ByteWriter(), x).bytes()))).toBe(x);
    }
    expect(() => writeI64(new ByteWriter(), 1n << 63n)).toThrow(RangeError);
    expect(() => writeI64(new ByteWriter(), -(1n << 63n) - 1n)).toThrow(RangeError);
    expect(toHex(writeI64(new ByteWriter(), -1n).bytes())).toBe("ff".repeat(8));
    expect(readI64(new ByteReader(writeI64(new ByteWriter(), 7).bytes()))).toBe(7n);
  });

  it("reads and writes bools as one byte, 0 or 1", () => {
    expect(toHex(writeBool(writeBool(new ByteWriter(), true), false).bytes())).toBe("0100");
    expect(readBool(new ByteReader(Uint8Array.of(1)))).toBe(true);
    expect(readBool(new ByteReader(Uint8Array.of(0)))).toBe(false);
    expect(() => readBool(new ByteReader(Uint8Array.of(2)))).toThrow(/bool/);
  });

  it("keeps the Borsh classes the cold signer bundles as they were", () => {
    // web/signer.html bundles ByteWriter and ByteReader whole; a method added to either changes
    // that file. Succession's extra field types are functions in borshExtra.ts instead.
    for (const name of ["i64", "bool"]) {
      expect(name in ByteWriter.prototype, `ByteWriter.${name}`).toBe(false);
      expect(name in ByteReader.prototype, `ByteReader.${name}`).toBe(false);
    }
  });
});

describe("the clock, as the program computes it", () => {
  it("runs the window from the last signed action", () => {
    const s = armed();
    expect(successionActivity(s)).toBe(T0);
    expect(successionDeadline(s)).toBe(T0 + 365n * DAY);
    expect(successionReleaseAt(s)).toBeUndefined();
    expect(checkinCountsUntil(s)).toBe(T0 + 730n * DAY);
  });

  it("counts a check-in, but only up to two years past the last signed action", () => {
    expect(successionActivity(armed({ lastCheckinTs: T0 + 100n * DAY }))).toBe(T0 + 100n * DAY);
    expect(successionActivity(armed({ lastCheckinTs: T0 + 730n * DAY }))).toBe(T0 + 730n * DAY);
    expect(successionActivity(armed({ lastCheckinTs: T0 + 731n * DAY }))).toBe(T0 + 730n * DAY);
    expect(successionActivity(armed({ lastCheckinTs: T0 - DAY }))).toBe(T0);
  });

  it("takes the contact's extension when it is the later deadline", () => {
    const s = armed({ windowSecs: 90n * DAY, extendedUntilTs: T0 + 400n * DAY });
    expect(successionDeadline(s)).toBe(T0 + 400n * DAY);
    expect(successionDeadline({ ...s, extendedUntilTs: T0 + 50n * DAY })).toBe(T0 + 90n * DAY);
  });

  it("names the phase a vault is in", () => {
    const s = armed({ windowSecs: 90n * DAY, waitSecs: 30n * DAY });
    const deadline = T0 + 90n * DAY;
    expect(successionStatus(emptySuccession(), T0)).toEqual({ phase: "unarmed" });
    expect(successionStatus(s, deadline).phase).toBe("quiet");
    expect(successionStatus(s, deadline + 1n).phase).toBe("overdue");
    const waiting = { ...s, waitOpen: true, waitStartedTs: deadline + 5n };
    expect(successionStatus(waiting, deadline + 5n + 30n * DAY - 1n).phase).toBe("waiting");
    expect(successionStatus(waiting, deadline + 5n + 30n * DAY).phase).toBe("releasable");
    expect(successionReleaseAt(waiting)).toBe(deadline + 5n + 30n * DAY);
  });

  it("never promises a release sooner than window + wait after the last signed action", () => {
    let seed = 0x9e3779b97f4a7c15n;
    const next = (n: bigint) => {
      seed = BigInt.asUintN(64, seed * 6364136223846793005n + 1442695040888963407n);
      return (seed >> 33n) % n;
    };
    for (let i = 0; i < 2000; i++) {
      const s = armed({
        windowSecs: (90n + next(1000n)) * DAY,
        waitSecs: (30n + next(400n)) * DAY,
        lastCheckinTs: T0 + next(900n) * DAY - 50n * DAY,
        extendedUntilTs: next(3n) === 0n ? T0 + next(2000n) * DAY : 0n,
      });
      const now = T0 + next(3000n) * DAY;
      const status = successionStatus(s, now);
      expect(status.earliestRelease!).toBeGreaterThan(s.lastSignedTs + s.windowSecs + s.waitSecs);
      expect(status.earliestRelease!).toBeGreaterThanOrEqual(now + s.waitSecs);
      expect(status.deadline!).toBeGreaterThanOrEqual(s.lastSignedTs + s.windowSecs);
      // check-ins alone never hold the deadline past cap + window, unless the contact extended
      if (s.extendedUntilTs === 0n) expect(status.deadline!).toBeLessThanOrEqual(s.lastSignedTs + 730n * DAY + s.windowSecs);
    }
  });

  it("has the program's durations, and a test clock where a day is a second", () => {
    expect(successionLimits()).toEqual({ minWindowSecs: 7_776_000n, minWaitSecs: 2_592_000n, maxDurationSecs: 3_153_600_000n, checkinCapSecs: 63_072_000n, contactExtensionSecs: 7_776_000n });
    expect(successionLimits(SHORT_SUCCESSION_CLOCK)).toEqual({ minWindowSecs: 90n, minWaitSecs: 30n, maxDurationSecs: 36_500n, checkinCapSecs: 730n, contactExtensionSecs: 90n });
    expect(successionClockFor(LAMPORT_VAULT_HEIR_PROGRAM_ID)).toBe(SUCCESSION_CLOCK);
    expect(successionClockFor(LAMPORT_VAULT_PROGRAM_ID)).toBe(SUCCESSION_CLOCK);
    expect(successionClockFor(LAMPORT_VAULT_HEIR_SHORT_CLOCKS_PROGRAM_ID)).toBe(SHORT_SUCCESSION_CLOCK);
  });
});

describe("a plan, checked before it is signed", () => {
  const vault = Keypair.generate().publicKey;

  it("accepts what the program accepts", () => {
    expect(() => checkSuccessionPlan(plan(), vault)).not.toThrow();
    expect(() => checkSuccessionPlan(plan({ windowSecs: 90n * DAY, waitSecs: 30n * DAY }), vault)).not.toThrow();
    expect(() => checkSuccessionPlan(plan({ windowSecs: 36_500n * DAY, waitSecs: 36_500n * DAY }), vault)).not.toThrow();
    expect(() => checkSuccessionPlan(plan({ checkinKey: PublicKey.default, contactKey: PublicKey.default }), vault)).not.toThrow();
    expect(() => checkSuccessionPlan(CLEAR_SUCCESSION_PLAN, vault)).not.toThrow();
    expect(() => checkSuccessionPlan(plan({ windowSecs: 90n, waitSecs: 30n }), vault, SHORT_SUCCESSION_CLOCK)).not.toThrow();
  });

  it("refuses what the program refuses, by the program's names", () => {
    expect(() => checkSuccessionPlan(plan({ windowSecs: 90n * DAY - 1n }), vault)).toThrow(/WindowOutOfRange/);
    expect(() => checkSuccessionPlan(plan({ windowSecs: 36_500n * DAY + 1n }), vault)).toThrow(/WindowOutOfRange/);
    expect(() => checkSuccessionPlan(plan({ waitSecs: 30n * DAY - 1n }), vault)).toThrow(/WaitOutOfRange/);
    expect(() => checkSuccessionPlan(plan({ waitSecs: 0n }), vault)).toThrow(/WaitOutOfRange/);
    expect(() => checkSuccessionPlan(plan({ claim: vault }), vault)).toThrow(/ClaimIsTheVault/);
    expect(() => checkSuccessionPlan({ ...CLEAR_SUCCESSION_PLAN, windowSecs: 1n }, vault)).toThrow(/ClearCarriesPlan/);
    expect(() => checkSuccessionPlan({ ...CLEAR_SUCCESSION_PLAN, checkinKey: CHECKIN }, vault)).toThrow(/ClearCarriesPlan/);
    // a plan sized for the test clock is far below the real floors
    expect(() => checkSuccessionPlan(plan({ windowSecs: 90n, waitSecs: 30n }), vault)).toThrow(/WindowOutOfRange/);
  });
});

describe("the four instructions", () => {
  const programId = LAMPORT_VAULT_HEIR_PROGRAM_ID;
  const vault = Keypair.generate().publicKey;
  const flags = (keys: { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }[]) => keys.map((k) => `${k.pubkey.toBase58()}:${k.isSigner ? "s" : "-"}${k.isWritable ? "w" : "-"}`);

  it("are their Anchor discriminator and nothing else", () => {
    expect(toHex(IX.checkin)).toBe(toHex(instructionDiscriminator("checkin")));
    expect(toHex(IX.contactExtend)).toBe(toHex(instructionDiscriminator("contact_extend")));
    expect(toHex(IX.startSuccession)).toBe(toHex(instructionDiscriminator("start_succession")));
    expect(toHex(IX.executeSuccession)).toBe(toHex(instructionDiscriminator("execute_succession")));
    for (const ix of [
      checkinInstruction({ programId, vault, checkinKey: CHECKIN }),
      contactExtendInstruction({ programId, vault, contactKey: CONTACT }),
      startSuccessionInstruction({ programId, vault }),
      executeSuccessionInstruction({ programId, vault, claim: CLAIM }),
    ]) {
      expect(ix.data.length).toBe(8);
      expect(ix.programId.equals(programId)).toBe(true);
    }
  });

  it("ask the check-in and contact keys to sign and nothing more", () => {
    const checkin = checkinInstruction({ programId, vault, checkinKey: CHECKIN });
    expect(flags(checkin.keys)).toEqual([`${vault.toBase58()}:-w`, `${CHECKIN.toBase58()}:s-`]);
    expect(toHex(checkin.data)).toBe(toHex(IX.checkin));
    const extend = contactExtendInstruction({ programId, vault, contactKey: CONTACT });
    expect(flags(extend.keys)).toEqual([`${vault.toBase58()}:-w`, `${CONTACT.toBase58()}:s-`]);
    expect(toHex(extend.data)).toBe(toHex(IX.contactExtend));
  });

  it("need no signer to start or to release", () => {
    const start = startSuccessionInstruction({ programId, vault });
    expect(flags(start.keys)).toEqual([`${vault.toBase58()}:-w`]);
    const t1 = Keypair.generate().publicKey;
    const t2 = Keypair.generate().publicKey;
    const release = executeSuccessionInstruction({ programId, vault, claim: CLAIM, closeTokenAccounts: [{ account: t1 }, { account: t2, tokenProgram: TOKEN_2022_PROGRAM_ID }] });
    expect(flags(release.keys)).toEqual([
      `${vault.toBase58()}:-w`,
      `${CLAIM.toBase58()}:-w`,
      `${t1.toBase58()}:-w`,
      `${TOKEN_PROGRAM_ID.toBase58()}:--`,
      `${t2.toBase58()}:-w`,
      `${TOKEN_2022_PROGRAM_ID.toBase58()}:--`,
    ]);
    expect(toHex(release.data)).toBe(toHex(IX.executeSuccession));
  });
});

/** The mock cluster, with a table of accounts that are not vaults: owner, executable flag, data. */
class Chain extends MockChain {
  others = new Map<string, { owner: PublicKey; executable?: boolean; data?: Uint8Array }>();
  readonly vaultProgram: PublicKey;
  constructor(vaultProgram: PublicKey) {
    super();
    this.vaultProgram = vaultProgram;
  }
  override async getAccountInfo(pk: PublicKey): Promise<AccountInfo<Buffer> | null> {
    const other = this.others.get(pk.toBase58());
    if (other) return { data: Buffer.from(other.data ?? new Uint8Array()), executable: other.executable ?? false, lamports: 1, owner: other.owner };
    const info = await super.getAccountInfo(pk);
    // the mock labels every vault with the vault program's id; this cluster runs the program under test
    return info && info.owner.equals(LAMPORT_VAULT_PROGRAM_ID) ? { ...info, owner: this.vaultProgram } : info;
  }
}

describe("VaultSigner and SetSuccession", () => {
  const key = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H5, lmotsType: 3, seed: fromHex("784bd340367baa20a90c48bf5623171cba34eb7b4022f11ecca2cc1a893cb506"), I: fromHex("00112233445566778899aabbccddeeff") });
  const payer = Keypair.generate();

  function world(programId: PublicKey, version: 2 | 3) {
    const rpc = new Chain(programId);
    const vault = findVaultPdaForKey(programId, key.publicKey).address;
    const account: VaultAccount = { version, bump: 0, vaultId: vaultId(key.publicKey), lmsPubkey: key.publicKey, spent: 0, generation: 0, createdSlot: 1n, used: new Uint8Array(4), usedKeys: [], ...(version === 3 ? { succession: emptySuccession() } : {}) };
    rpc.accounts.set(vault.toBase58(), encodeVault(account));
    const journal = new MemoryLeafJournal(key.publicKey);
    const signer = new VaultSigner({ rpc, programId, key, payer, journal });
    const leavesSigned = async () => (await journal.load())?.reserved ?? [];
    return { rpc, vault, signer, leavesSigned };
  }

  it("signs a plan for a vault of the Heir-enabled program, bound to that program", async () => {
    const { vault, signer, leavesSigned } = world(LAMPORT_VAULT_HEIR_PROGRAM_ID, 3);
    const signed = await signer.sign({ kind: "SetSuccession", ...plan() });
    expect(signed.action.kind).toBe("SetSuccession");
    expect(signed.actionBytes.length).toBe(129);
    expect(decodeHeirAction(signed.actionBytes)).toEqual(signed.action);
    expect(toHex(signed.message)).toBe(toHex(vaultMessage(vault, 0, signed.actionBytes, LAMPORT_VAULT_HEIR_PROGRAM_ID)));
    expect(toHex(signed.message)).not.toBe(toHex(vaultMessage(vault, 0, signed.actionBytes, LAMPORT_VAULT_PROGRAM_ID)));
    expect(await leavesSigned()).toEqual([signed.q]);
    // and a clear
    const cleared = await signer.sign({ kind: "SetSuccession", ...CLEAR_SUCCESSION_PLAN });
    expect(cleared.q).not.toBe(signed.q);
  });

  it("spends no leaf on a plan for the vault program, which has no such action", async () => {
    const { signer, leavesSigned } = world(LAMPORT_VAULT_PROGRAM_ID, 2);
    await expect(signer.sign({ kind: "SetSuccession", ...plan() })).rejects.toThrow(/Heir-enabled program/);
    expect(await leavesSigned()).toEqual([]);
  });

  it("spends no leaf on a plan the chain would refuse", async () => {
    const { rpc, vault, signer, leavesSigned } = world(LAMPORT_VAULT_HEIR_PROGRAM_ID, 3);
    const refuse = async (p: Partial<SuccessionPlan>, why: RegExp) => {
      await expect(signer.sign({ kind: "SetSuccession", ...plan(p) })).rejects.toThrow(why);
    };
    await refuse({ windowSecs: 89n * DAY }, /WindowOutOfRange/);
    await refuse({ waitSecs: 29n * DAY }, /WaitOutOfRange/);
    await refuse({ claim: vault }, /ClaimIsTheVault/);
    await expect(signer.sign({ kind: "SetSuccession", ...CLEAR_SUCCESSION_PLAN, waitSecs: 5n })).rejects.toThrow(/ClearCarriesPlan/);

    // claim accounts that could never receive the release
    const mint = Keypair.generate().publicKey;
    const tokenAccount = Keypair.generate().publicKey;
    rpc.mints.set(mint.toBase58(), TOKEN_PROGRAM_ID);
    rpc.tokenAccounts.set(tokenAccount.toBase58(), { owner: vault, mint, amount: 0n });
    await refuse({ claim: tokenAccount }, /ClaimNotUsable/);
    await refuse({ claim: mint }, /ClaimNotUsable/);
    const program = Keypair.generate().publicKey;
    rpc.others.set(program.toBase58(), { owner: Keypair.generate().publicKey, executable: true });
    await refuse({ claim: program }, /ClaimNotUsable/);
    const sysvar = new PublicKey("SysvarC1ock11111111111111111111111111111111");
    rpc.others.set(sysvar.toBase58(), { owner: new PublicKey("Sysvar1111111111111111111111111111111111111") });
    await refuse({ claim: sysvar }, /ClaimNotUsable/);
    const closedVault = Keypair.generate().publicKey;
    rpc.others.set(closedVault.toBase58(), { owner: LAMPORT_VAULT_HEIR_PROGRAM_ID, data: encodeTombstone({ version: TOMBSTONE_ACCOUNT_VERSION, vaultId: new Uint8Array(32), closedSlot: 1n, heir: CLAIM }) });
    await refuse({ claim: closedVault }, /not an open vault/);
    expect(await leavesSigned()).toEqual([]);

    // what the program allows: an address with nothing at it, a wallet, another program's account, another open vault
    const wallet = Keypair.generate().publicKey;
    rpc.others.set(wallet.toBase58(), { owner: PublicKey.default });
    const foreign = Keypair.generate().publicKey;
    rpc.others.set(foreign.toBase58(), { owner: Keypair.generate().publicKey, data: Uint8Array.of(1, 2, 3) });
    const backup = Keypair.generate().publicKey;
    rpc.others.set(backup.toBase58(), { owner: LAMPORT_VAULT_HEIR_PROGRAM_ID, data: encodeVault({ version: 3, bump: 0, vaultId: new Uint8Array(32), lmsPubkey: key.publicKey, spent: 0, generation: 0, createdSlot: 1n, succession: emptySuccession(), used: new Uint8Array(4), usedKeys: [] }) });
    for (const claim of [Keypair.generate().publicKey, wallet, foreign, backup]) {
      const signed = await signer.sign({ kind: "SetSuccession", ...plan({ claim }) });
      expect(signed.action.kind === "SetSuccession" && signed.action.claim.equals(claim)).toBe(true);
    }
    expect((await leavesSigned()).length).toBe(4);
  });

  it("refuses a claim address that has no account and no key, unless told to sign anyway", async () => {
    const { rpc, vault, signer, leavesSigned } = world(LAMPORT_VAULT_HEIR_PROGRAM_ID, 3);
    // A program-derived address: off the curve, so no key exists for it. Until a program creates an
    // account there (a plan that was never set up, say), a release sent to it could not be claimed.
    const [unkeyed] = PublicKey.findProgramAddressSync([new TextEncoder().encode("plan"), vault.toBytes()], Keypair.generate().publicKey);
    expect(PublicKey.isOnCurve(unkeyed.toBytes())).toBe(false);
    await expect(signer.sign({ kind: "SetSuccession", ...plan({ claim: unkeyed }) })).rejects.toThrow(/no account on chain and is not a key's address/);
    expect(await leavesSigned()).toEqual([]);

    // once an account exists there (whoever owns it), the program's own rules decide, as before
    rpc.others.set(unkeyed.toBase58(), { owner: Keypair.generate().publicKey, data: Uint8Array.of(1) });
    await signer.sign({ kind: "SetSuccession", ...plan({ claim: unkeyed }) });
    rpc.others.delete(unkeyed.toBase58());

    // and the caller who knows better can say so
    await signer.sign({ kind: "SetSuccession", ...plan({ claim: unkeyed }) }, { allowUnkeyedClaim: true });
    // an ordinary unused wallet address is on the curve: never refused for having no account
    const fresh = Keypair.generate().publicKey;
    expect(PublicKey.isOnCurve(fresh.toBytes())).toBe(true);
    await signer.sign({ kind: "SetSuccession", ...plan({ claim: fresh }) });
    expect((await leavesSigned()).length).toBe(3);
  });

  it("holds a plan on the test clock to the test clock's floors", async () => {
    const { signer } = world(LAMPORT_VAULT_HEIR_SHORT_CLOCKS_PROGRAM_ID, 3);
    await expect(signer.sign({ kind: "SetSuccession", ...plan({ windowSecs: 89n, waitSecs: 30n }) })).rejects.toThrow(/WindowOutOfRange/);
    const signed = await signer.sign({ kind: "SetSuccession", ...plan({ windowSecs: 90n, waitSecs: 30n }) });
    expect(signed.actionBytes.length).toBe(129);
  });
});
