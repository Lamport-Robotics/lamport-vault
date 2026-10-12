import { fromHex, LMS_SHA256_M32_H10, LMS_SHA256_M32_H15, LMS_SHA256_M32_H5, toHex } from "@lamport-robotics/lms";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import {
  COMMITMENT_ACCOUNT_SIZE,
  type CommitmentAccount,
  commitmentAccountSize,
  decodeCommitment,
  decodePqSigBuffer,
  decodeSigBuffer,
  decodeTombstone,
  decodeVault,
  decodeVaultOrTombstone,
  encodeCommitment,
  encodePqSigBuffer,
  encodeSigBuffer,
  encodeTombstone,
  encodeVault,
  firstFreeLeaf,
  freeLeaves,
  hasUsedKey,
  isLeafUsed,
  isTombstone,
  KEY_HASH_LEN,
  leafCount,
  pqSigBufferSize,
  SCHEME_LMS_SHA256,
  type SigBufferAccount,
  sigBufferSize,
  TOMBSTONE_ACCOUNT_SIZE,
  TOMBSTONE_ACCOUNT_VERSION,
  type TombstoneAccount,
  usedKeyHash,
  vaultAccountSize,
  type VaultAccount,
  VaultClosedError,
} from "../src/accounts.ts";
import { encodeAction } from "../src/action.ts";
import { ACCOUNT } from "../src/discriminator.ts";
import { vaultId } from "../src/pda.ts";
import { KAT_H10_PUBKEY, KAT_H5_PUBKEY, NONCE, PK_11, PK_22, PK_33 } from "./fixtures.ts";

/** A past key that only appears hashed (same inputs as scripts/write-kat.ts). */
const PAST_PUBKEY = fromHex("0000000500000003" + "aa".repeat(16) + "bb".repeat(32));

describe("Vault account", () => {
  const v: VaultAccount = {
    version: 2,
    bump: 254,
    vaultId: vaultId(KAT_H5_PUBKEY),
    lmsPubkey: KAT_H5_PUBKEY,
    spent: 6,
    generation: 2,
    createdSlot: 0x1122334455n,
    used: new Uint8Array([0x07, 0x00, 0x40, 0x81]),
    usedKeys: [usedKeyHash(KAT_H10_PUBKEY), usedKeyHash(PAST_PUBKEY)],
  };

  it("is disc || version || bump || vault_id || lms_pubkey || spent || generation || created_slot || vec used || vec used_keys", () => {
    const bytes = encodeVault(v);
    expect(bytes.length).toBe(vaultAccountSize(LMS_SHA256_M32_H5, 2));
    expect(vaultAccountSize(LMS_SHA256_M32_H5)).toBe(126);
    expect(vaultAccountSize(LMS_SHA256_M32_H10)).toBe(250);
    expect(vaultAccountSize(LMS_SHA256_M32_H15)).toBe(4218);
    expect(() => vaultAccountSize(8)).toThrow(/not accepted/);
    expect(toHex(bytes)).toBe(
      toHex(ACCOUNT.vault) +
        "02" +
        "fe" +
        toHex(v.vaultId) +
        toHex(KAT_H5_PUBKEY) +
        "06000000" +
        "02000000" +
        "5544332211000000" +
        "04000000" +
        "07004081" +
        "02000000" +
        toHex(usedKeyHash(KAT_H10_PUBKEY)) +
        toHex(usedKeyHash(PAST_PUBKEY)),
    );
    const back = decodeVault(bytes);
    expect(back.spent).toBe(6);
    expect(back.generation).toBe(2);
    expect(back.createdSlot).toBe(0x1122334455n);
    expect(toHex(back.lmsPubkey)).toBe(toHex(KAT_H5_PUBKEY));
    expect(toHex(back.used)).toBe("07004081");
    expect(back.usedKeys.map(toHex)).toEqual(v.usedKeys.map(toHex));
  });

  it("used_keys entries are sha256(pubkey)[0..16]", () => {
    expect(usedKeyHash(KAT_H5_PUBKEY).length).toBe(KEY_HASH_LEN);
    expect(toHex(usedKeyHash(KAT_H5_PUBKEY))).toBe(toHex(sha256(KAT_H5_PUBKEY).subarray(0, 16)));
    expect(toHex(usedKeyHash(KAT_H5_PUBKEY))).toBe(toHex(vaultId(KAT_H5_PUBKEY).subarray(0, 16)));
    expect(() => usedKeyHash(KAT_H5_PUBKEY.subarray(1))).toThrow();
  });

  it("hasUsedKey covers the current key and every past one", () => {
    expect(hasUsedKey(v, KAT_H5_PUBKEY)).toBe(true);
    expect(hasUsedKey(v, KAT_H10_PUBKEY)).toBe(true);
    expect(hasUsedKey(v, PAST_PUBKEY)).toBe(true);
    const fresh = new Uint8Array(KAT_H5_PUBKEY);
    fresh[55]! ^= 1;
    expect(hasUsedKey(v, fresh)).toBe(false);
  });

  it("reads the bitmap: isLeafUsed, freeLeaves, firstFreeLeaf with lanes", () => {
    expect(leafCount(v)).toBe(32);
    expect(freeLeaves(v)).toBe(26);
    expect([0, 1, 2, 22, 24, 31].every((q) => isLeafUsed(v, q))).toBe(true);
    expect([3, 4, 7, 8, 23, 30].some((q) => isLeafUsed(v, q))).toBe(false);
    expect(isLeafUsed(v, 32)).toBe(true); // outside the tree counts as spent
    expect(() => isLeafUsed(v, -1)).toThrow(RangeError);
    expect(firstFreeLeaf(v)).toBe(3);
    expect(firstFreeLeaf(v, 0, 2)).toBe(4);
    expect(firstFreeLeaf(v, 1, 2)).toBe(3);
    expect(firstFreeLeaf(v, 0, 2, (q) => q < 10)).toBe(10);
    expect(firstFreeLeaf(v, 2, 3)).toBe(5);
    const full = { used: new Uint8Array([0xff, 0xff, 0xff, 0xff]) };
    expect(firstFreeLeaf(full)).toBeUndefined();
    expect(() => firstFreeLeaf(v, 2, 2)).toThrow(RangeError);
    expect(() => firstFreeLeaf(v, 0, 0)).toThrow(RangeError);
  });

  it("rejects a wrong discriminator, another layout version, a wrong bitmap size, trailing bytes and short data", () => {
    const bytes = encodeVault(v);
    bytes[0]! ^= 1;
    expect(() => decodeVault(bytes)).toThrow(/discriminator/);
    const v1 = encodeVault(v);
    v1[8] = 1;
    expect(() => decodeVault(v1)).toThrow(/version 1/);
    expect(() => decodeVault(encodeVault(v).subarray(0, 100))).toThrow();
    expect(() => decodeVault(new Uint8Array([...encodeVault(v), 0]))).toThrow(/trailing/);
    expect(() => encodeVault({ ...v, used: new Uint8Array(128) })).toThrow(/bitmap/);
    const h10 = encodeVault({ ...v, lmsPubkey: KAT_H10_PUBKEY, used: new Uint8Array(128) });
    h10.set(KAT_H5_PUBKEY, 10 + 32); // now claims H5 with a 128-byte bitmap
    expect(() => decodeVault(h10)).toThrow(/bitmap/);
    expect(() => encodeVault({ ...v, usedKeys: new Array(129).fill(usedKeyHash(KAT_H10_PUBKEY)) })).toThrow(/at most 128/);
  });
});

describe("Tombstone account", () => {
  const t: TombstoneAccount = { version: TOMBSTONE_ACCOUNT_VERSION, vaultId: vaultId(KAT_H5_PUBKEY), closedSlot: 0x1122334455n, heir: PK_33 };

  it("is disc || version 0xfe || vault_id || closed_slot || heir, 81 bytes, with its own discriminator", () => {
    const bytes = encodeTombstone(t);
    expect(bytes.length).toBe(TOMBSTONE_ACCOUNT_SIZE);
    expect(TOMBSTONE_ACCOUNT_SIZE).toBe(81);
    expect(toHex(ACCOUNT.tombstone)).toBe(toHex(sha256(new TextEncoder().encode("account:Tombstone")).subarray(0, 8)));
    expect(toHex(bytes)).toBe(toHex(ACCOUNT.tombstone) + "fe" + toHex(t.vaultId) + "5544332211000000" + "33".repeat(32));
    expect(decodeTombstone(bytes).heir.equals(PK_33)).toBe(true);
    expect(decodeTombstone(bytes)).toEqual(t);
    expect(isTombstone(bytes)).toBe(true);
    expect(isTombstone(bytes.subarray(0, 7))).toBe(false);
  });

  it("decodeVaultOrTombstone tells the two apart; decodeVault names a closed vault", () => {
    const vault = encodeVault({ version: 2, bump: 0, vaultId: vaultId(KAT_H5_PUBKEY), lmsPubkey: KAT_H5_PUBKEY, spent: 0, generation: 0, createdSlot: 1n, used: new Uint8Array(4), usedKeys: [] });
    expect(isTombstone(vault)).toBe(false);
    expect(decodeVaultOrTombstone(vault)).toEqual({ kind: "vault", vault: decodeVault(vault) });
    const tomb = encodeTombstone(t);
    expect(decodeVaultOrTombstone(tomb)).toEqual({ kind: "tombstone", tombstone: t });
    let err: unknown;
    try {
      decodeVault(tomb);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(VaultClosedError);
    expect((err as VaultClosedError).tombstone).toEqual(t);
    expect(String(err)).toMatch(/closed at slot 73588229205/);
    // the wrong version, trailing bytes, short data and another account are refused
    const v1 = encodeTombstone(t);
    v1[8] = 2;
    expect(() => decodeTombstone(v1)).toThrow(/version 2/);
    expect(() => decodeTombstone(new Uint8Array([...tomb, 0]))).toThrow(/trailing/);
    expect(() => decodeTombstone(tomb.subarray(0, 40))).toThrow();
    expect(() => decodeTombstone(tomb.subarray(0, 49))).toThrow(); // the pre-heir layout is not accepted
    expect(() => decodeTombstone(vault)).toThrow(/discriminator/);
    expect(() => decodeVaultOrTombstone(new Uint8Array(81))).toThrow(/discriminator/);
  });
});

describe("SigBuffer account", () => {
  const action = encodeAction({ kind: "TransferSol", to: PK_22, lamports: 10n, issuedSlot: 0n, expirySlot: 20n });
  const sig = new Uint8Array(2348).map((_, i) => (i * 7) & 0xff);
  const b: SigBufferAccount = { version: 1, bump: 250, vault: PK_11, payer: PK_22, nonce: NONCE, action, sigLen: 2348, filled: 900, sig };

  it("lays out vec<u8> action, sig_len/filled u16, then vec<u8> sig (SigBuffer::space)", () => {
    const bytes = encodeSigBuffer(b);
    expect(bytes.length).toBe(sigBufferSize(action.length, 2348));
    expect(sigBufferSize(57, 2348)).toBe(8 + 1 + 1 + 32 + 32 + 8 + (4 + 57) + 2 + 2 + (4 + 2348));
    const head = toHex(ACCOUNT.sigBuffer) + "01" + "fa" + "11".repeat(32) + "22".repeat(32) + "0807060504030201" + "39000000" + toHex(action) + "2c09" + "8403" + "2c090000";
    expect(toHex(bytes.subarray(0, head.length / 2))).toBe(head);
    expect(toHex(bytes.subarray(head.length / 2))).toBe(toHex(sig));
    const back = decodeSigBuffer(bytes);
    expect(back.filled).toBe(900);
    expect(back.sigLen).toBe(2348);
    expect(back.nonce).toBe(NONCE);
    expect(toHex(back.action)).toBe(toHex(action));
    expect(toHex(back.sig)).toBe(toHex(sig));
  });

  it("rejects sig/sig_len mismatch", () => {
    expect(() => encodeSigBuffer({ ...b, sigLen: 100 })).toThrow();
    const bytes = encodeSigBuffer(b);
    bytes[8 + 1 + 1 + 32 + 32 + 8 + 4 + action.length]! ^= 1; // sig_len low byte
    expect(() => decodeSigBuffer(bytes)).toThrow(/sig_len/);
  });
});

describe("Commitment account", () => {
  const c: CommitmentAccount = {
    version: 2,
    bump: 255,
    owner: PK_11,
    scheme: SCHEME_LMS_SHA256,
    pqPubkey: KAT_H10_PUBKEY,
    nextQ: 3,
    generation: 1,
    createdSlot: 100n,
    updatedSlot: 200n,
    usedKeys: [usedKeyHash(KAT_H5_PUBKEY)],
  };

  it("round-trips and has the documented size", () => {
    const bytes = encodeCommitment(c);
    expect(bytes.length).toBe(commitmentAccountSize(1));
    expect(COMMITMENT_ACCOUNT_SIZE).toBe(127);
    expect(toHex(bytes)).toBe(
      toHex(ACCOUNT.commitment) +
        "02ff" +
        "11".repeat(32) +
        "01" +
        toHex(KAT_H10_PUBKEY) +
        "03000000" +
        "01000000" +
        "6400000000000000" +
        "c800000000000000" +
        "01000000" +
        toHex(usedKeyHash(KAT_H5_PUBKEY)),
    );
    const back = decodeCommitment(bytes);
    expect(back.owner.equals(PK_11)).toBe(true);
    expect(back.generation).toBe(1);
    expect(back.updatedSlot).toBe(200n);
    expect(hasUsedKey(back, KAT_H5_PUBKEY)).toBe(true);
    expect(hasUsedKey(back, KAT_H10_PUBKEY)).toBe(true);
    expect(hasUsedKey(back, PAST_PUBKEY)).toBe(false);
    const v1 = encodeCommitment(c);
    v1[8] = 1;
    expect(() => decodeCommitment(v1)).toThrow(/version 1/);
    expect(() => decodeCommitment(new Uint8Array([...bytes, 0]))).toThrow(/trailing/);
    expect(() => encodeCommitment({ ...c, usedKeys: new Array(33).fill(usedKeyHash(KAT_H5_PUBKEY)) })).toThrow(/at most 32/);
  });
});

describe("PqSigBuffer account", () => {
  it("round-trips with PqSigBuffer::space", () => {
    const sig = new Uint8Array(2508).fill(3);
    const bytes = encodePqSigBuffer({ version: 1, bump: 1, owner: PK_11, payer: PK_22, nonce: 9n, newPqPubkey: KAT_H5_PUBKEY, issuedSlot: 0x1234n, expirySlot: 0x5678n, sigLen: 2508, filled: 2508, sig });
    expect(bytes.length).toBe(pqSigBufferSize(2508));
    expect(pqSigBufferSize(2508)).toBe(8 + 1 + 1 + 32 + 32 + 8 + 56 + 8 + 8 + 2 + 2 + 4 + 2508);
    // the window sits between the key and sig_len: u64le issued, u64le expiry
    const w = 8 + 1 + 1 + 32 + 32 + 8 + 56;
    expect(toHex(bytes.subarray(w, w + 16))).toBe("3412000000000000" + "7856000000000000");
    expect(toHex(bytes.subarray(w + 16, w + 18))).toBe("cc09");
    const back = decodePqSigBuffer(bytes);
    expect(back.nonce).toBe(9n);
    expect(back.issuedSlot).toBe(0x1234n);
    expect(back.expirySlot).toBe(0x5678n);
    expect(toHex(back.newPqPubkey)).toBe(toHex(KAT_H5_PUBKEY));
    expect(toHex(back.sig)).toBe(toHex(sig));
  });
});
