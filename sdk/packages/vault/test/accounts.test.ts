import { toHex } from "@lamport-robotics/lms";
import { describe, expect, it } from "vitest";
import {
  COMMITMENT_ACCOUNT_SIZE,
  type CommitmentAccount,
  decodeCommitment,
  decodePqSigBuffer,
  decodeSigBuffer,
  decodeVault,
  encodeCommitment,
  encodePqSigBuffer,
  encodeSigBuffer,
  encodeVault,
  pqSigBufferSize,
  SCHEME_LMS_SHA256,
  type SigBufferAccount,
  sigBufferSize,
  VAULT_ACCOUNT_SIZE,
  type VaultAccount,
} from "../src/accounts.ts";
import { encodeAction } from "../src/action.ts";
import { ACCOUNT } from "../src/discriminator.ts";
import { vaultId } from "../src/pda.ts";
import { KAT_H10_PUBKEY, KAT_H5_PUBKEY, NONCE, PK_11, PK_22 } from "./fixtures.ts";

describe("Vault account", () => {
  const v: VaultAccount = {
    version: 1,
    bump: 254,
    vaultId: vaultId(KAT_H5_PUBKEY),
    lmsPubkey: KAT_H5_PUBKEY,
    nextQ: 7,
    rotations: 2,
    createdSlot: 0x1122334455n,
  };

  it("is disc || version || bump || vault_id || lms_pubkey || next_q_le || rotations_le || created_slot_le", () => {
    const bytes = encodeVault(v);
    expect(bytes.length).toBe(VAULT_ACCOUNT_SIZE);
    expect(VAULT_ACCOUNT_SIZE).toBe(114);
    expect(toHex(bytes)).toBe(toHex(ACCOUNT.vault) + "01" + "fe" + toHex(v.vaultId) + toHex(KAT_H5_PUBKEY) + "07000000" + "02000000" + "5544332211000000");
    const back = decodeVault(bytes);
    expect(back.nextQ).toBe(7);
    expect(back.rotations).toBe(2);
    expect(back.createdSlot).toBe(0x1122334455n);
    expect(toHex(back.lmsPubkey)).toBe(toHex(KAT_H5_PUBKEY));
  });

  it("rejects a wrong discriminator and short data", () => {
    const bytes = encodeVault(v);
    bytes[0]! ^= 1;
    expect(() => decodeVault(bytes)).toThrow(/discriminator/);
    expect(() => decodeVault(encodeVault(v).subarray(0, 100))).toThrow();
  });
});

describe("SigBuffer account", () => {
  const action = encodeAction({ kind: "TransferSol", to: PK_22, lamports: 10n, expirySlot: 20n });
  const sig = new Uint8Array(2348).map((_, i) => (i * 7) & 0xff);
  const b: SigBufferAccount = { version: 1, bump: 250, vault: PK_11, payer: PK_22, nonce: NONCE, action, sigLen: 2348, filled: 900, sig };

  it("lays out vec<u8> action, sig_len/filled u16, then vec<u8> sig (SigBuffer::space)", () => {
    const bytes = encodeSigBuffer(b);
    expect(bytes.length).toBe(sigBufferSize(action.length, 2348));
    expect(sigBufferSize(49, 2348)).toBe(8 + 1 + 1 + 32 + 32 + 8 + (4 + 49) + 2 + 2 + (4 + 2348));
    const head = toHex(ACCOUNT.sigBuffer) + "01" + "fa" + "11".repeat(32) + "22".repeat(32) + "0807060504030201" + "31000000" + toHex(action) + "2c09" + "8403" + "2c090000";
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
    version: 1,
    bump: 255,
    owner: PK_11,
    scheme: SCHEME_LMS_SHA256,
    pqPubkey: KAT_H10_PUBKEY,
    nextQ: 3,
    createdSlot: 100n,
    updatedSlot: 200n,
  };

  it("round-trips and has the documented size", () => {
    const bytes = encodeCommitment(c);
    expect(bytes.length).toBe(COMMITMENT_ACCOUNT_SIZE);
    expect(COMMITMENT_ACCOUNT_SIZE).toBe(119);
    expect(toHex(bytes)).toBe(toHex(ACCOUNT.commitment) + "01ff" + "11".repeat(32) + "01" + toHex(KAT_H10_PUBKEY) + "03000000" + "6400000000000000" + "c800000000000000");
    const back = decodeCommitment(bytes);
    expect(back.owner.equals(PK_11)).toBe(true);
    expect(back.updatedSlot).toBe(200n);
  });
});

describe("PqSigBuffer account", () => {
  it("round-trips with PqSigBuffer::space", () => {
    const sig = new Uint8Array(2508).fill(3);
    const bytes = encodePqSigBuffer({ version: 1, bump: 1, owner: PK_11, payer: PK_22, nonce: 9n, newPqPubkey: KAT_H5_PUBKEY, sigLen: 2508, filled: 2508, sig });
    expect(bytes.length).toBe(pqSigBufferSize(2508));
    expect(pqSigBufferSize(2508)).toBe(8 + 1 + 1 + 32 + 32 + 8 + 56 + 2 + 2 + 4 + 2508);
    const back = decodePqSigBuffer(bytes);
    expect(back.nonce).toBe(9n);
    expect(toHex(back.newPqPubkey)).toBe(toHex(KAT_H5_PUBKEY));
    expect(toHex(back.sig)).toBe(toHex(sig));
  });
});
