import { sha256 } from "@noble/hashes/sha2.js";
import { PublicKey } from "@solana/web3.js";
import { toHex } from "@lamport-robotics/lms";
import { describe, expect, it } from "vitest";
import { encodeAction } from "../src/action.ts";
import { registryMessage, REGISTRY_MESSAGE_PREFIX, vaultMessage, VAULT_MESSAGE_PREFIX } from "../src/message.ts";
import {
  associatedTokenAddress,
  findCommitmentPda,
  findPqSigBufferPda,
  findSigBufferPda,
  findVaultPda,
  findVaultPdaForKey,
  TOKEN_PROGRAM_ID,
  vaultId,
} from "../src/pda.ts";
import { KAT_H10_PUBKEY, KAT_H5_PUBKEY, NONCE, PK_11, PK_22, REGISTRY_PROGRAM_ID, VAULT_PROGRAM_ID } from "./fixtures.ts";

describe("PDAs", () => {
  it("vault_id = sha256(lms_pubkey)", () => {
    expect(toHex(vaultId(KAT_H5_PUBKEY))).toBe(toHex(sha256(KAT_H5_PUBKEY)));
    expect(() => vaultId(KAT_H5_PUBKEY.subarray(1))).toThrow();
  });

  it('vault = ["vault", vault_id]', () => {
    const id = vaultId(KAT_H5_PUBKEY);
    const [want, bump] = PublicKey.findProgramAddressSync([Buffer.from("vault"), id], VAULT_PROGRAM_ID);
    const got = findVaultPda(VAULT_PROGRAM_ID, id);
    expect(got.address.equals(want)).toBe(true);
    expect(got.bump).toBe(bump);
    expect(findVaultPdaForKey(VAULT_PROGRAM_ID, KAT_H5_PUBKEY).address.equals(want)).toBe(true);
    expect(findVaultPdaForKey(VAULT_PROGRAM_ID, KAT_H10_PUBKEY).address.equals(want)).toBe(false);
  });

  it('sig buffer = ["sig", vault, payer, nonce_le_u64]', () => {
    const vault = findVaultPdaForKey(VAULT_PROGRAM_ID, KAT_H5_PUBKEY).address;
    const nonceLe = Buffer.alloc(8);
    nonceLe.writeBigUInt64LE(NONCE);
    expect(toHex(nonceLe)).toBe("0807060504030201");
    const [want] = PublicKey.findProgramAddressSync([Buffer.from("sig"), vault.toBuffer(), PK_11.toBuffer(), nonceLe], VAULT_PROGRAM_ID);
    expect(findSigBufferPda(VAULT_PROGRAM_ID, vault, PK_11, NONCE).address.equals(want)).toBe(true);
    expect(findSigBufferPda(VAULT_PROGRAM_ID, vault, PK_11, NONCE + 1n).address.equals(want)).toBe(false);
    expect(findSigBufferPda(VAULT_PROGRAM_ID, vault, PK_22, NONCE).address.equals(want)).toBe(false);
  });

  it('commitment = ["pq", owner] and pq sig buffer = ["pqsig", owner, payer, nonce_le_u64]', () => {
    const [want] = PublicKey.findProgramAddressSync([Buffer.from("pq"), PK_11.toBuffer()], REGISTRY_PROGRAM_ID);
    expect(findCommitmentPda(REGISTRY_PROGRAM_ID, PK_11).address.equals(want)).toBe(true);
    const nonceLe = Buffer.alloc(8);
    nonceLe.writeBigUInt64LE(NONCE);
    const [wantBuf] = PublicKey.findProgramAddressSync([Buffer.from("pqsig"), PK_11.toBuffer(), PK_22.toBuffer(), nonceLe], REGISTRY_PROGRAM_ID);
    expect(findPqSigBufferPda(REGISTRY_PROGRAM_ID, PK_11, PK_22, NONCE).address.equals(wantBuf)).toBe(true);
  });

  it("associated token address matches the SPL derivation", () => {
    const owner = findVaultPdaForKey(VAULT_PROGRAM_ID, KAT_H5_PUBKEY).address;
    const [want] = PublicKey.findProgramAddressSync(
      [owner.toBuffer(), TOKEN_PROGRAM_ID.toBuffer(), PK_22.toBuffer()],
      new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
    );
    expect(associatedTokenAddress(owner, PK_22).equals(want)).toBe(true);
  });

  it("pins the PDA vectors for the fixed program ids", () => {
    const vault = findVaultPdaForKey(VAULT_PROGRAM_ID, KAT_H5_PUBKEY);
    expect({
      vault: vault.address.toBase58(),
      vaultBump: vault.bump,
      sigBuffer: findSigBufferPda(VAULT_PROGRAM_ID, vault.address, PK_11, NONCE).address.toBase58(),
      commitment: findCommitmentPda(REGISTRY_PROGRAM_ID, PK_11).address.toBase58(),
    }).toMatchSnapshot();
  });
});

describe("signed messages", () => {
  it('vault message = sha256("lamport-vault/v1" || vault || action_bytes)', () => {
    const vault = findVaultPdaForKey(VAULT_PROGRAM_ID, KAT_H5_PUBKEY).address;
    const action = encodeAction({ kind: "TransferSol", to: PK_11, lamports: 1n, expirySlot: 2n });
    const want = sha256(Buffer.concat([Buffer.from("lamport-vault/v1"), vault.toBuffer(), action]));
    expect(toHex(VAULT_MESSAGE_PREFIX)).toBe(toHex(Buffer.from("lamport-vault/v1")));
    expect(toHex(vaultMessage(vault, action))).toBe(toHex(want));
    expect(vaultMessage(vault, action).length).toBe(32);
    // a different vault or action changes the digest
    expect(toHex(vaultMessage(PK_22, action))).not.toBe(toHex(want));
    const other = encodeAction({ kind: "TransferSol", to: PK_11, lamports: 2n, expirySlot: 2n });
    expect(toHex(vaultMessage(vault, other))).not.toBe(toHex(want));
  });

  it('registry message = sha256("pq-registry/v1" || owner || new_pq_pubkey)', () => {
    const want = sha256(Buffer.concat([Buffer.from("pq-registry/v1"), PK_11.toBuffer(), KAT_H10_PUBKEY]));
    expect(toHex(REGISTRY_MESSAGE_PREFIX)).toBe(toHex(Buffer.from("pq-registry/v1")));
    expect(toHex(registryMessage(PK_11, KAT_H10_PUBKEY))).toBe(toHex(want));
    expect(() => registryMessage(PK_11, KAT_H10_PUBKEY.subarray(0, 55))).toThrow();
  });
});
