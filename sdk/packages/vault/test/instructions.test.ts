import { sha256 } from "@noble/hashes/sha2.js";
import { ComputeBudgetProgram, Keypair, PACKET_DATA_SIZE, SystemProgram, Transaction } from "@solana/web3.js";
import { LMOTS_SHA256_N32_W4, LMS_SHA256_M32_H10, LMS_SHA256_M32_H5, lmsSignatureLength, toHex } from "@lamport-robotics/lms";
import { describe, expect, it } from "vitest";
import { type Action, encodeAction } from "../src/action.ts";
import { chunkSignature, MAX_CHUNK_BYTES } from "../src/chunk.ts";
import { ACCOUNT, accountDiscriminator, instructionDiscriminator, IX } from "../src/discriminator.ts";
import {
  buildStagedExecution,
  closeSigBufferInstruction,
  createVaultInstruction,
  EXECUTE_COMPUTE_UNITS,
  executeInstruction,
  executeInstructions,
  executeRemainingAccounts,
  openSigBufferFirstChunkCapacity,
  openSigBufferInstruction,
  sweepClosedInstruction,
  writeSigInstruction,
  writeSigInstructions,
} from "../src/instructions.ts";
import { ASSOCIATED_TOKEN_PROGRAM_ID, associatedTokenAddress, findSigBufferPda, findVaultPdaForKey, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, vaultId } from "../src/pda.ts";
import { buildStagedRotatePq, closePqBufferInstruction, commitInstruction, openPqBufferInstruction, writePqSigInstruction } from "../src/registry.ts";
import { KAT_H10_PUBKEY, KAT_H5_PUBKEY, NONCE, PK_11, PK_22, PK_33, PK_44, REGISTRY_PROGRAM_ID, VAULT_PROGRAM_ID } from "./fixtures.ts";

const keysOf = (ix: { keys: { pubkey: { toBase58(): string }; isSigner: boolean; isWritable: boolean }[] }) =>
  ix.keys.map((k) => [k.pubkey.toBase58(), k.isSigner, k.isWritable]);

describe("Anchor discriminators", () => {
  it('are sha256("global:<ix>")[0..8] and sha256("account:<Name>")[0..8]', () => {
    const enc = new TextEncoder();
    expect(toHex(instructionDiscriminator("create_vault"))).toBe(toHex(sha256(enc.encode("global:create_vault")).subarray(0, 8)));
    expect(toHex(accountDiscriminator("Vault"))).toBe(toHex(sha256(enc.encode("account:Vault")).subarray(0, 8)));
    for (const d of [...Object.values(IX), ...Object.values(ACCOUNT)]) expect(d.length).toBe(8);
    expect(new Set([...Object.values(IX), ...Object.values(ACCOUNT)].map(toHex)).size).toBe(Object.keys(IX).length + Object.keys(ACCOUNT).length);
  });
});

describe("chunking", () => {
  it("splits H5/H10/H15/H20 signatures into sequential chunks of at most 900 bytes", () => {
    for (const [lms, want] of [
      [LMS_SHA256_M32_H5, [900, 900, 548]],
      [LMS_SHA256_M32_H10, [900, 900, 708]],
      [7, [900, 900, 868]],
      [8, [900, 900, 900, 128]],
    ] as const) {
      const len = lmsSignatureLength(lms, LMOTS_SHA256_N32_W4);
      const sig = new Uint8Array(len).map((_, i) => i & 0xff);
      const chunks = chunkSignature(sig);
      expect(chunks.map((c) => c.bytes.length)).toEqual(want);
      let offset = 0;
      for (const c of chunks) {
        expect(c.offset).toBe(offset);
        expect(toHex(c.bytes)).toBe(toHex(sig.subarray(offset, offset + c.bytes.length)));
        offset += c.bytes.length;
      }
      expect(offset).toBe(len);
    }
    expect(chunkSignature(new Uint8Array(2348), 800).map((c) => c.bytes.length)).toEqual([800, 800, 748]);
    expect(() => chunkSignature(new Uint8Array(10), 901)).toThrow(RangeError);
  });

  it("writeSigInstructions honours a start offset (bytes already in open_sig_buffer)", () => {
    const sig = new Uint8Array(2508).map((_, i) => i & 0xff);
    const { chunks } = writeSigInstructions({ programId: VAULT_PROGRAM_ID, sigBuffer: PK_33, payer: PK_11, signature: sig, startOffset: 700 });
    expect(chunks.map((c) => [c.offset, c.bytes.length])).toEqual([
      [700, 900],
      [1600, 900],
      [2500, 8],
    ]);
    expect(toHex(chunks[2]!.bytes)).toBe(toHex(sig.subarray(2500)));
  });
});

describe("vault instruction data and accounts", () => {
  const vault = findVaultPdaForKey(VAULT_PROGRAM_ID, KAT_H5_PUBKEY).address;
  const payer = PK_11;

  it("create_vault: payer, vault, system_program", () => {
    const { instruction, vault: v } = createVaultInstruction({ programId: VAULT_PROGRAM_ID, payer, lmsPubkey: KAT_H5_PUBKEY });
    expect(v.equals(vault)).toBe(true);
    expect(toHex(instruction.data)).toBe(toHex(IX.createVault) + toHex(vaultId(KAT_H5_PUBKEY)) + toHex(KAT_H5_PUBKEY));
    expect(instruction.data.length).toBe(8 + 32 + 56);
    expect(keysOf(instruction)).toEqual([
      [payer.toBase58(), true, true],
      [vault.toBase58(), false, true],
      [SystemProgram.programId.toBase58(), false, false],
    ]);
  });

  it("open_sig_buffer: disc || nonce_le || vec<u8> action || sig_len_le || vec<u8> first_chunk", () => {
    const action = encodeAction({ kind: "Close", to: PK_22, issuedSlot: 0n, expirySlot: 5n });
    const { instruction, sigBuffer } = openSigBufferInstruction({ programId: VAULT_PROGRAM_ID, vault, payer, nonce: NONCE, action, sigLen: 2348 });
    expect(sigBuffer.equals(findSigBufferPda(VAULT_PROGRAM_ID, vault, payer, NONCE).address)).toBe(true);
    expect(toHex(instruction.data)).toBe(toHex(IX.openSigBuffer) + "0807060504030201" + "31000000" + toHex(action) + "2c09" + "00000000");
    expect(keysOf(instruction)).toEqual([
      [payer.toBase58(), true, true],
      [vault.toBase58(), false, false],
      [sigBuffer.toBase58(), false, true],
      [SystemProgram.programId.toBase58(), false, false],
    ]);
    const withChunk = openSigBufferInstruction({ programId: VAULT_PROGRAM_ID, vault, payer, nonce: NONCE, action, sigLen: 2348, firstChunk: new Uint8Array([1, 2, 3]) });
    expect(toHex(withChunk.instruction.data.subarray(-7))).toBe("03000000010203");
    expect(() => openSigBufferInstruction({ programId: VAULT_PROGRAM_ID, vault, payer, nonce: NONCE, action: new Uint8Array(257), sigLen: 1 })).toThrow();
    expect(() => openSigBufferInstruction({ programId: VAULT_PROGRAM_ID, vault, payer, nonce: NONCE, action: new Uint8Array(0), sigLen: 1 })).toThrow();
    expect(() => openSigBufferInstruction({ programId: VAULT_PROGRAM_ID, vault, payer, nonce: NONCE, action, sigLen: 2, firstChunk: new Uint8Array(3) })).toThrow();
  });

  it("write_sig: disc || offset_le_u16 || vec<u8> chunk; payer signs read-only", () => {
    const sigBuffer = PK_33;
    const chunk = new Uint8Array([9, 8, 7]);
    const ix = writeSigInstruction({ programId: VAULT_PROGRAM_ID, sigBuffer, payer, offset: 900, chunk });
    expect(toHex(ix.data)).toBe(toHex(IX.writeSig) + "8403" + "03000000" + "090807");
    expect(keysOf(ix)).toEqual([
      [payer.toBase58(), true, false],
      [sigBuffer.toBase58(), false, true],
    ]);
    expect(() => writeSigInstruction({ programId: VAULT_PROGRAM_ID, sigBuffer, payer, offset: 0, chunk: new Uint8Array(901) })).toThrow();
  });

  it("close_sig_buffer and execute carry only the discriminator", () => {
    const close = closeSigBufferInstruction({ programId: VAULT_PROGRAM_ID, sigBuffer: PK_33, payer });
    expect(toHex(close.data)).toBe(toHex(IX.closeSigBuffer));
    expect(keysOf(close)).toEqual([
      [payer.toBase58(), true, true],
      [PK_33.toBase58(), false, true],
    ]);
    const ix = executeInstruction({ programId: VAULT_PROGRAM_ID, vault, sigBuffer: PK_33, payer, action: { kind: "Rotate", newLmsPubkey: KAT_H10_PUBKEY, issuedSlot: 0n, expirySlot: 1n } });
    expect(toHex(ix.data)).toBe(toHex(IX.execute));
    expect(keysOf(ix)).toEqual([
      [vault.toBase58(), false, true],
      [PK_33.toBase58(), false, true],
      [payer.toBase58(), false, true],
    ]);
  });

  it("execute remaining accounts follow the action", () => {
    expect(executeRemainingAccounts(vault, { kind: "TransferSol", to: PK_22, lamports: 1n, issuedSlot: 0n, expirySlot: 1n }).map((k) => [k.pubkey.toBase58(), k.isWritable])).toEqual([[PK_22.toBase58(), true]]);
    expect(executeRemainingAccounts(vault, { kind: "Close", to: PK_22, issuedSlot: 0n, expirySlot: 1n }).map((k) => k.pubkey.toBase58())).toEqual([PK_22.toBase58()]);
    expect(
      executeRemainingAccounts(vault, { kind: "Close", to: PK_22, issuedSlot: 0n, expirySlot: 1n }, TOKEN_PROGRAM_ID, [{ account: PK_33 }, { account: PK_11, tokenProgram: TOKEN_2022_PROGRAM_ID }]).map((k) => [k.pubkey.toBase58(), k.isWritable]),
    ).toEqual([
      [PK_22.toBase58(), true],
      [PK_33.toBase58(), true],
      [TOKEN_PROGRAM_ID.toBase58(), false],
      [PK_11.toBase58(), true],
      [TOKEN_2022_PROGRAM_ID.toBase58(), false],
    ]);
    expect(executeRemainingAccounts(vault, { kind: "Rotate", newLmsPubkey: KAT_H10_PUBKEY, issuedSlot: 0n, expirySlot: 1n })).toEqual([]);
    const tok = executeRemainingAccounts(vault, { kind: "TransferToken", mint: PK_22, to: PK_33, amount: 1n, issuedSlot: 0n, expirySlot: 1n });
    expect(tok.map((k) => [k.pubkey.toBase58(), k.isWritable])).toEqual([
      [associatedTokenAddress(vault, PK_22).toBase58(), true],
      [PK_33.toBase58(), true],
      [PK_22.toBase58(), false],
      [TOKEN_PROGRAM_ID.toBase58(), false],
    ]);
    const tok22 = executeRemainingAccounts(vault, { kind: "TransferToken", mint: PK_22, to: PK_33, amount: 1n, issuedSlot: 0n, expirySlot: 1n }, TOKEN_2022_PROGRAM_ID);
    expect(tok22[0]!.pubkey.equals(associatedTokenAddress(vault, PK_22, TOKEN_2022_PROGRAM_ID))).toBe(true);
    expect(tok22[3]!.pubkey.equals(TOKEN_2022_PROGRAM_ID)).toBe(true);
    // a token sitting in a non-associated account owned by the vault is drawn from that account
    const aux = executeRemainingAccounts(vault, { kind: "TransferToken", mint: PK_22, to: PK_33, amount: 1n, issuedSlot: 0n, expirySlot: 1n }, TOKEN_PROGRAM_ID, [], PK_11);
    expect(aux[0]!.pubkey.equals(PK_11)).toBe(true);
    expect(aux[0]!.isWritable).toBe(true);
    // TransferTokenFrom: the signed `from` is the source, no default and no override
    const from = executeRemainingAccounts(vault, { kind: "TransferTokenFrom", from: PK_11, mint: PK_22, to: PK_33, amount: 1n, issuedSlot: 0n, expirySlot: 1n }, TOKEN_2022_PROGRAM_ID);
    expect(from.map((k) => [k.pubkey.toBase58(), k.isWritable])).toEqual([
      [PK_11.toBase58(), true],
      [PK_33.toBase58(), true],
      [PK_22.toBase58(), false],
      [TOKEN_2022_PROGRAM_ID.toBase58(), false],
    ]);
    expect(executeRemainingAccounts(vault, { kind: "TransferTokenFrom", from: PK_11, mint: PK_22, to: PK_33, amount: 1n, issuedSlot: 0n, expirySlot: 1n }, TOKEN_PROGRAM_ID, [], PK_11)[0]!.pubkey.equals(PK_11)).toBe(true);
    expect(() => executeRemainingAccounts(vault, { kind: "TransferTokenFrom", from: PK_11, mint: PK_22, to: PK_33, amount: 1n, issuedSlot: 0n, expirySlot: 1n }, TOKEN_PROGRAM_ID, [], PK_44)).toThrow(/differs/);
  });

  it("sweep_closed: payer, tombstone, heir, heir ATA, vault token account, mint, token program, system, ATA program; only the discriminator", () => {
    const { instruction, heirTokenAccount } = sweepClosedInstruction({ programId: VAULT_PROGRAM_ID, payer, vault, heir: PK_22, mint: PK_11, vaultTokenAccount: PK_33 });
    expect(toHex(instruction.data)).toBe(toHex(IX.sweepClosed));
    expect(toHex(IX.sweepClosed)).toBe(toHex(instructionDiscriminator("sweep_closed")));
    expect(heirTokenAccount.equals(associatedTokenAddress(PK_22, PK_11, TOKEN_PROGRAM_ID))).toBe(true);
    expect(keysOf(instruction)).toEqual([
      [payer.toBase58(), true, true],
      [vault.toBase58(), false, false],
      [PK_22.toBase58(), false, true],
      [heirTokenAccount.toBase58(), false, true],
      [PK_33.toBase58(), false, true],
      [PK_11.toBase58(), false, false],
      [TOKEN_PROGRAM_ID.toBase58(), false, false],
      [SystemProgram.programId.toBase58(), false, false],
      [ASSOCIATED_TOKEN_PROGRAM_ID.toBase58(), false, false],
    ]);
    // Token-2022: the heir's ATA is the one under that program, and the program is passed along.
    const t22 = sweepClosedInstruction({ programId: VAULT_PROGRAM_ID, payer, vault, heir: PK_22, mint: PK_11, vaultTokenAccount: PK_33, tokenProgram: TOKEN_2022_PROGRAM_ID });
    expect(t22.heirTokenAccount.equals(associatedTokenAddress(PK_22, PK_11, TOKEN_2022_PROGRAM_ID))).toBe(true);
    expect(t22.instruction.keys[3]!.pubkey.equals(t22.heirTokenAccount)).toBe(true);
    expect(t22.instruction.keys[6]!.pubkey.equals(TOKEN_2022_PROGRAM_ID)).toBe(true);
  });

  it("execute transaction requests 400k compute units first", () => {
    const ixs = executeInstructions({ programId: VAULT_PROGRAM_ID, vault, sigBuffer: PK_33, payer, action: { kind: "Close", to: PK_22, issuedSlot: 0n, expirySlot: 1n } });
    expect(ixs.length).toBe(2);
    expect(ixs[0]!.programId.equals(ComputeBudgetProgram.programId)).toBe(true);
    expect(toHex(ixs[0]!.data)).toBe(toHex(ComputeBudgetProgram.setComputeUnitLimit({ units: EXECUTE_COMPUTE_UNITS }).data));
    expect(EXECUTE_COMPUTE_UNITS).toBe(400_000);
  });

  it("stages with the first chunk in open_sig_buffer: H10 needs 4 transactions, every one fits a packet", () => {
    const kp = Keypair.generate();
    const actions: Action[] = [
      { kind: "TransferSol", to: PK_22, lamports: 1n, issuedSlot: 0n, expirySlot: 1n },
      { kind: "TransferToken", mint: PK_22, to: PK_33, amount: 1n, issuedSlot: 0n, expirySlot: 1n },
      { kind: "Rotate", newLmsPubkey: KAT_H10_PUBKEY, issuedSlot: 0n, expirySlot: 1n },
      { kind: "Close", to: PK_22, issuedSlot: 0n, expirySlot: 1n },
    ];
    for (const lms of [LMS_SHA256_M32_H5, LMS_SHA256_M32_H10, 7, 8]) {
      const sig = new Uint8Array(lmsSignatureLength(lms, LMOTS_SHA256_N32_W4)).map((_, i) => (i * 13) & 0xff);
      for (const action of actions) {
        const staged = buildStagedExecution({ programId: VAULT_PROGRAM_ID, vault, payer: kp.publicKey, nonce: NONCE, action, signature: sig });
        expect(staged.firstChunk.length).toBeGreaterThan(600);
        expect(staged.firstChunk.length).toBeLessThanOrEqual(MAX_CHUNK_BYTES);
        // reassembly
        const all = Buffer.concat([staged.firstChunk, ...staged.chunks.map((c) => c.bytes)]);
        expect(toHex(all)).toBe(toHex(sig));
        expect(staged.chunks[0]?.offset ?? sig.length).toBe(staged.firstChunk.length);
        if (lms === LMS_SHA256_M32_H10) expect(staged.transactions.length).toBe(4);
        for (const ixs of staged.transactions) {
          const tx = new Transaction({ feePayer: kp.publicKey, blockhash: "11111111111111111111111111111111", lastValidBlockHeight: 1 }).add(...ixs);
          tx.sign(kp);
          expect(tx.serialize().length).toBeLessThanOrEqual(PACKET_DATA_SIZE);
        }
      }
    }
    // explicit sizes
    const sig = new Uint8Array(2508);
    const none = buildStagedExecution({ programId: VAULT_PROGRAM_ID, vault, payer: kp.publicKey, nonce: NONCE, action: actions[0]!, signature: sig, firstChunkSize: 0 });
    expect(none.firstChunk.length).toBe(0);
    expect(none.chunks.map((c) => c.bytes.length)).toEqual([900, 900, 708]);
    expect(none.transactions.length).toBe(5);
    expect(() => buildStagedExecution({ programId: VAULT_PROGRAM_ID, vault, payer: kp.publicKey, nonce: NONCE, action: actions[0]!, signature: sig, firstChunkSize: 2509 })).toThrow(RangeError);
    const cap = openSigBufferFirstChunkCapacity({ programId: VAULT_PROGRAM_ID, vault, payer: kp.publicKey, nonce: NONCE, action: encodeAction(actions[0]!), sigLen: 2508 });
    expect(cap).toBeGreaterThan(700);
  });
});

describe("registry instruction data", () => {
  it("commit: disc || pq_pubkey[56]; owner, payer, commitment, system_program", () => {
    const { instruction, commitment } = commitInstruction({ programId: REGISTRY_PROGRAM_ID, owner: PK_11, pqPubkey: KAT_H10_PUBKEY });
    expect(toHex(instruction.data)).toBe(toHex(IX.commit) + toHex(KAT_H10_PUBKEY));
    expect(keysOf(instruction)).toEqual([
      [PK_11.toBase58(), true, true],
      [PK_11.toBase58(), true, true],
      [commitment.toBase58(), false, true],
      [SystemProgram.programId.toBase58(), false, false],
    ]);
    const split = commitInstruction({ programId: REGISTRY_PROGRAM_ID, owner: PK_11, payer: PK_22, pqPubkey: KAT_H10_PUBKEY });
    expect(keysOf(split.instruction).slice(0, 2)).toEqual([
      [PK_11.toBase58(), true, false],
      [PK_22.toBase58(), true, true],
    ]);
  });

  it("open_pq_buffer / write_pq_sig / close_pq_buffer / rotate_pq", () => {
    const window = { issuedSlot: 0x1234n, expirySlot: 0x5678n };
    const { instruction: open, buffer, commitment } = openPqBufferInstruction({ programId: REGISTRY_PROGRAM_ID, owner: PK_11, payer: PK_22, nonce: NONCE, newPqPubkey: KAT_H5_PUBKEY, sigLen: 2508, window });
    // disc || nonce_le || new_pq_pubkey || sig_len_le || issued_slot_le || expiry_slot_le
    expect(toHex(open.data)).toBe(toHex(IX.openPqBuffer) + "0807060504030201" + toHex(KAT_H5_PUBKEY) + "cc09" + "3412000000000000" + "7856000000000000");
    // a window the chain would refuse is refused here
    expect(() => openPqBufferInstruction({ programId: REGISTRY_PROGRAM_ID, owner: PK_11, payer: PK_22, nonce: NONCE, newPqPubkey: KAT_H5_PUBKEY, sigLen: 2508, window: { issuedSlot: 10n, expirySlot: 9n } })).toThrow(/inverted/);
    expect(() => openPqBufferInstruction({ programId: REGISTRY_PROGRAM_ID, owner: PK_11, payer: PK_22, nonce: NONCE, newPqPubkey: KAT_H5_PUBKEY, sigLen: 2508, window: { issuedSlot: 0n, expirySlot: 216_001n } })).toThrow(/MAX_VALIDITY_SLOTS/);
    expect(keysOf(open)).toEqual([
      [PK_22.toBase58(), true, true],
      [commitment.toBase58(), false, false],
      [buffer.toBase58(), false, true],
      [SystemProgram.programId.toBase58(), false, false],
    ]);
    const write = writePqSigInstruction({ programId: REGISTRY_PROGRAM_ID, buffer, payer: PK_22, offset: 900, chunk: new Uint8Array([1]) });
    expect(toHex(write.data)).toBe(toHex(IX.writePqSig) + "8403" + "01000000" + "01");
    expect(keysOf(write)).toEqual([
      [PK_22.toBase58(), true, false],
      [buffer.toBase58(), false, true],
    ]);
    expect(toHex(closePqBufferInstruction({ programId: REGISTRY_PROGRAM_ID, buffer, payer: PK_22 }).data)).toBe(toHex(IX.closePqBuffer));

    const sig = new Uint8Array(2508).fill(1);
    const staged = buildStagedRotatePq({ programId: REGISTRY_PROGRAM_ID, owner: PK_11, payer: PK_22, nonce: NONCE, newPqPubkey: KAT_H5_PUBKEY, window, signature: sig });
    expect(staged.chunks.map((c) => c.bytes.length)).toEqual([900, 900, 708]);
    expect(toHex(Buffer.concat(staged.chunks.map((c) => c.bytes)))).toBe(toHex(sig));
    expect(staged.transactions.length).toBe(5);
    expect(toHex(staged.rotate[1]!.data)).toBe(toHex(IX.rotatePq));
    expect(keysOf(staged.rotate[1]!)).toEqual([
      [staged.commitment.toBase58(), false, true],
      [staged.buffer.toBase58(), false, true],
      [PK_22.toBase58(), false, true],
    ]);
    const kp = Keypair.generate();
    for (const ixs of buildStagedRotatePq({ programId: REGISTRY_PROGRAM_ID, owner: PK_11, payer: kp.publicKey, nonce: NONCE, newPqPubkey: KAT_H5_PUBKEY, window, signature: new Uint8Array(2828) }).transactions) {
      const tx = new Transaction({ feePayer: kp.publicKey, blockhash: "11111111111111111111111111111111", lastValidBlockHeight: 1 }).add(...ixs);
      tx.sign(kp);
      expect(tx.serialize().length).toBeLessThanOrEqual(PACKET_DATA_SIZE);
    }
  });
});
