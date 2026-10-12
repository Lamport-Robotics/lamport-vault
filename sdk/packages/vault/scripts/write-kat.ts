/**
 * Writes kat/vault_encoding.json: byte-exact vectors for everything the Rust programs and the SDK
 * must agree on: Borsh actions, signed-message digests, Anchor discriminators, instruction data,
 * account layouts and PDAs (under the program ids declared in programs/).
 *
 *   node packages/vault/scripts/write-kat.ts        (from sdk/)
 */
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { PublicKey } from "@solana/web3.js";
import { fromHex, toHex } from "../../lms/src/index.ts";
import { encodeCommitment, encodePqSigBuffer, encodeSigBuffer, encodeVault } from "../src/accounts.ts";
import { type Action, encodeAction } from "../src/action.ts";
import { ACCOUNT, IX } from "../src/discriminator.ts";
import { createVaultInstruction, openSigBufferInstruction, writeSigInstruction } from "../src/instructions.ts";
import { registryMessage, vaultMessage } from "../src/message.ts";
import { findCommitmentPda, findPqSigBufferPda, findSigBufferPda, findVaultPda, vaultId } from "../src/pda.ts";
import { LAMPORT_VAULT_PROGRAM_ID, PQ_REGISTRY_PROGRAM_ID } from "../src/programIds.ts";
import { commitInstruction, openPqBufferInstruction } from "../src/registry.ts";

const out = fileURLToPath(new URL("../../../../kat/vault_encoding.json", import.meta.url));

const PK_11 = new PublicKey(new Uint8Array(32).fill(0x11));
const PK_22 = new PublicKey(new Uint8Array(32).fill(0x22));
const H5_PUBKEY = fromHex("000000050000000300112233445566778899aabbccddeeffcd079a17aad0d1f9554c1812f20a4d465dd0503acd83608f890a58d715e20253");
const H10_PUBKEY = fromHex("00000006000000034c616d706f727420526f626f7469637363aa0e1c3a5949b62fc83d2506d79688f5116d25fbd201c70a63bf3bec9a8521");
const NONCE = 0x0102030405060708n;
const EXPIRY = 0x12345678n;

const actions: Record<string, Action> = {
  transfer_sol: { kind: "TransferSol", to: PK_11, lamports: 1_500_000_000n, expirySlot: EXPIRY },
  transfer_token: { kind: "TransferToken", mint: PK_22, to: PK_11, amount: 123_456_789_012n, expirySlot: EXPIRY },
  rotate: { kind: "Rotate", newLmsPubkey: H10_PUBKEY, expirySlot: EXPIRY },
  close: { kind: "Close", to: PK_11, expirySlot: EXPIRY },
};

const id = vaultId(H5_PUBKEY);
const vault = findVaultPda(LAMPORT_VAULT_PROGRAM_ID, id);
const sigBuffer = findSigBufferPda(LAMPORT_VAULT_PROGRAM_ID, vault.address, PK_11, NONCE);
const commitment = findCommitmentPda(PQ_REGISTRY_PROGRAM_ID, PK_11);
const pqSigBuffer = findPqSigBufferPda(PQ_REGISTRY_PROGRAM_ID, PK_11, PK_22, NONCE);

const plain = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v instanceof Uint8Array ? toHex(v) : v instanceof PublicKey ? v.toBase58() : v);

const actionVectors = Object.fromEntries(
  Object.entries(actions).map(([name, a]) => {
    const bytes = encodeAction(a);
    return [name, { action: JSON.parse(JSON.stringify(a, plain)), action_hex: toHex(bytes), message_hex: toHex(vaultMessage(vault.address, bytes)) }];
  }),
);

const closeAction = encodeAction(actions.close!);

const doc = {
  source: "@lamport-robotics/vault (this repository)",
  program_ids: { lamport_vault: LAMPORT_VAULT_PROGRAM_ID.toBase58(), pq_registry: PQ_REGISTRY_PROGRAM_ID.toBase58() },
  inputs: {
    pk_11: PK_11.toBase58(),
    pk_22: PK_22.toBase58(),
    pk_11_hex: "11".repeat(32),
    pk_22_hex: "22".repeat(32),
    h5_pubkey_hex: toHex(H5_PUBKEY),
    h10_pubkey_hex: toHex(H10_PUBKEY),
    nonce: NONCE.toString(),
    nonce_le_hex: "0807060504030201",
    expiry_slot: EXPIRY.toString(),
  },
  discriminators: {
    instructions: {
      create_vault: toHex(IX.createVault),
      open_sig_buffer: toHex(IX.openSigBuffer),
      write_sig: toHex(IX.writeSig),
      close_sig_buffer: toHex(IX.closeSigBuffer),
      execute: toHex(IX.execute),
      commit: toHex(IX.commit),
      open_pq_buffer: toHex(IX.openPqBuffer),
      write_pq_sig: toHex(IX.writePqSig),
      close_pq_buffer: toHex(IX.closePqBuffer),
      rotate_pq: toHex(IX.rotatePq),
    },
    accounts: {
      Vault: toHex(ACCOUNT.vault),
      SigBuffer: toHex(ACCOUNT.sigBuffer),
      Commitment: toHex(ACCOUNT.commitment),
      PqSigBuffer: toHex(ACCOUNT.pqSigBuffer),
    },
  },
  pdas: {
    vault_id_hex: toHex(id),
    vault: { address: vault.address.toBase58(), bump: vault.bump, seeds: ["vault", "vault_id"] },
    sig_buffer: { address: sigBuffer.address.toBase58(), bump: sigBuffer.bump, seeds: ["sig", "vault", "payer=pk_11", "nonce_le_u64"] },
    commitment: { address: commitment.address.toBase58(), bump: commitment.bump, seeds: ["pq", "owner=pk_11"] },
    pq_sig_buffer: { address: pqSigBuffer.address.toBase58(), bump: pqSigBuffer.bump, seeds: ["pqsig", "owner=pk_11", "payer=pk_22", "nonce_le_u64"] },
  },
  actions: actionVectors,
  messages: {
    vault_prefix_hex: toHex(new TextEncoder().encode("lamport-vault/v1")),
    registry_prefix_hex: toHex(new TextEncoder().encode("pq-registry/v1")),
    registry_message_hex: toHex(registryMessage(PK_11, H10_PUBKEY)),
    registry_message_inputs: { owner: PK_11.toBase58(), new_pq_pubkey_hex: toHex(H10_PUBKEY) },
  },
  instruction_data: {
    create_vault_hex: toHex(createVaultInstruction({ programId: LAMPORT_VAULT_PROGRAM_ID, payer: PK_11, lmsPubkey: H5_PUBKEY }).instruction.data),
    open_sig_buffer_hex: toHex(
      openSigBufferInstruction({
        programId: LAMPORT_VAULT_PROGRAM_ID,
        vault: vault.address,
        payer: PK_11,
        nonce: NONCE,
        action: closeAction,
        sigLen: 2348,
        firstChunk: new Uint8Array([0xaa, 0xbb, 0xcc]),
      }).instruction.data,
    ),
    write_sig_hex: toHex(writeSigInstruction({ programId: LAMPORT_VAULT_PROGRAM_ID, sigBuffer: sigBuffer.address, payer: PK_11, offset: 900, chunk: new Uint8Array([9, 8, 7]) }).data),
    commit_hex: toHex(commitInstruction({ programId: PQ_REGISTRY_PROGRAM_ID, owner: PK_11, pqPubkey: H10_PUBKEY }).instruction.data),
    open_pq_buffer_hex: toHex(openPqBufferInstruction({ programId: PQ_REGISTRY_PROGRAM_ID, owner: PK_11, payer: PK_22, nonce: NONCE, newPqPubkey: H5_PUBKEY, sigLen: 2508 }).instruction.data),
  },
  accounts: {
    vault_hex: toHex(encodeVault({ version: 1, bump: vault.bump, vaultId: id, lmsPubkey: H5_PUBKEY, nextQ: 7, rotations: 2, createdSlot: 0x1122334455n })),
    sig_buffer_hex: toHex(
      encodeSigBuffer({
        version: 1,
        bump: sigBuffer.bump,
        vault: vault.address,
        payer: PK_11,
        nonce: NONCE,
        action: closeAction,
        sigLen: 4,
        filled: 2,
        sig: new Uint8Array([0xaa, 0xbb, 0, 0]),
      }),
    ),
    commitment_hex: toHex(encodeCommitment({ version: 1, bump: commitment.bump, owner: PK_11, scheme: 1, pqPubkey: H10_PUBKEY, nextQ: 3, createdSlot: 100n, updatedSlot: 200n })),
    pq_sig_buffer_hex: toHex(
      encodePqSigBuffer({
        version: 1,
        bump: pqSigBuffer.bump,
        owner: PK_11,
        payer: PK_22,
        nonce: NONCE,
        newPqPubkey: H5_PUBKEY,
        sigLen: 4,
        filled: 1,
        sig: new Uint8Array([0xaa, 0, 0, 0]),
      }),
    ),
  },
  chunking: {
    max_chunk_bytes: 900,
    note: "open_sig_buffer carries a first chunk sized to fill the packet and the remainder goes in 900-byte write_sig chunks; open_pq_buffer takes no chunk, so rotate_pq uses the plain chunking below",
    plain_h5_chunks: [900, 900, 548],
    plain_h10_chunks: [900, 900, 708],
    plain_h15_chunks: [900, 900, 868],
    plain_h20_chunks: [900, 900, 900, 128],
  },
};

writeFileSync(out, JSON.stringify(doc, null, 2) + "\n");
console.log(`wrote ${out}`);
