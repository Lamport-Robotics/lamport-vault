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
import { commitmentAccountSize, COMMITMENT_MAX_KEY_HISTORY, encodeCommitment, encodePqSigBuffer, encodeSigBuffer, encodeTombstone, encodeVault, KEY_HASH_LEN, TOMBSTONE_ACCOUNT_VERSION, usedKeyHash, vaultAccountSize, VAULT_MAX_KEY_HISTORY } from "../src/accounts.ts";
import { type Action, ACTION_SIZES, encodeAction, MAX_VALIDITY_SLOTS } from "../src/action.ts";
import { ACCOUNT, IX } from "../src/discriminator.ts";
import { createVaultInstruction, openSigBufferInstruction, writeSigInstruction } from "../src/instructions.ts";
import { MESSAGE_VERSION, registryMessage, vaultMessage } from "../src/message.ts";
import { findCommitmentPda, findPqSigBufferPda, findSigBufferPda, findVaultPda, vaultId } from "../src/pda.ts";
import { LAMPORT_VAULT_PROGRAM_ID, PQ_REGISTRY_PROGRAM_ID } from "../src/programIds.ts";
import { commitInstruction, openPqBufferInstruction } from "../src/registry.ts";
import { writeDerivationKat } from "./write-derivation-kat.ts";

const out = fileURLToPath(new URL("../../../../kat/vault_encoding.json", import.meta.url));

const PK_11 = new PublicKey(new Uint8Array(32).fill(0x11));
const PK_22 = new PublicKey(new Uint8Array(32).fill(0x22));
const H5_PUBKEY = fromHex("000000050000000300112233445566778899aabbccddeeffcd079a17aad0d1f9554c1812f20a4d465dd0503acd83608f890a58d715e20253");
const H10_PUBKEY = fromHex("00000006000000034c616d706f727420526f626f7469637363aa0e1c3a5949b62fc83d2506d79688f5116d25fbd201c70a63bf3bec9a8521");
const NONCE = 0x0102030405060708n;
const ISSUED = 0x12340000n;
const EXPIRY = 0x12345678n;
const WINDOW = { issuedSlot: ISSUED, expirySlot: EXPIRY };
/** Key generation the vault message vectors are bound to (the vault account vector has the same generation). */
const GENERATION = 2;
/** Generation of the registry message vector and of the commitment account vector. */
const REGISTRY_GENERATION = 1;
/** A third key, only ever seen as a hash in the vault vector's history. */
const H5_PAST_PUBKEY = fromHex("0000000500000003" + "aa".repeat(16) + "bb".repeat(32));

const actions: Record<string, Action> = {
  transfer_sol: { kind: "TransferSol", to: PK_11, lamports: 1_500_000_000n, ...WINDOW },
  transfer_token: { kind: "TransferToken", mint: PK_22, to: PK_11, amount: 123_456_789_012n, ...WINDOW },
  rotate: { kind: "Rotate", newLmsPubkey: H10_PUBKEY, ...WINDOW },
  close: { kind: "Close", to: PK_11, ...WINDOW },
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
    return [name, { action: JSON.parse(JSON.stringify(a, plain)), action_hex: toHex(bytes), message_hex: toHex(vaultMessage(vault.address, GENERATION, bytes)) }];
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
    issued_slot: ISSUED.toString(),
    issued_slot_le_hex: "0000341200000000",
    expiry_slot: EXPIRY.toString(),
    expiry_slot_le_hex: "7856341200000000",
    generation: String(GENERATION),
    registry_generation: String(REGISTRY_GENERATION),
  },
  discriminators: {
    instructions: {
      create_vault: toHex(IX.createVault),
      open_sig_buffer: toHex(IX.openSigBuffer),
      write_sig: toHex(IX.writeSig),
      close_sig_buffer: toHex(IX.closeSigBuffer),
      execute: toHex(IX.execute),
      execute_direct: toHex(IX.executeDirect),
      commit: toHex(IX.commit),
      open_pq_buffer: toHex(IX.openPqBuffer),
      write_pq_sig: toHex(IX.writePqSig),
      close_pq_buffer: toHex(IX.closePqBuffer),
      rotate_pq: toHex(IX.rotatePq),
    },
    accounts: {
      Vault: toHex(ACCOUNT.vault),
      Tombstone: toHex(ACCOUNT.tombstone),
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
  validity: {
    note: "every Action ends in issued_slot || expiry_slot (u64le each); the program requires issued_slot <= slot <= expiry_slot and expiry_slot - issued_slot <= max_validity_slots",
    max_validity_slots: Number(MAX_VALIDITY_SLOTS),
    action_sizes: ACTION_SIZES,
  },
  actions: actionVectors,
  messages: {
    message_version: MESSAGE_VERSION,
    vault_prefix_hex: toHex(new TextEncoder().encode("lamport-vault/v1")),
    vault_message_formula: "sha256(prefix || program_id || vault || u32le(generation) || action_bytes)",
    vault_message_inputs: { program_id: LAMPORT_VAULT_PROGRAM_ID.toBase58(), vault: vault.address.toBase58(), generation: String(GENERATION) },
    registry_prefix_hex: toHex(new TextEncoder().encode("pq-registry/v1")),
    registry_message_formula: "sha256(prefix || program_id || owner || u32le(generation) || new_pq_pubkey || u64le(issued_slot) || u64le(expiry_slot))",
    registry_message_hex: toHex(registryMessage(PK_11, REGISTRY_GENERATION, H10_PUBKEY, WINDOW)),
    registry_message_inputs: {
      program_id: PQ_REGISTRY_PROGRAM_ID.toBase58(),
      owner: PK_11.toBase58(),
      generation: String(REGISTRY_GENERATION),
      new_pq_pubkey_hex: toHex(H10_PUBKEY),
      issued_slot: ISSUED.toString(),
      expiry_slot: EXPIRY.toString(),
    },
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
    open_pq_buffer_hex: toHex(openPqBufferInstruction({ programId: PQ_REGISTRY_PROGRAM_ID, owner: PK_11, payer: PK_22, nonce: NONCE, newPqPubkey: H5_PUBKEY, sigLen: 2508, window: WINDOW }).instruction.data),
  },
  accounts: {
    // H5 vault at generation 2: 6 leaves spent (bits 0,1,2,22,24,31), the two past keys were H10_PUBKEY and H5_PAST_PUBKEY.
    vault_hex: toHex(
      encodeVault({
        version: 2,
        bump: vault.bump,
        vaultId: id,
        lmsPubkey: H5_PUBKEY,
        spent: 6,
        generation: GENERATION,
        createdSlot: 0x1122334455n,
        used: new Uint8Array([0x07, 0x00, 0x40, 0x81]),
        usedKeys: [usedKeyHash(H10_PUBKEY), usedKeyHash(H5_PAST_PUBKEY)],
      }),
    ),
    // What Close leaves at the vault's address: version 0xfe, the vault id, the slot of the close.
    tombstone_hex: toHex(encodeTombstone({ version: TOMBSTONE_ACCOUNT_VERSION, vaultId: id, closedSlot: 0x1122334466n })),
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
    // Commitment at generation 1: H10_PUBKEY is committed, H5_PUBKEY was the key before.
    commitment_hex: toHex(
      encodeCommitment({
        version: 2,
        bump: commitment.bump,
        owner: PK_11,
        scheme: 1,
        pqPubkey: H10_PUBKEY,
        nextQ: 3,
        generation: REGISTRY_GENERATION,
        createdSlot: 100n,
        updatedSlot: 200n,
        usedKeys: [usedKeyHash(H5_PUBKEY)],
      }),
    ),
    pq_sig_buffer_hex: toHex(
      encodePqSigBuffer({
        version: 1,
        bump: pqSigBuffer.bump,
        owner: PK_11,
        payer: PK_22,
        nonce: NONCE,
        newPqPubkey: H5_PUBKEY,
        ...WINDOW,
        sigLen: 4,
        filled: 1,
        sig: new Uint8Array([0xaa, 0, 0, 0]),
      }),
    ),
    sizes: {
      note: "fresh accounts (no key history); each Rotate / rotate_pq adds one key_history_entry",
      vault_h5: vaultAccountSize(5),
      vault_h10: vaultAccountSize(6),
      vault_h15: vaultAccountSize(7),
      key_history_entry: KEY_HASH_LEN,
      vault_max_key_history: VAULT_MAX_KEY_HISTORY,
      commitment: commitmentAccountSize(0),
      commitment_max_key_history: COMMITMENT_MAX_KEY_HISTORY,
    },
  },
  key_hashes: {
    note: "used_keys entries are sha256(pubkey)[0..16]",
    h5_pubkey: toHex(usedKeyHash(H5_PUBKEY)),
    h10_pubkey: toHex(usedKeyHash(H10_PUBKEY)),
    h5_past_pubkey_hex: toHex(H5_PAST_PUBKEY),
    h5_past_pubkey: toHex(usedKeyHash(H5_PAST_PUBKEY)),
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
writeDerivationKat();
