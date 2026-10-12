/** Fixed inputs shared by the vault tests and the kat/vault_encoding.json writer. */
import { PublicKey } from "@solana/web3.js";
import { fromHex } from "@lamport-robotics/lms";
import { LAMPORT_VAULT_PROGRAM_ID, PQ_REGISTRY_PROGRAM_ID } from "../src/programIds.ts";

export const VAULT_PROGRAM_ID = LAMPORT_VAULT_PROGRAM_ID;
export const REGISTRY_PROGRAM_ID = PQ_REGISTRY_PROGRAM_ID;

export const PK_11 = new PublicKey(new Uint8Array(32).fill(0x11));
export const PK_22 = new PublicKey(new Uint8Array(32).fill(0x22));
export const PK_33 = new PublicKey(new Uint8Array(32).fill(0x33));
export const PK_44 = new PublicKey(new Uint8Array(32).fill(0x44));

/** The H5 KAT public key (kat/lms_sha256_w4.json, vector 0). */
export const KAT_H5_PUBKEY = fromHex(
  "000000050000000300112233445566778899aabbccddeeffcd079a17aad0d1f9554c1812f20a4d465dd0503acd83608f890a58d715e20253",
);
/** The H10 KAT public key (vector 1). */
export const KAT_H10_PUBKEY = fromHex(
  "00000006000000034c616d706f727420526f626f7469637363aa0e1c3a5949b62fc83d2506d79688f5116d25fbd201c70a63bf3bec9a8521",
);

export const NONCE = 0x0102030405060708n;
