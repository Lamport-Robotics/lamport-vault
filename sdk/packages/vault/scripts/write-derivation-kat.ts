/**
 * Writes kat/derivation_v2.json: test vectors for the v2 key derivation (docs/SPEC-DERIVATION.md),
 * master -> (SEED_k, I_k) -> H5 public key, per cluster and program id. Every implementation of
 * the derivation (this SDK, the Rust crate, firmware) must reproduce them.
 *
 *   node packages/vault/scripts/write-derivation-kat.ts        (from sdk/)
 *
 * It lives in the vault package because that is where the program ids are declared.
 */
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  base58Decode,
  CLUSTERS,
  deriveLmsInputs,
  DERIVATION_VERSION,
  derivationInfo,
  ID_DOMAIN,
  ID_INFO_LABEL,
  LMOTS_SHA256_N32_W4,
  LMS_SHA256_M32_H5,
  LmsPrivateKey,
  mnemonicToMaster,
  REGISTRY_KEY_INDEX,
  SEED_DOMAIN,
  SEED_INFO_LABEL,
  toHex,
} from "../../lms/src/index.ts";
import { LAMPORT_VAULT_PROGRAM_ID, PQ_REGISTRY_PROGRAM_ID } from "../src/programIds.ts";

const out = fileURLToPath(new URL("../../../../kat/derivation_v2.json", import.meta.url));

// The BIP-39 reference phrase (Trezor vectors, entropy 0x00..00), with and without the "TREZOR" passphrase.
const REF_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const masters = {
  ref: { mnemonic: REF_MNEMONIC, passphrase: "", master: mnemonicToMaster(REF_MNEMONIC) },
  ref_trezor: { mnemonic: REF_MNEMONIC, passphrase: "TREZOR", master: mnemonicToMaster(REF_MNEMONIC, "TREZOR") },
};

const programs = {
  lamport_vault: LAMPORT_VAULT_PROGRAM_ID,
  pq_registry: PQ_REGISTRY_PROGRAM_ID,
};

interface Plan {
  master: keyof typeof masters;
  cluster: keyof typeof CLUSTERS;
  program: keyof typeof programs;
  k: number;
}

const plan: Plan[] = [
  { master: "ref", cluster: "devnet", program: "lamport_vault", k: 0 },
  { master: "ref", cluster: "devnet", program: "lamport_vault", k: 1 },
  { master: "ref", cluster: "devnet", program: "lamport_vault", k: 65535 },
  { master: "ref", cluster: "mainnet", program: "lamport_vault", k: 0 },
  { master: "ref", cluster: "devnet", program: "pq_registry", k: REGISTRY_KEY_INDEX },
  { master: "ref", cluster: "mainnet", program: "pq_registry", k: REGISTRY_KEY_INDEX },
  { master: "ref_trezor", cluster: "devnet", program: "lamport_vault", k: 0 },
];

export function writeDerivationKat(): void {
  const vectors = plan.map((p) => {
    const m = masters[p.master];
    const cluster = CLUSTERS[p.cluster];
    const programId = programs[p.program];
    const scope = { genesisHash: cluster.genesisHash, programId };
    const { seed, I } = deriveLmsInputs(m.master, p.k, scope);
    const key = LmsPrivateKey.generate({ lmsType: LMS_SHA256_M32_H5, lmotsType: LMOTS_SHA256_N32_W4, seed, I });
    return {
      name: `${p.master} / ${cluster.name} / ${p.program} / k=${p.k}`,
      master: p.master,
      master_hex: toHex(m.master),
      cluster: cluster.name,
      genesis_hash: cluster.genesisHash,
      genesis_hash_hex: toHex(base58Decode(cluster.genesisHash)),
      program: p.program,
      program_id: programId.toBase58(),
      program_id_hex: toHex(programId.toBytes()),
      k: p.k,
      seed_info_hex: toHex(derivationInfo(scope, p.k, SEED_INFO_LABEL)),
      id_info_hex: toHex(derivationInfo(scope, p.k, ID_INFO_LABEL)),
      seed_hex: toHex(seed),
      I_hex: toHex(I),
      lms_type: LMS_SHA256_M32_H5,
      lmots_type: LMOTS_SHA256_N32_W4,
      public_key_hex: toHex(key.publicKey),
    };
  });
  const doc = {
    source: "@lamport-robotics/lms (this repository), docs/SPEC-DERIVATION.md",
    version: DERIVATION_VERSION,
    formula: {
      seed: `SEED_k = HKDF-SHA256(ikm = master, salt = "${SEED_DOMAIN}", info = genesis_hash[32] || program_id[32] || u32be(k) || "${SEED_INFO_LABEL}")[0..32]`,
      id: `I_k = HKDF-SHA256(ikm = master, salt = "${ID_DOMAIN}", info = genesis_hash[32] || program_id[32] || u32be(k) || "${ID_INFO_LABEL}")[0..16]`,
      master: 'BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic" || passphrase), 64 bytes',
      registry_key_index: REGISTRY_KEY_INDEX,
      seed_salt_hex: toHex(new TextEncoder().encode(SEED_DOMAIN)),
      id_salt_hex: toHex(new TextEncoder().encode(ID_DOMAIN)),
    },
    masters: Object.fromEntries(Object.entries(masters).map(([k, v]) => [k, { mnemonic: v.mnemonic, passphrase: v.passphrase, master_hex: toHex(v.master) }])),
    clusters: Object.fromEntries(
      Object.values(CLUSTERS).map((c) => [c.name, { genesis_hash: c.genesisHash, genesis_hash_hex: toHex(base58Decode(c.genesisHash)) }]),
    ),
    programs: Object.fromEntries(Object.entries(programs).map(([k, v]) => [k, { program_id: v.toBase58(), program_id_hex: toHex(v.toBytes()) }])),
    vectors,
  };
  writeFileSync(out, JSON.stringify(doc, null, 2) + "\n");
  console.log(`wrote ${out} (${vectors.length} vectors)`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) writeDerivationKat();
