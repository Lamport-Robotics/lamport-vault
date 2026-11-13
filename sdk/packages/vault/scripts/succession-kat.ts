/**
 * Builds kat/succession_encoding.json: byte-exact vectors for what the Heir-enabled program (the
 * vault built with the `succession` feature) and the SDK must agree on: the `SetSuccession` action
 * and its signed message, the version-3 vault account, the new instructions' discriminators, the
 * duration constants, and a table of clock states with what the rules say about each.
 *
 * `write-succession-kat.ts` writes the file. The Rust side reads it in
 * `programs/lamport-vault/tests/succession_encoding.rs`, and `test/succession.test.ts` checks the
 * file on disk is what this builds.
 */
import { PublicKey } from "@solana/web3.js";
import { fromHex, LMS_SHA256_M32_H10, LMS_SHA256_M32_H15, LMS_SHA256_M32_H5, toHex } from "../../lms/src/index.ts";
import {
  emptySuccession,
  encodeVault,
  SUCCESSION_BLOCK_OFFSET,
  SUCCESSION_BLOCK_SIZE,
  type SuccessionState,
  usedKeyHash,
  VAULT_SUCCESSION_ACCOUNT_VERSION,
  vaultAccountSize,
} from "../src/accounts.ts";
import { IX } from "../src/discriminator.ts";
import { vaultMessage } from "../src/message.ts";
import { findVaultPda, vaultId } from "../src/pda.ts";
import { LAMPORT_VAULT_HEIR_PROGRAM_ID, LAMPORT_VAULT_HEIR_SHORT_CLOCKS_PROGRAM_ID } from "../src/programIds.ts";
import {
  checkinCountsUntil,
  encodeHeirAction,
  type HeirAction,
  SET_SUCCESSION_ACTION_SIZE,
  SET_SUCCESSION_VARIANT,
  SHORT_SUCCESSION_CLOCK,
  SUCCESSION_CLOCK,
  SUCCESSION_ERROR,
  successionActivity,
  successionDeadline,
  successionLimits,
  successionReleaseAt,
  successionStatus,
} from "../src/succession.ts";

const PK_11 = new PublicKey(new Uint8Array(32).fill(0x11));
const PK_44 = new PublicKey(new Uint8Array(32).fill(0x44));
const PK_55 = new PublicKey(new Uint8Array(32).fill(0x55));
const H5_PUBKEY = fromHex("000000050000000300112233445566778899aabbccddeeffcd079a17aad0d1f9554c1812f20a4d465dd0503acd83608f890a58d715e20253");
const H10_PUBKEY = fromHex("00000006000000034c616d706f727420526f626f7469637363aa0e1c3a5949b62fc83d2506d79688f5116d25fbd201c70a63bf3bec9a8521");
const ISSUED = 0x12340000n;
const EXPIRY = 0x12345678n;
const WINDOW = { issuedSlot: ISSUED, expirySlot: EXPIRY };
const GENERATION = 1;
const DAY = SUCCESSION_CLOCK.daySecs;
const T0 = 1_800_000_000n;

const plain = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v instanceof Uint8Array ? toHex(v) : v instanceof PublicKey ? v.toBase58() : v);
const json = (v: unknown) => JSON.parse(JSON.stringify(v, plain));

const armed = (over: Partial<SuccessionState> = {}): SuccessionState => ({
  ...emptySuccession(),
  claim: PK_11,
  windowSecs: 365n * DAY,
  waitSecs: 60n * DAY,
  lastSignedTs: T0,
  checkinKey: PK_44,
  contactKey: PK_55,
  ...over,
});

/** Clock states and the moment each is looked at. The Rust rules must say the same about every one. */
const clockCases: { name: string; state: SuccessionState; now: bigint }[] = [
  { name: "no plan", state: emptySuccession(), now: T0 },
  { name: "armed a moment ago", state: armed(), now: T0 },
  { name: "at the deadline, which is not past it", state: armed(), now: T0 + 365n * DAY },
  { name: "one second past the deadline", state: armed(), now: T0 + 365n * DAY + 1n },
  { name: "a check-in moved the window", state: armed({ lastCheckinTs: T0 + 300n * DAY }), now: T0 + 400n * DAY },
  { name: "a check-in exactly at the cap", state: armed({ lastCheckinTs: T0 + 730n * DAY }), now: T0 + 730n * DAY },
  { name: "a check-in field past the cap counts only to the cap", state: armed({ lastCheckinTs: T0 + 5000n * DAY }), now: T0 + 900n * DAY },
  { name: "a check-in older than the last signed action", state: armed({ lastCheckinTs: T0 - 50n * DAY }), now: T0 + 10n * DAY },
  { name: "the contact's extension is the later deadline", state: armed({ windowSecs: 90n * DAY, waitSecs: 30n * DAY, contactUsed: true, extendedUntilTs: T0 + 400n * DAY }), now: T0 + 399n * DAY },
  { name: "an extension that the window has outrun", state: armed({ contactUsed: true, extendedUntilTs: T0 + 100n * DAY }), now: T0 + 366n * DAY },
  { name: "waiting, not over", state: armed({ waitOpen: true, waitStartedTs: T0 + 370n * DAY }), now: T0 + 400n * DAY },
  { name: "waiting, over to the second", state: armed({ waitOpen: true, waitStartedTs: T0 + 370n * DAY }), now: T0 + 430n * DAY },
  { name: "waiting, one second short", state: armed({ waitOpen: true, waitStartedTs: T0 + 370n * DAY }), now: T0 + 430n * DAY - 1n },
  { name: "the shortest plan", state: armed({ windowSecs: 90n * DAY, waitSecs: 30n * DAY }), now: T0 + 90n * DAY + 1n },
  { name: "the longest plan", state: armed({ windowSecs: 36_500n * DAY, waitSecs: 36_500n * DAY }), now: T0 + 36_500n * DAY },
];

export function buildSuccessionKat(): unknown {
  const programId = LAMPORT_VAULT_HEIR_PROGRAM_ID;
  const id = vaultId(H5_PUBKEY);
  const vault = findVaultPda(programId, id);

  const actions: Record<string, HeirAction> = {
    set_succession: { kind: "SetSuccession", claim: PK_11, windowSecs: 365n * DAY, waitSecs: 60n * DAY, checkinKey: PK_44, contactKey: PK_55, ...WINDOW },
    set_succession_no_keys: { kind: "SetSuccession", claim: PK_11, windowSecs: 90n * DAY, waitSecs: 30n * DAY, checkinKey: PublicKey.default, contactKey: PublicKey.default, ...WINDOW },
    clear_succession: { kind: "SetSuccession", claim: PublicKey.default, windowSecs: 0n, waitSecs: 0n, checkinKey: PublicKey.default, contactKey: PublicKey.default, ...WINDOW },
    // the actions the vault already had encode the same; only the program id in their message differs
    transfer_sol: { kind: "TransferSol", to: PK_11, lamports: 1_500_000_000n, ...WINDOW },
    close: { kind: "Close", to: PK_11, ...WINDOW },
  };
  const actionVectors = Object.fromEntries(
    Object.entries(actions).map(([name, a]) => {
      const bytes = encodeHeirAction(a);
      return [name, { action: json(a), action_hex: toHex(bytes), message_hex: toHex(vaultMessage(vault.address, GENERATION, bytes, programId)) }];
    }),
  );

  const succession = armed({ lastCheckinTs: T0 + 12n * DAY, contactUsed: true, extendedUntilTs: T0 + 500n * DAY, waitOpen: true, waitStartedTs: T0 + 501n * DAY });
  const used = new Uint8Array(4);
  used[0] = 0b0000_0101;
  const vaultAccount = {
    version: VAULT_SUCCESSION_ACCOUNT_VERSION,
    bump: vault.bump,
    vaultId: id,
    lmsPubkey: H5_PUBKEY,
    spent: 2,
    generation: GENERATION,
    createdSlot: 0x11223344n,
    succession,
    used,
    usedKeys: [usedKeyHash(H10_PUBKEY)],
  };

  const limits = (clock: typeof SUCCESSION_CLOCK) => json({ day_secs: clock.daySecs, ...snake({ ...successionLimits(clock) }) });

  return {
    source: "@lamport-robotics/vault (this repository), scripts/succession-kat.ts",
    note: "The Heir-enabled program: programs/lamport-vault built with the `succession` feature. The program ids are placeholders with no private key until a deployment exists.",
    program_ids: { lamport_vault_heir: programId.toBase58(), lamport_vault_heir_short_clocks: LAMPORT_VAULT_HEIR_SHORT_CLOCKS_PROGRAM_ID.toBase58() },
    inputs: { pk_11: PK_11.toBase58(), pk_44: PK_44.toBase58(), pk_55: PK_55.toBase58(), h5_pubkey_hex: toHex(H5_PUBKEY), h10_pubkey_hex: toHex(H10_PUBKEY), issued_slot: ISSUED.toString(), expiry_slot: EXPIRY.toString(), generation: GENERATION, t0: T0.toString() },
    discriminators: { checkin: toHex(IX.checkin), contact_extend: toHex(IX.contactExtend), start_succession: toHex(IX.startSuccession), execute_succession: toHex(IX.executeSuccession) },
    limits: { clock: limits(SUCCESSION_CLOCK), short_clocks: limits(SHORT_SUCCESSION_CLOCK) },
    errors: SUCCESSION_ERROR,
    pdas: { vault_id_hex: toHex(id), vault: { address: vault.address.toBase58(), bump: vault.bump } },
    actions: { variant: SET_SUCCESSION_VARIANT, size: SET_SUCCESSION_ACTION_SIZE, vectors: actionVectors },
    accounts: {
      vault_version: VAULT_SUCCESSION_ACCOUNT_VERSION,
      block_offset: SUCCESSION_BLOCK_OFFSET,
      block_size: SUCCESSION_BLOCK_SIZE,
      vault_hex: toHex(encodeVault(vaultAccount)),
      vault: json({ ...vaultAccount, usedKeys: vaultAccount.usedKeys.map((k) => toHex(k)) }),
      sizes: {
        vault_h5: vaultAccountSize(LMS_SHA256_M32_H5, 0, VAULT_SUCCESSION_ACCOUNT_VERSION),
        vault_h10: vaultAccountSize(LMS_SHA256_M32_H10, 0, VAULT_SUCCESSION_ACCOUNT_VERSION),
        vault_h15: vaultAccountSize(LMS_SHA256_M32_H15, 0, VAULT_SUCCESSION_ACCOUNT_VERSION),
      },
    },
    clock: clockCases.map(({ name, state, now }) => {
      const status = successionStatus(state, now);
      return json({
        name,
        state: { ...state, reserved: undefined },
        now,
        activity: successionActivity(state),
        deadline: successionDeadline(state),
        release_at: successionReleaseAt(state) ?? null,
        checkin_counts_until: checkinCountsUntil(state),
        phase: status.phase,
        earliest_release: status.earliestRelease ?? null,
      });
    }),
  };
}

function snake(o: Record<string, bigint>): Record<string, bigint> {
  return Object.fromEntries(Object.entries(o).map(([k, v]) => [k.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`), v]));
}
