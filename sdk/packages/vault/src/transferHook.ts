/**
 * The accounts of a Token-2022 transfer hook.
 *
 * A Token-2022 mint may name a hook program that the token program calls on every transfer. The
 * hook has a validation account at `["extra-account-metas", mint]` of its program, listing the
 * further accounts it wants; a transfer only goes through when the token program is handed the
 * hook program, the validation account and every account on that list. `execute`,
 * `execute_direct` and `sweep_closed` pass whatever follows their own accounts on to the token
 * program (`extraAccounts` in the builders), so a hook mint can leave a vault when a client
 * supplies them. {@link transferHookAccounts} works out what to supply.
 *
 * None of these accounts is covered by an LMS signature; whoever submits the transaction chooses
 * them. Two rules keep that from costing the submitter anything (docs/DESIGN.md, "Transfer hooks"):
 *
 * - No account is ever added as a signer, whatever the list asks for. The vault program passes
 *   none on as a signer either. A hook that cannot do without a signature fails the transfer on
 *   chain, and nothing moves.
 * - No key that signs the transaction (the fee payer above all) is added because a hook's list
 *   names it. A mint's owner can write any key into the list; a client that followed it blindly
 *   would put its own payer in front of a stranger's program. This throws instead, before a leaf
 *   is spent on a transaction that could not succeed without that account.
 *
 * This module is not used by the cold signer (`web/signer.html`), which builds no transactions.
 */
import { type AccountMeta, type Commitment, PublicKey } from "@solana/web3.js";
import { TOKEN_2022_PROGRAM_ID } from "./pda.ts";

/** What this needs of an RPC: `Connection` and the SDK's `Rpc` both have it. */
export interface TransferHookRpc {
  getAccountInfo(publicKey: PublicKey, commitment?: Commitment): Promise<{ data: Uint8Array; owner: PublicKey } | null>;
}

/** Discriminator of the hook interface's `Execute`: `sha256("spl-transfer-hook-interface:execute")[..8]`. */
const EXECUTE = Uint8Array.of(105, 37, 101, 197, 75, 251, 102, 26);
/** Token-2022's extension type of a mint's transfer hook. */
const TRANSFER_HOOK_EXTENSION = 14;
/** Base length of a token account; a mint with extensions is padded to it, then one account-type byte (1 = mint). */
const TOKEN_ACCOUNT_LEN = 165;
/** One entry of a hook's list: discriminator, 32 bytes of address configuration, is_signer, is_writable. */
const EXTRA_ACCOUNT_META_LEN = 35;

function u16le(data: Uint8Array, at: number): number {
  return data[at]! | (data[at + 1]! << 8);
}

function u32le(data: Uint8Array, at: number): number {
  return (data[at]! | (data[at + 1]! << 8) | (data[at + 2]! << 16) | (data[at + 3]! << 24)) >>> 0;
}

/**
 * The hook program a Token-2022 mint names, or `null`: a mint without the extension, one whose
 * extension names no program, and anything that is not a Token-2022 mint with extensions.
 *
 * Extensions this code has never heard of are stepped over by their length, so a later
 * Token-2022 extension in front of the hook does not hide it.
 */
export function transferHookProgramId(mintData: Uint8Array): PublicKey | null {
  if (mintData.length <= TOKEN_ACCOUNT_LEN + 1 || mintData[TOKEN_ACCOUNT_LEN] !== 1) return null;
  let at = TOKEN_ACCOUNT_LEN + 1;
  while (at + 4 <= mintData.length) {
    const type = u16le(mintData, at);
    const length = u16le(mintData, at + 2);
    if (type === 0) break; // uninitialised: nothing is written after it
    const value = at + 4;
    if (value + length > mintData.length) throw new Error("mint: an extension runs past the end of the account");
    if (type === TRANSFER_HOOK_EXTENSION) {
      if (length < 64) throw new Error(`mint: the transfer-hook extension is ${length} bytes, expected 64`);
      const program = mintData.subarray(value + 32, value + 64);
      return program.every((b) => b === 0) ? null : new PublicKey(program);
    }
    at = value + length;
  }
  return null;
}

/** The hook's validation account for `mint`: `["extra-account-metas", mint]` of the hook program. */
export function extraAccountMetasAddress(mint: PublicKey, hookProgram: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync([new TextEncoder().encode("extra-account-metas"), mint.toBytes()], hookProgram)[0];
}

/** One entry of a hook's list, as stored. */
export interface ExtraAccountMeta {
  /** 0: `addressConfig` is the address. 1: seeds of an address of the hook program. 2: where to read the address. 128 + i: seeds of an address of the program at account i. */
  discriminator: number;
  addressConfig: Uint8Array;
  isSigner: boolean;
  isWritable: boolean;
}

/**
 * The list a validation account holds for `Execute`. The account is a sequence of
 * type-length-value entries (8-byte type, u32 length); the entry of type `Execute` holds a u32
 * count and that many 35-byte entries.
 */
export function decodeExtraAccountMetas(data: Uint8Array): ExtraAccountMeta[] {
  let at = 0;
  while (at + 12 <= data.length) {
    const length = u32le(data, at + 8);
    const value = at + 12;
    if (value + length > data.length) break;
    if (EXECUTE.every((b, i) => data[at + i] === b)) {
      if (length < 4) throw new Error("validation account: the Execute entry is too short for a count");
      const count = u32le(data, value);
      if (4 + count * EXTRA_ACCOUNT_META_LEN > length) throw new Error(`validation account: ${count} entries do not fit in ${length} bytes`);
      const metas: ExtraAccountMeta[] = [];
      for (let i = 0; i < count; i++) {
        const o = value + 4 + i * EXTRA_ACCOUNT_META_LEN;
        metas.push({ discriminator: data[o]!, addressConfig: data.slice(o + 1, o + 33), isSigner: data[o + 33] !== 0, isWritable: data[o + 34] !== 0 });
      }
      return metas;
    }
    at = value + length;
  }
  throw new Error("validation account: no list for Execute");
}

/** A token transfer as the hook is told of it. */
export interface HookedTransfer {
  mint: PublicKey;
  /** The token account the tokens leave. */
  source: PublicKey;
  /** The token account they go to. */
  destination: PublicKey;
  /** The source's authority: the vault, or the tombstone of a closed one (the same address). */
  authority: PublicKey;
  /** Base units. A hook's list may derive addresses from it. */
  amount: bigint;
}

export interface TransferHookOptions {
  commitment?: Commitment | undefined;
  /**
   * Every key that signs the transaction, the fee payer first of all. If the hook's list names
   * one of them, {@link transferHookAccounts} throws instead of adding it.
   */
  signers?: PublicKey[];
}

/**
 * Resolves one hook's accounts for one transfer: what to pass as `extraAccounts`. The accounts the
 * list names come first, in its order, then the validation account, then the hook program. All
 * are unsigned, whether or not the list asks for a signer; an account is writable only if the
 * list asks for that and it is not one of the transfer's own accounts, which a hook always gets
 * read-only. Throws if the list names one of `opts.signers`.
 *
 * The token program repeats this resolution on chain, from the same list, and takes the accounts
 * by address; a wrong or missing one fails the transfer and moves nothing.
 *
 * A hook with no validation account gets the hook program alone.
 */
export async function resolveTransferHookAccounts(rpc: TransferHookRpc, hookProgram: PublicKey, transfer: HookedTransfer, opts: TransferHookOptions = {}): Promise<AccountMeta[]> {
  if (transfer.amount < 0n || transfer.amount >= 1n << 64n) throw new RangeError(`amount out of range: ${transfer.amount}`);
  const program: AccountMeta = { pubkey: hookProgram, isSigner: false, isWritable: false };
  const validation = extraAccountMetasAddress(transfer.mint, hookProgram);
  const validationInfo = await rpc.getAccountInfo(validation, opts.commitment);
  if (!validationInfo) return [program];
  const list = decodeExtraAccountMetas(validationInfo.data);

  // `Execute` as the token program will build it: the data, and the accounts the list's entries index into
  const data = new Uint8Array(16);
  data.set(EXECUTE);
  new DataView(data.buffer).setBigUint64(8, transfer.amount, true);
  const accounts: AccountMeta[] = [transfer.source, transfer.mint, transfer.destination, transfer.authority, validation].map((pubkey) => ({ pubkey, isSigner: false, isWritable: false }));
  const fetched = new Map<string, Uint8Array | null>([[validation.toBase58(), validationInfo.data]]);
  const dataOf = async (index: number, what: string): Promise<Uint8Array> => {
    const key = accountAt(accounts, index, what).pubkey;
    const id = key.toBase58();
    if (!fetched.has(id)) fetched.set(id, (await rpc.getAccountInfo(key, opts.commitment))?.data ?? null);
    const found = fetched.get(id);
    if (!found) throw new Error(`transfer hook of mint ${transfer.mint.toBase58()}: ${what} reads account ${id}, which does not exist yet`);
    return found;
  };

  const extra: AccountMeta[] = [];
  for (const [i, entry] of list.entries()) {
    const what = `entry ${i} of the hook's list`;
    const pubkey = await resolveAddress(entry, hookProgram, accounts, data, dataOf, what);
    // An account the instruction already holds is handed to the hook with the privileges it has
    // there, never more (the token program's own rule); the five it starts with are read-only.
    const earlier = accounts.filter((a) => a.pubkey.equals(pubkey));
    if (opts.signers?.some((s) => s.equals(pubkey))) {
      throw new Error(
        `transfer hook of mint ${transfer.mint.toBase58()}: ${what} names ${pubkey.toBase58()}, which signs this transaction. ` +
          "Refusing to put a signer of the transaction in front of a hook program; pay for the transaction with another key",
      );
    }
    const meta: AccountMeta = { pubkey, isSigner: false, isWritable: entry.isWritable && (earlier.length === 0 || earlier.some((a) => a.isWritable)) };
    accounts.push(meta);
    extra.push(meta);
  }
  return [...extra, { pubkey: validation, isSigner: false, isWritable: false }, program];
}

/**
 * The accounts to pass as `extraAccounts` for a transfer of `transfer.mint` out of a vault: empty
 * for a mint that is not Token-2022's or has no hook, otherwise {@link resolveTransferHookAccounts}.
 */
export async function transferHookAccounts(rpc: TransferHookRpc, transfer: HookedTransfer, opts: TransferHookOptions = {}): Promise<AccountMeta[]> {
  const mint = await rpc.getAccountInfo(transfer.mint, opts.commitment);
  if (!mint || !mint.owner.equals(TOKEN_2022_PROGRAM_ID)) return [];
  const hookProgram = transferHookProgramId(mint.data);
  return hookProgram ? resolveTransferHookAccounts(rpc, hookProgram, transfer, opts) : [];
}

function accountAt(accounts: AccountMeta[], index: number, what: string): AccountMeta {
  const account = accounts[index];
  if (!account) throw new Error(`transfer hook: ${what} refers to account ${index}, and only ${accounts.length} come before it`);
  return account;
}

function slice(bytes: Uint8Array, start: number, length: number, what: string): Uint8Array {
  if (start + length > bytes.length) throw new Error(`transfer hook: ${what} reads ${length} bytes at ${start} of ${bytes.length}`);
  return bytes.subarray(start, start + length);
}

type DataOf = (index: number, what: string) => Promise<Uint8Array>;

/** The address one entry stands for (spl-tlv-account-resolution, `ExtraAccountMeta::resolve`). */
async function resolveAddress(entry: ExtraAccountMeta, hookProgram: PublicKey, accounts: AccountMeta[], data: Uint8Array, dataOf: DataOf, what: string): Promise<PublicKey> {
  const config = entry.addressConfig;
  if (entry.discriminator === 0) return new PublicKey(config);
  if (entry.discriminator === 2) {
    // the address is 32 bytes of the instruction data, or of an earlier account's data
    if (config[0] === 1) return new PublicKey(slice(data, config[1]!, 32, what));
    if (config[0] === 2) return new PublicKey(slice(await dataOf(config[1]!, what), config[2]!, 32, what));
    throw new Error(`transfer hook: ${what} has an unknown address source ${config[0]}`);
  }
  if (entry.discriminator !== 1 && entry.discriminator < 128) throw new Error(`transfer hook: ${what} has an unknown kind ${entry.discriminator}`);
  // a program-derived address: of the hook program, or of the program at an earlier account
  const owner = entry.discriminator === 1 ? hookProgram : accountAt(accounts, entry.discriminator - 128, what).pubkey;
  const seeds: Uint8Array[] = [];
  for (let at = 0; at < config.length; ) {
    const kind = config[at]!;
    if (kind === 0) break;
    if (kind === 1) {
      const length = config[at + 1] ?? 0;
      seeds.push(slice(config, at + 2, length, what));
      at += 2 + length;
    } else if (kind === 2) {
      seeds.push(slice(data, config[at + 1] ?? 0, config[at + 2] ?? 0, what));
      at += 3;
    } else if (kind === 3) {
      seeds.push(accountAt(accounts, config[at + 1] ?? 0, what).pubkey.toBytes());
      at += 2;
    } else if (kind === 4) {
      seeds.push(slice(await dataOf(config[at + 1] ?? 0, what), config[at + 2] ?? 0, config[at + 3] ?? 0, what));
      at += 4;
    } else {
      throw new Error(`transfer hook: ${what} has an unknown seed kind ${kind}`);
    }
  }
  return PublicKey.findProgramAddressSync(seeds, owner)[0];
}
