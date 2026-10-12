/**
 * Recovering tokens from a closed vault. `Close` cannot enumerate the vault's token accounts, so
 * any it was not handed stays owned by the PDA; the program's permissionless `sweep_closed` moves
 * such a balance to the tombstone's heir (the `to` the Close was signed for) and nowhere else.
 * `sweepClosed` finds a closed vault's token accounts for one mint and sweeps each.
 */
import { type Commitment, type PublicKey, type Signer } from "@solana/web3.js";
import { decodeTombstone, isTombstone } from "./accounts.ts";
import { sweepClosedInstruction } from "./instructions.ts";
import { TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID } from "./pda.ts";
import { LAMPORT_VAULT_PROGRAM_ID } from "./programIds.ts";
import { type Rpc, sendAndConfirm, type SendOpts } from "./signer.ts";

/** What `sweepClosed` needs beyond {@link Rpc}: `Connection.getTokenAccountsByOwner`. */
export interface SweepRpc extends Rpc {
  getTokenAccountsByOwner(
    owner: PublicKey,
    filter: { mint: PublicKey },
    commitment?: Commitment,
  ): Promise<{ value: { pubkey: PublicKey }[] }>;
}

export interface SweepClosedOptions extends SendOpts {
  /** Default: the id declared by `programs/lamport-vault`. */
  programId?: PublicKey;
}

export interface SweptAccount {
  /** the vault's token account that was emptied and closed */
  account: PublicKey;
  signature: string;
}

export interface SweepClosedResult {
  /** the tombstone's heir: where the tokens and the accounts' rent went */
  heir: PublicKey;
  /** the heir's associated token account for `mint` (created by the first sweep if it was missing) */
  heirTokenAccount: PublicKey;
  /** one entry per token account swept, in the order they were found; empty when there was nothing to sweep */
  swept: SweptAccount[];
}

/**
 * Sweeps every token account of `mint` that the closed vault at `vault` still owns to the heir named
 * in its tombstone: one `sweep_closed` transaction per account, paid and signed by `payer` (any key;
 * it only pays the heir's associated token account rent when that account has to be created).
 * Refused before anything is sent when the address holds a live vault or nothing at all. The token
 * program is the one that owns `mint` (Token or Token-2022).
 */
export async function sweepClosed(rpc: SweepRpc, payer: Signer, vault: PublicKey, mint: PublicKey, opts: SweepClosedOptions = {}): Promise<SweepClosedResult> {
  const programId = opts.programId ?? LAMPORT_VAULT_PROGRAM_ID;
  const info = await rpc.getAccountInfo(vault, opts.commitment);
  if (!info) throw new Error(`no account at ${vault.toBase58()}: nothing to sweep`);
  if (!info.owner.equals(programId) || !isTombstone(new Uint8Array(info.data))) {
    throw new Error(`${vault.toBase58()} is not a closed vault (no Tombstone): sweep_closed only recovers tokens after Close`);
  }
  const { heir } = decodeTombstone(new Uint8Array(info.data));
  const mintInfo = await rpc.getAccountInfo(mint, opts.commitment);
  if (!mintInfo) throw new Error(`mint ${mint.toBase58()} does not exist`);
  const tokenProgram = [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID].find((p) => p.equals(mintInfo.owner));
  if (!tokenProgram) throw new Error(`mint ${mint.toBase58()} is owned by ${mintInfo.owner.toBase58()}, not Token or Token-2022`);
  const found = await rpc.getTokenAccountsByOwner(vault, { mint }, opts.commitment);
  const swept: SweptAccount[] = [];
  let heirTokenAccount: PublicKey | undefined;
  for (const [i, { pubkey }] of found.value.entries()) {
    const built = sweepClosedInstruction({ programId, payer: payer.publicKey, vault, heir, mint, vaultTokenAccount: pubkey, tokenProgram });
    heirTokenAccount = built.heirTokenAccount;
    const signature = await sendAndConfirm(rpc, [payer], [built.instruction], { commitment: opts.commitment });
    swept.push({ account: pubkey, signature });
    opts.onTransaction?.(i, found.value.length, signature);
  }
  heirTokenAccount ??= sweepClosedInstruction({ programId, payer: payer.publicKey, vault, heir, mint, vaultTokenAccount: vault, tokenProgram }).heirTokenAccount;
  return { heir, heirTokenAccount, swept };
}
