/** spl tokens held by a vault, and the destination token account a transfer needs */
import { PublicKey, TransactionInstruction, SystemProgram } from "@solana/web3.js";
import { ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, associatedTokenAddress } from "@lamport-robotics/vault";
import { rpc } from "./rpc.ts";

export interface Holding { mint: PublicKey; amount: bigint; decimals: number; ui: string; tokenProgram: PublicKey; account: PublicKey }

export async function holdings(owner: PublicKey): Promise<Holding[]> {
  const out: Holding[] = [];
  for (const tokenProgram of [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID]) {
    // a failed read must surface: an empty list would read as "no tokens" and hide a balance
    const r = await rpc.getParsedTokenAccountsByOwner(owner, { programId: tokenProgram }, "confirmed");
    for (const a of r.value) {
      const info = (a.account.data as any).parsed?.info;
      if (!info) continue;
      const amount = BigInt(info.tokenAmount.amount);
      if (amount === 0n) continue;
      out.push({ mint: new PublicKey(info.mint), amount, decimals: info.tokenAmount.decimals, ui: info.tokenAmount.uiAmountString, tokenProgram, account: a.pubkey });
    }
  }
  return out;
}

/** the receiver's associated token account; `create` is the instruction to make it if it does not exist yet */
export async function destinationTokenAccount(payer: PublicKey, owner: PublicKey, mint: PublicKey, tokenProgram: PublicKey): Promise<{ address: PublicKey; create: TransactionInstruction | null }> {
  const address = associatedTokenAddress(owner, mint, tokenProgram);
  const info = await rpc.getAccountInfo(address, "confirmed");
  if (info) return { address, create: null };
  // associated token program: CreateIdempotent (discriminator 1)
  const create = new TransactionInstruction({
    programId: ASSOCIATED_TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: address, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: tokenProgram, isSigner: false, isWritable: false },
    ],
    data: Buffer.from([1]),
  });
  return { address, create };
}

export const toBase = (ui: string, decimals: number): bigint => {
  const [i, f = ""] = ui.trim().split(".");
  if (!/^\d*$/.test(i) || !/^\d*$/.test(f) || f.length > decimals) throw new Error("amount?");
  return BigInt(i || "0") * 10n ** BigInt(decimals) + BigInt((f + "0".repeat(decimals)).slice(0, decimals) || "0");
};
