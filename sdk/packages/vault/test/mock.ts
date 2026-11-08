/**
 * A mock cluster for the signer tests: records every transaction, and applies `execute` to the
 * vault account (burns the leaf, performs a Rotate, leaves a tombstone on Close) so journal,
 * generation and tombstone logic can be exercised end to end without a validator. `failAt` makes
 * the n-th transaction fail at confirmation. Token accounts and mints are a flat table (`mints`,
 * `tokenAccounts`) so `sweep_closed` can be applied too: it checks what the program checks (a
 * tombstone, its heir, the heir's ATA, a vault-owned account of the mint) and moves the balance.
 */
import { Keypair, PublicKey, Transaction, type AccountInfo } from "@solana/web3.js";
import { decodeTombstone, decodeVault, encodeTombstone, encodeVault, isTombstone, TOMBSTONE_ACCOUNT_VERSION, usedKeyHash, type VaultAccount } from "../src/accounts.ts";
import { decodeAction } from "../src/action.ts";
import { IX } from "../src/discriminator.ts";
import { associatedTokenAddress } from "../src/pda.ts";
import { LAMPORT_VAULT_PROGRAM_ID } from "../src/programIds.ts";
import type { Rpc } from "../src/signer.ts";
import type { SweepRpc } from "../src/sweep.ts";

export interface MockTokenAccount {
  owner: PublicKey;
  mint: PublicKey;
  amount: bigint;
}

export class MockChain implements Rpc, SweepRpc {
  accounts = new Map<string, Uint8Array>();
  /** mint address -> the token program that owns it */
  mints = new Map<string, PublicKey>();
  /** token account address -> owner, mint, balance (the program is the mint's) */
  tokenAccounts = new Map<string, MockTokenAccount>();
  sent: Transaction[] = [];
  slot = 1000;
  failAt: number | null = null;
  /** The action of every staged execution is remembered at open_sig_buffer and applied at execute. */
  private pendingActions = new Map<string, { q: number; actionBytes: Uint8Array }>();

  vault(vault: PublicKey): VaultAccount {
    return decodeVault(this.accounts.get(vault.toBase58())!);
  }

  async getAccountInfo(pk: PublicKey): Promise<AccountInfo<Buffer> | null> {
    const data = this.accounts.get(pk.toBase58());
    if (data) return { data: Buffer.from(data), executable: false, lamports: 1, owner: LAMPORT_VAULT_PROGRAM_ID };
    const mintProgram = this.mints.get(pk.toBase58());
    if (mintProgram) return { data: Buffer.alloc(82), executable: false, lamports: 1, owner: mintProgram };
    const token = this.tokenAccounts.get(pk.toBase58());
    if (token) return { data: Buffer.alloc(165), executable: false, lamports: 1, owner: this.mints.get(token.mint.toBase58())! };
    return null;
  }
  async getTokenAccountsByOwner(owner: PublicKey, filter: { mint: PublicKey }): Promise<{ value: { pubkey: PublicKey }[] }> {
    const value: { pubkey: PublicKey }[] = [];
    for (const [address, t] of this.tokenAccounts) {
      if (t.owner.equals(owner) && t.mint.equals(filter.mint)) value.push({ pubkey: new PublicKey(address) });
    }
    return { value };
  }
  async getLatestBlockhash() {
    return { blockhash: Keypair.generate().publicKey.toBase58(), lastValidBlockHeight: 10 };
  }
  async sendRawTransaction(raw: Buffer | Uint8Array | number[]): Promise<string> {
    const tx = Transaction.from(Buffer.from(raw as Uint8Array));
    if (!tx.verifySignatures()) throw new Error("bad signature");
    this.sent.push(tx);
    for (const ix of tx.instructions) {
      const disc = Buffer.from(ix.data.subarray(0, 8)).toString("hex");
      if (disc === Buffer.from(IX.openSigBuffer).toString("hex")) {
        const actionLen = ix.data.readUInt32LE(16);
        const actionBytes = new Uint8Array(ix.data.subarray(20, 20 + actionLen));
        const firstChunkLen = ix.data.readUInt32LE(20 + actionLen + 2);
        const firstChunk = ix.data.subarray(20 + actionLen + 6, 20 + actionLen + 6 + firstChunkLen);
        // the LMS signature starts with u32be(q); with no first chunk it arrives in the write at offset 0
        const q = firstChunkLen >= 4 ? firstChunk.readUInt32BE(0) : -1;
        this.pendingActions.set(ix.keys[2]!.pubkey.toBase58(), { q, actionBytes });
      } else if (disc === Buffer.from(IX.writeSig).toString("hex")) {
        const pending = this.pendingActions.get(ix.keys[1]!.pubkey.toBase58())!;
        if (ix.data.readUInt16LE(8) === 0) pending.q = ix.data.readUInt32BE(14);
      } else if (disc === Buffer.from(IX.execute).toString("hex")) {
        const vaultKey = ix.keys[0]!.pubkey;
        const pending = this.pendingActions.get(ix.keys[1]!.pubkey.toBase58())!;
        if (pending.q < 0) throw new Error("mock: execute before the signature's first bytes were written");
        const v = this.vault(vaultKey);
        v.used[pending.q >> 3]! |= 1 << (pending.q & 7);
        v.spent += 1;
        const action = decodeAction(pending.actionBytes);
        if (action.kind === "Rotate") {
          v.usedKeys.push(usedKeyHash(v.lmsPubkey));
          v.lmsPubkey = action.newLmsPubkey;
          v.used.fill(0);
          v.spent = 0;
          v.generation += 1;
        }
        if (action.kind === "Close") {
          this.accounts.set(vaultKey.toBase58(), encodeTombstone({ version: TOMBSTONE_ACCOUNT_VERSION, vaultId: v.vaultId, closedSlot: BigInt(this.slot), heir: action.to }));
        } else {
          this.accounts.set(vaultKey.toBase58(), encodeVault(v));
        }
      } else if (disc === Buffer.from(IX.sweepClosed).toString("hex")) {
        const [, tombstoneKey, heir, heirAta, vaultTa, mint, tokenProgram] = ix.keys.map((k) => k.pubkey) as PublicKey[];
        const data = this.accounts.get(tombstoneKey!.toBase58());
        if (!data || !isTombstone(data)) throw new Error("mock: VaultNotClosed");
        const tomb = decodeTombstone(data);
        if (!tomb.heir.equals(heir!)) throw new Error("mock: WrongHeir");
        const program = this.mints.get(mint!.toBase58());
        if (!program || !program.equals(tokenProgram!)) throw new Error("mock: InvalidTokenProgram");
        if (!heirAta!.equals(associatedTokenAddress(heir!, mint!, program))) throw new Error("mock: NotHeirTokenAccount");
        const from = this.tokenAccounts.get(vaultTa!.toBase58());
        if (!from || !from.owner.equals(tombstoneKey!)) throw new Error("mock: NotVaultTokenAccount");
        if (!from.mint.equals(mint!)) throw new Error("mock: WrongMint");
        const to = this.tokenAccounts.get(heirAta!.toBase58()) ?? { owner: heir!, mint: mint!, amount: 0n };
        to.amount += from.amount;
        this.tokenAccounts.set(heirAta!.toBase58(), to);
        this.tokenAccounts.delete(vaultTa!.toBase58());
      }
    }
    return "sig" + this.sent.length;
  }
  async confirmTransaction(strategy: { signature: string }) {
    const idx = Number(strategy.signature.slice(3)) - 1;
    return { value: { err: this.failAt === idx ? { InstructionError: [0, "Custom"] } : null } };
  }
  async getSlot(): Promise<number> {
    return this.slot;
  }

  /** Marks leaves spent on chain without a transaction: what another device would do. */
  spend(vault: PublicKey, leaves: number[]): void {
    const v = this.vault(vault);
    for (const q of leaves) {
      v.used[q >> 3]! |= 1 << (q & 7);
      v.spent += 1;
    }
    this.accounts.set(vault.toBase58(), encodeVault(v));
  }
}


