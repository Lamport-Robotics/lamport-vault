/**
 * A mock cluster for the signer tests: records every transaction, and applies `execute` to the
 * vault account (burns the leaf, performs a Rotate, leaves a tombstone on Close) so journal,
 * generation and tombstone logic can be exercised end to end without a validator. `failAt` makes
 * the n-th transaction fail at confirmation.
 */
import { Keypair, PublicKey, Transaction, type AccountInfo } from "@solana/web3.js";
import { decodeVault, encodeTombstone, encodeVault, TOMBSTONE_ACCOUNT_VERSION, usedKeyHash, type VaultAccount } from "../src/accounts.ts";
import { decodeAction } from "../src/action.ts";
import { IX } from "../src/discriminator.ts";
import { LAMPORT_VAULT_PROGRAM_ID } from "../src/programIds.ts";
import type { Rpc } from "../src/signer.ts";

export class MockChain implements Rpc {
  accounts = new Map<string, Uint8Array>();
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
    if (!data) return null;
    return { data: Buffer.from(data), executable: false, lamports: 1, owner: LAMPORT_VAULT_PROGRAM_ID };
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
          this.accounts.set(vaultKey.toBase58(), encodeTombstone({ version: TOMBSTONE_ACCOUNT_VERSION, vaultId: v.vaultId, closedSlot: BigInt(this.slot) }));
        } else {
          this.accounts.set(vaultKey.toBase58(), encodeVault(v));
        }
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


