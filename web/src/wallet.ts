/** the classical wallet: pays rent and fees, funds deposits. never touches the vault key. */
import { Keypair, PublicKey, Transaction, VersionedTransaction, type TransactionInstruction } from "@solana/web3.js";
import { getWallets } from "@wallet-standard/app";
import type { Wallet as StdWallet, WalletAccount } from "@wallet-standard/base";
import { CLUSTER, rpc } from "./common.ts";

export interface Wallet {
  name: string;
  pubkey: PublicKey;
  send(ixs: TransactionInstruction[]): Promise<string>;
  disconnect(): Promise<void>;
}

const CHAIN = `solana:${CLUSTER}` as const;

export function listWallets(): StdWallet[] {
  return getWallets().get().filter((w) => (w.chains as readonly string[]).includes(CHAIN) && ("solana:signAndSendTransaction" in w.features || "solana:signTransaction" in w.features));
}

export function onWalletsChange(cb: () => void) {
  const { on } = getWallets();
  on("register", cb); on("unregister", cb);
}

async function buildTx(ixs: TransactionInstruction[], payer: PublicKey) {
  const { blockhash, lastValidBlockHeight } = await rpc.getLatestBlockhash("confirmed");
  const tx = new Transaction({ feePayer: payer, blockhash, lastValidBlockHeight }).add(...ixs);
  return { tx, blockhash, lastValidBlockHeight };
}

async function confirm(sig: string, blockhash: string, lastValidBlockHeight: number) {
  const r = await rpc.confirmTransaction({ signature: sig, blockhash, lastValidBlockHeight }, "confirmed");
  if (r.value.err) throw new Error(`transaction failed: ${JSON.stringify(r.value.err)}`);
  return sig;
}

export async function connectStandard(w: StdWallet, silent = false): Promise<Wallet> {
  const feat = w.features as Record<string, any>;
  const res = await feat["standard:connect"].connect(silent ? { silent: true } : undefined);
  if (!res.accounts?.length) throw new Error("not connected");
  const account: WalletAccount | undefined = (res.accounts as WalletAccount[]).find((a) => (a.chains as readonly string[]).includes(CHAIN)) ?? res.accounts[0];
  if (!account) throw new Error("wallet returned no account");
  const pubkey = new PublicKey(account.publicKey);
  return {
    name: w.name,
    pubkey,
    async send(ixs) {
      const { tx, blockhash, lastValidBlockHeight } = await buildTx(ixs, pubkey);
      const bytes = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
      if (feat["solana:signAndSendTransaction"]) {
        const [out] = await feat["solana:signAndSendTransaction"].signAndSendTransaction({ transaction: bytes, account, chain: CHAIN, options: { preflightCommitment: "confirmed" } });
        const sig = bs58(out.signature);
        return confirm(sig, blockhash, lastValidBlockHeight);
      }
      const [out] = await feat["solana:signTransaction"].signTransaction({ transaction: bytes, account, chain: CHAIN });
      const signed = VersionedTransaction.deserialize(out.signedTransaction);
      const sig = await rpc.sendRawTransaction(signed.serialize(), { preflightCommitment: "confirmed" });
      return confirm(sig, blockhash, lastValidBlockHeight);
    },
    async disconnect() { try { await feat["standard:disconnect"]?.disconnect(); } catch { /* fine */ } },
  };
}

/** local test wallet, only offered on localhost: a keypair kept in sessionStorage, fund it from the cli */
export function localWallet(): Wallet {
  const k = "lamport-vault-local-payer";
  let kp: Keypair;
  const saved = sessionStorage.getItem(k);
  if (saved) kp = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(saved)));
  else { kp = Keypair.generate(); sessionStorage.setItem(k, JSON.stringify(Array.from(kp.secretKey))); }
  return {
    name: "local test key",
    pubkey: kp.publicKey,
    async send(ixs) {
      const { tx, blockhash, lastValidBlockHeight } = await buildTx(ixs, kp.publicKey);
      tx.sign(kp);
      const sig = await rpc.sendRawTransaction(tx.serialize(), { preflightCommitment: "confirmed" });
      return confirm(sig, blockhash, lastValidBlockHeight);
    },
    async disconnect() { sessionStorage.removeItem(k); },
  };
}

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function bs58(bytes: Uint8Array): string {
  let n = 0n; for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = ""; while (n > 0n) { out = ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b === 0) out = "1" + out; else break; }
  return out;
}

const REMEMBER = "lamport-vault-wallet";
export function remember(name: string | null) { try { if (name) localStorage.setItem(REMEMBER, name); else localStorage.removeItem(REMEMBER); } catch { /* private mode */ } }
export function remembered(): string | null { try { return localStorage.getItem(REMEMBER); } catch { return null; } }
