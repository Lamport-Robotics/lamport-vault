/** the classical wallet: pays rent and fees, funds deposits. never touches the vault key. */
import { Keypair, PublicKey, Transaction, VersionedTransaction, type TransactionInstruction } from "@solana/web3.js";
import { getWallets } from "@wallet-standard/app";
import type { Wallet as StdWallet, WalletAccount } from "@wallet-standard/base";
import { CLUSTER } from "./common.ts";
import { rpc } from "./rpc.ts";
import { registerMwa, createDefaultAuthorizationCache, createDefaultChainSelector, createDefaultWalletNotFoundHandler } from "@solana-mobile/wallet-standard-mobile";

// Android: wallets that speak Mobile Wallet Adapter (Phantom, Solflare, Backpack, …) show up as one
// Wallet Standard entry and open the wallet app for approval. No-op where MWA is not available.
try {
  registerMwa({
    appIdentity: { name: "Lamport Vault", uri: location.origin, icon: "apple-touch-icon.png" },
    chains: [`solana:${CLUSTER}`],
    authorizationCache: createDefaultAuthorizationCache(),
    chainSelector: createDefaultChainSelector(),
    onWalletNotFound: createDefaultWalletNotFoundHandler(),
  });
} catch { /* not on a platform with MWA */ }
import { assembleV1Transaction, keypairV1Signer, v1TransactionSignature } from "@lamport-robotics/vault";

export interface Wallet {
  name: string;
  pubkey: PublicKey;
  send(ixs: TransactionInstruction[]): Promise<string>;
  /** transaction v1 (0x81, up to 4096 bytes): present when the wallet can sign it */
  sendV1?: (t: { messageBytes: Uint8Array; unsignedTransaction: Uint8Array; blockhash: string; lastValidBlockHeight: number }) => Promise<string>;
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

/**
 * waits for a transaction. when we hold the signed bytes we re-send them every two seconds until the
 * chain has them: devnet rpcs drop transactions, and a wallet on a phone can take a while to come back.
 * on expiry the status is checked one last time before giving up, with a message that says what to do.
 */
async function confirm(sig: string, blockhash: string, lastValidBlockHeight: number, wire?: Uint8Array) {
  let stop = false;
  const rebroadcast = wire ? (async () => { while (!stop) { await new Promise((r) => setTimeout(r, 2000)); if (stop) break; try { await rpc.sendRawTransaction(wire, { skipPreflight: true, maxRetries: 0 }); } catch { /* already known or expired */ } } })() : Promise.resolve();
  try {
    const r = await rpc.confirmTransaction({ signature: sig, blockhash, lastValidBlockHeight }, "confirmed");
    if (r.value.err) throw new Error(`transaction failed: ${JSON.stringify(r.value.err)}`);
    return sig;
  } catch (e) {
    if (!/expired|block height/i.test(String((e as Error).message))) throw e;
    const st = await rpc.getSignatureStatuses([sig]).catch(() => null);
    const v = st?.value?.[0];
    if (v && !v.err) return sig;
    if (v?.err) throw new Error(`transaction failed: ${JSON.stringify(v.err)}`);
    throw new Error("the network did not pick up the transaction before its blockhash expired (about a minute). The transfer did not happen and no fee was paid. A signed action keeps its one-time key: this page will not offer that key again, the next attempt takes the next one. Approve the wallet prompt promptly when you retry");
  } finally { stop = true; await rebroadcast.catch(() => undefined); }
}

export async function connectStandard(w: StdWallet, silent = false): Promise<Wallet> {
  const feat = w.features as Record<string, any>;
  const res = await feat["standard:connect"].connect(silent ? { silent: true } : undefined);
  if (!res.accounts?.length) throw new Error("not connected");
  const account: WalletAccount | undefined = (res.accounts as WalletAccount[]).find((a) => (a.chains as readonly string[]).includes(CHAIN)) ?? res.accounts[0];
  if (!account) throw new Error("wallet returned no account");
  const pubkey = new PublicKey(account.publicKey);
  const sas = feat["solana:signAndSendTransaction"], st = feat["solana:signTransaction"];
  const supports1 = (f: any) => { const v = f?.supportedTransactionVersions; return !!v && (Array.isArray(v) ? v.includes(1) : typeof v.has === "function" ? v.has(1) : false); };
  const sendV1 = supports1(sas) || supports1(st) ? async (t: { messageBytes: Uint8Array; unsignedTransaction: Uint8Array; blockhash: string; lastValidBlockHeight: number }) => {
    if (supports1(st)) {
      const [out] = await st.signTransaction({ transaction: t.unsignedTransaction, account, chain: CHAIN });
      const sig = await rpc.sendRawTransaction(out.signedTransaction, { preflightCommitment: "confirmed" });
      return confirm(sig, t.blockhash, t.lastValidBlockHeight, out.signedTransaction);
    }
    const [out] = await sas.signAndSendTransaction({ transaction: t.unsignedTransaction, account, chain: CHAIN, options: { preflightCommitment: "confirmed" } });
    return confirm(bs58(out.signature), t.blockhash, t.lastValidBlockHeight);
  } : undefined;
  return {
    name: w.name,
    pubkey,
    sendV1,
    async send(ixs) {
      const { tx, blockhash, lastValidBlockHeight } = await buildTx(ixs, pubkey);
      const bytes = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
      if (feat["solana:signTransaction"]) {
        const [out] = await feat["solana:signTransaction"].signTransaction({ transaction: bytes, account, chain: CHAIN });
        const wire = VersionedTransaction.deserialize(out.signedTransaction).serialize();
        const sig = await rpc.sendRawTransaction(wire, { preflightCommitment: "confirmed" });
        return confirm(sig, blockhash, lastValidBlockHeight, wire);
      }
      const [out] = await feat["solana:signAndSendTransaction"].signAndSendTransaction({ transaction: bytes, account, chain: CHAIN, options: { preflightCommitment: "confirmed" } });
      return confirm(bs58(out.signature), blockhash, lastValidBlockHeight);
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
  const signV1 = keypairV1Signer(kp.secretKey);
  return {
    name: "local test key",
    pubkey: kp.publicKey,
    async sendV1(t) {
      const wire = assembleV1Transaction(t.messageBytes, [await signV1(t.messageBytes)]);
      const sig = await rpc.sendRawTransaction(wire, { preflightCommitment: "confirmed" });
      void v1TransactionSignature;
      return confirm(sig, t.blockhash, t.lastValidBlockHeight, wire);
    },
    async send(ixs) {
      const { tx, blockhash, lastValidBlockHeight } = await buildTx(ixs, kp.publicKey);
      tx.sign(kp);
      const wire = tx.serialize();
      const sig = await rpc.sendRawTransaction(wire, { preflightCommitment: "confirmed" });
      return confirm(sig, blockhash, lastValidBlockHeight, wire);
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
