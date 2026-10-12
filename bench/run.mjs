// Runs the lms-cu benchmark program in LiteSVM and prints the compute units of one LMS
// verification (public key parse + lms_verify) per parameter set, 16 signatures each.
//
//   cd bench/gen && cargo run --release        # writes lms-cu/vectors.bin
//   cd ../lms-cu && cargo build-sbf            # builds target/deploy/lms_cu.so
//   cd .. && npm i --no-save litesvm@0.8.0 @solana/web3.js@1 && node run.mjs
//
// MODE=parse node run.mjs measures parsing only (public key + signature), without hashing.
import { readFileSync } from "node:fs";
import { LiteSVM, TransactionMetadata } from "litesvm";
import { ComputeBudgetProgram, Keypair, Transaction, TransactionInstruction } from "@solana/web3.js";

const here = (p) => new URL(p, import.meta.url);
const NAMES = { "6/3": "SHA-256     N32 W4 H10", "11/7": "SHA-256/192 N24 W4 H10", "11/8": "SHA-256/192 N24 W8 H10", "10/8": "SHA-256/192 N24 W8 H5" };

const blob = readFileSync(here(process.argv[2] ?? "./lms-cu/vectors.bin"));
const so = readFileSync(here(process.argv[3] ?? "./lms-cu/target/deploy/lms_cu.so"));
const svm = new LiteSVM();
const programId = Keypair.generate().publicKey;
svm.addProgram(programId, so);
const payer = Keypair.generate();
svm.airdrop(payer.publicKey, 10_000_000_000n);

const field = (b) => {
  const out = Buffer.alloc(2 + b.length);
  out.writeUInt16LE(b.length, 0);
  b.copy(out, 2);
  return out;
};

let o = 0;
const u16 = () => { const v = blob.readUInt16LE(o); o += 2; return v; };
// Reads a u16le length then that many bytes. (Not `subarray(o, o += u16())`: `o` would be read first.)
const bytes = () => { const n = u16(); const v = blob.subarray(o, o + n); o += n; return v; };
const cases = blob[o++];
for (let c = 0; c < cases; c++) {
  const key = `${blob[o++]}/${blob[o++]}`;
  const pk = bytes();
  const count = blob[o++];
  const units = [];
  let sigLen = 0;
  for (let i = 0; i < count; i++) {
    const msg = bytes();
    const sig = bytes();
    sigLen = sig.length;
    const acct = Keypair.generate().publicKey;
    const data = Buffer.concat([field(pk), field(msg), field(sig)]);
    svm.setAccount(acct, { lamports: 1_000_000_000, data, owner: programId, executable: false });
    const tx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      new TransactionInstruction({ programId, keys: [{ pubkey: acct, isSigner: false, isWritable: false }], data: Buffer.from(process.env.MODE === "parse" ? [1] : []) })
    );
    tx.recentBlockhash = svm.latestBlockhash();
    tx.feePayer = payer.publicKey;
    tx.sign(payer);
    const r = svm.sendTransaction(tx);
    if (!(r instanceof TransactionMetadata)) throw new Error(`${key} #${i}: ${r.err()}\n${r.meta().logs().join("\n")}`);
    units.push(Number(r.computeUnitsConsumed()) - 150); // minus the compute-budget instruction
    svm.expireBlockhash();
  }
  const avg = Math.round(units.reduce((a, b) => a + b, 0) / units.length);
  console.log(`${(NAMES[key] ?? key).padEnd(24)} sig ${String(sigLen).padStart(4)} B   CU min ${Math.min(...units)}  avg ${avg}  max ${Math.max(...units)}`);
}
