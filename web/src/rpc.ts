// the online page's connection. kept out of common.ts so the cold signer's bundle never carries a
// Connection object: its no-network claim should not depend on dead code staying dead.
import { Connection } from "@solana/web3.js";
import { RPC_URL } from "./common.ts";

export const rpc = new Connection(RPC_URL, "confirmed");
