// web3.js and the sdk use Buffer; browsers don't have it
import { Buffer } from "buffer";
(globalThis as any).Buffer ??= Buffer;
