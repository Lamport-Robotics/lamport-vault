/**
 * Borsh fields that only the Heir-enabled program's layouts use: signed 64-bit times and bools.
 *
 * They are functions here, and not methods of `ByteWriter` and `ByteReader`, on purpose. A bundler
 * keeps every method of a class it keeps, and the cold signer (`web/signer.html`, the one file
 * that ever sees the 24 words) bundles those classes. As functions that the cold signer never
 * calls, these are left out of it, so adding them does not change that file.
 */
import { ByteReader, ByteWriter } from "./borsh.ts";

/** Signed 64-bit, two's complement, little-endian (Borsh `i64`). */
export function writeI64(w: ByteWriter, x: bigint | number): ByteWriter {
  const v = typeof x === "number" ? BigInt(x) : x;
  if (v < -(1n << 63n) || v >= 1n << 63n) throw new RangeError(`i64 out of range: ${v}`);
  return w.u64(BigInt.asUintN(64, v));
}

/** Signed 64-bit, two's complement, little-endian (Borsh `i64`). */
export function readI64(r: ByteReader): bigint {
  return BigInt.asIntN(64, r.u64());
}

/** Borsh `bool`: one byte, 0 or 1. */
export function writeBool(w: ByteWriter, x: boolean): ByteWriter {
  return w.u8(x ? 1 : 0);
}

/** Borsh `bool`: one byte, 0 or 1; anything else is refused. */
export function readBool(r: ByteReader): boolean {
  const b = r.u8();
  if (b > 1) throw new Error(`decode: bool byte is ${b}`);
  return b === 1;
}
