/**
 * Minimal Borsh encoding, enough for the layouts in docs/DESIGN.md. Integers are little-endian;
 * `Vec<u8>` is a u32 length prefix followed by the bytes; fixed arrays and Pubkeys are raw.
 */
import { PublicKey } from "@solana/web3.js";

export class ByteWriter {
  private chunks: Uint8Array[] = [];
  private length = 0;

  u8(x: number): this {
    if (!Number.isInteger(x) || x < 0 || x > 0xff) throw new RangeError(`u8 out of range: ${x}`);
    return this.raw(Uint8Array.of(x));
  }

  u16(x: number): this {
    if (!Number.isInteger(x) || x < 0 || x > 0xffff) throw new RangeError(`u16 out of range: ${x}`);
    return this.raw(Uint8Array.of(x & 0xff, x >>> 8));
  }

  u32(x: number): this {
    if (!Number.isInteger(x) || x < 0 || x > 0xffffffff) throw new RangeError(`u32 out of range: ${x}`);
    return this.raw(Uint8Array.of(x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, (x >>> 24) & 0xff));
  }

  u64(x: bigint | number): this {
    const v = typeof x === "number" ? BigInt(x) : x;
    if (v < 0n || v > 0xffffffffffffffffn) throw new RangeError(`u64 out of range: ${v}`);
    const out = new Uint8Array(8);
    let t = v;
    for (let i = 0; i < 8; i++) {
      out[i] = Number(t & 0xffn);
      t >>= 8n;
    }
    return this.raw(out);
  }

  pubkey(pk: PublicKey): this {
    return this.raw(pk.toBytes());
  }

  fixed(bytes: Uint8Array, len: number): this {
    if (bytes.length !== len) throw new RangeError(`expected ${len} bytes, got ${bytes.length}`);
    return this.raw(bytes);
  }

  vecU8(bytes: Uint8Array): this {
    this.u32(bytes.length);
    return this.raw(bytes);
  }

  raw(bytes: Uint8Array): this {
    this.chunks.push(bytes);
    this.length += bytes.length;
    return this;
  }

  bytes(): Uint8Array {
    const out = new Uint8Array(this.length);
    let o = 0;
    for (const c of this.chunks) {
      out.set(c, o);
      o += c.length;
    }
    return out;
  }
}

export class ByteReader {
  offset = 0;
  readonly data: Uint8Array;
  constructor(data: Uint8Array) {
    this.data = data;
  }

  get remaining(): number {
    return this.data.length - this.offset;
  }

  private need(n: number): void {
    if (this.remaining < n) throw new Error(`decode: need ${n} bytes at offset ${this.offset}, have ${this.remaining}`);
  }

  u8(): number {
    this.need(1);
    return this.data[this.offset++]!;
  }

  u16(): number {
    this.need(2);
    const v = this.data[this.offset]! | (this.data[this.offset + 1]! << 8);
    this.offset += 2;
    return v;
  }

  u32(): number {
    this.need(4);
    const d = this.data;
    const o = this.offset;
    const v = (d[o]! | (d[o + 1]! << 8) | (d[o + 2]! << 16) | (d[o + 3]! << 24)) >>> 0;
    this.offset += 4;
    return v;
  }

  u64(): bigint {
    this.need(8);
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(this.data[this.offset + i]!);
    this.offset += 8;
    return v;
  }

  pubkey(): PublicKey {
    return new PublicKey(this.fixed(32));
  }

  fixed(len: number): Uint8Array {
    this.need(len);
    const out = this.data.slice(this.offset, this.offset + len);
    this.offset += len;
    return out;
  }

  vecU8(): Uint8Array {
    const len = this.u32();
    return this.fixed(len);
  }

  finish(): void {
    if (this.remaining !== 0) throw new Error(`decode: ${this.remaining} trailing bytes`);
  }
}

export function u64le(x: bigint | number): Uint8Array {
  return new ByteWriter().u64(x).bytes();
}
