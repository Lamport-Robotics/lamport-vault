/** Small byte helpers shared by the LMS code. All integers are big-endian (network order), as in RFC 8554. */

export function u8str(x: number): Uint8Array {
  if (!Number.isInteger(x) || x < 0 || x > 0xff) throw new RangeError(`u8str: ${x} out of range`);
  return Uint8Array.of(x);
}

export function u16str(x: number): Uint8Array {
  if (!Number.isInteger(x) || x < 0 || x > 0xffff) throw new RangeError(`u16str: ${x} out of range`);
  return Uint8Array.of(x >>> 8, x & 0xff);
}

export function u32str(x: number): Uint8Array {
  if (!Number.isInteger(x) || x < 0 || x > 0xffffffff) throw new RangeError(`u32str: ${x} out of range`);
  return Uint8Array.of((x >>> 24) & 0xff, (x >>> 16) & 0xff, (x >>> 8) & 0xff, x & 0xff);
}

export function strTou32(s: Uint8Array, offset = 0): number {
  if (s.length < offset + 4) throw new RangeError("strTou32: need 4 bytes");
  return ((s[offset]! << 24) | (s[offset + 1]! << 16) | (s[offset + 2]! << 8) | s[offset + 3]!) >>> 0;
}

export function writeU32(dst: Uint8Array, offset: number, x: number): void {
  dst[offset] = (x >>> 24) & 0xff;
  dst[offset + 1] = (x >>> 16) & 0xff;
  dst[offset + 2] = (x >>> 8) & 0xff;
  dst[offset + 3] = x & 0xff;
}

export function writeU16(dst: Uint8Array, offset: number, x: number): void {
  dst[offset] = (x >>> 8) & 0xff;
  dst[offset + 1] = x & 0xff;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

const HEX = "0123456789abcdef";

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    s += HEX[b >>> 4]! + HEX[b & 0x0f]!;
  }
  return s;
}

export function fromHex(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) throw new Error("fromHex: odd length");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const v = Number.parseInt(h.slice(2 * i, 2 * i + 2), 16);
    if (Number.isNaN(v)) throw new Error("fromHex: bad hex");
    out[i] = v;
  }
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
