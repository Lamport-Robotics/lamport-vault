import { sha256 as noble } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { padSingleBlock, sha256Short, sha256SingleBlock, SINGLE_BLOCK_MAX } from "../src/sha256.ts";
import { toHex } from "../src/bytes.ts";

describe("single-block SHA-256", () => {
  it("matches @noble/hashes for every length 0..55, 50 random inputs each", () => {
    for (let len = 0; len <= SINGLE_BLOCK_MAX; len++) {
      for (let t = 0; t < 50; t++) {
        const msg = randomBytes(len);
        expect(toHex(sha256Short(msg))).toBe(toHex(noble(msg)));
      }
    }
  });

  it("matches the FIPS 180 'abc' vector", () => {
    expect(toHex(sha256Short(new TextEncoder().encode("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("writes the digest in place when out aliases the block", () => {
    const block = new Uint8Array(64);
    const msg = randomBytes(55);
    block.set(msg);
    padSingleBlock(block, 55);
    sha256SingleBlock(block, block, 23);
    expect(toHex(block.subarray(23, 55))).toBe(toHex(noble(msg)));
  });

  it("rejects messages longer than one block", () => {
    expect(() => padSingleBlock(new Uint8Array(64), 56)).toThrow();
  });
});
