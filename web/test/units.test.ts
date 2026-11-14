/**
 * The number the cold signer shows for a token amount. It has to be exact, and it has to exist for
 * every request the signer can sign: a request it cannot describe is a request it must not sign.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { decimalUnits } from "../src/units.ts";

test("moves the point through the digits", () => {
  assert.equal(decimalUnits("1234500", 3), "1,234.5");
  assert.equal(decimalUnits("1", 0), "1");
  assert.equal(decimalUnits("0", 6), "0");
  assert.equal(decimalUnits("1", 6), "0.000001");
  assert.equal(decimalUnits("1000000", 6), "1");
  assert.equal(decimalUnits("1500000", 6), "1.5");
  assert.equal(decimalUnits("123456789", 0), "123,456,789");
  assert.equal(decimalUnits("000042", 1), "4.2");
});

test("is exact where floating point is not", () => {
  // 2^64 - 1 base units of a 9-decimal token: a double cannot hold it
  assert.equal(decimalUnits("18446744073709551615", 9), "18,446,744,073.709551615");
  assert.equal(decimalUnits("9007199254740993", 0), "9,007,199,254,740,993");
});

test("has an answer for every number of decimals a mint can have", () => {
  // toLocaleString throws above 100 fraction digits; a mint's decimals go to 255
  for (const d of [0, 1, 20, 21, 100, 101, 200, 255]) {
    const text = decimalUnits("1", d);
    assert.equal(text, d === 0 ? "1" : `0.${"0".repeat(d - 1)}1`, `decimals ${d}`);
  }
  assert.equal(decimalUnits("18446744073709551615", 255).length, 2 + 255);
});

test("refuses what is not an amount or not a number of decimals", () => {
  for (const raw of ["", "-1", "1.5", "1e9", " 1", "0x10", "１２"]) assert.throws(() => decimalUnits(raw, 6), RangeError, JSON.stringify(raw));
  for (const d of [-1, 256, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) assert.throws(() => decimalUnits("1", d), RangeError, String(d));
});
