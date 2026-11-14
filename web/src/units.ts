/**
 * A token amount in base units, written as a decimal number: the point is moved through the
 * digits, so the result is exact for any amount and any number of decimals a mint can have (0 to
 * 255). No floating point and no `Intl`: `toLocaleString` rounds past 2^53 and throws above 100
 * fraction digits, and the cold signer must be able to show every request it is able to sign.
 *
 *   decimalUnits("1234500", 3)  ->  "1,234.5"
 */
export function decimalUnits(raw: string, decimals: number): string {
  if (!/^\d{1,78}$/.test(raw)) throw new RangeError("an amount is a whole number of base units");
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) throw new RangeError("decimals must be a whole number from 0 to 255");
  const digits = raw.replace(/^0+(?=\d)/, "").padStart(decimals + 1, "0");
  const whole = digits.slice(0, digits.length - decimals).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const fraction = digits.slice(digits.length - decimals).replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole;
}
