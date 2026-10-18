/** the key meter: the vault's one-time keys as 64 segments. a segment fills as its leaves are spent. */
export function tape(leafCount: number, used: Uint8Array, spent: number, nextFree: number | undefined): HTMLElement {
  const cells = 64, per = leafCount / cells;
  const isUsed = (q: number) => (used[q >> 3] >> (q & 7) & 1) === 1;
  const box = document.createElement("div");
  box.className = "meter";
  const bar = document.createElement("div"); bar.className = "bar";
  for (let i = 0; i < cells; i++) {
    const from = i * per, to = from + per;
    let n = 0; for (let q = from; q < to; q++) if (isUsed(q)) n++;
    const seg = document.createElement("i");
    if (n === per) seg.className = "used";
    else if (n > 0 || (nextFree !== undefined && nextFree >= from && nextFree < to)) seg.className = "next";
    bar.append(seg);
  }
  const cap = document.createElement("div"); cap.className = "cap";
  const a = document.createElement("span"); a.textContent = `${spent.toLocaleString("en-US")} of ${leafCount.toLocaleString("en-US")} one-time keys spent`;
  const b = document.createElement("span"); b.textContent = nextFree === undefined ? "none left" : `next ${nextFree}`;
  cap.append(a, b);
  box.append(bar, cap);
  return box;
}
