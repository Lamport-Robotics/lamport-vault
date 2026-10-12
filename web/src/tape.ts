/** the leaf tape: every one-time key of the vault as a bar. spent ones filled, the next one marked. */
export function tape(leafCount: number, nextQ: number): HTMLElement {
  const cells = Math.min(leafCount, 1024);
  const per = leafCount / cells;         // leaves per cell (1 for H10, 32 for H15, 1024 for H20)
  const cols = 64, rows = cells / cols;
  const w = 6, g = 2, h = 14, gy = 4;
  const W = cols * (w + g) - g, H = rows * (h + gy) - gy;
  const parts: string[] = [];
  for (let i = 0; i < cells; i++) {
    const x = (i % cols) * (w + g), y = Math.floor(i / cols) * (h + gy);
    const from = i * per, to = from + per;
    let fill: string;
    if (nextQ >= to) fill = "#f2eee3";                        // spent
    else if (nextQ >= from) fill = "#9a968c";                 // the cell holding the next leaf
    else fill = "rgba(242,238,227,0.10)";                     // unused
    parts.push(`<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="${fill}"/>`);
  }
  const box = document.createElement("div");
  box.className = "tape";
  box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet" aria-label="one-time keys">${parts.join("")}</svg>
  <div class="cap"><span>${nextQ} of ${leafCount} keys spent</span><span>next q = ${nextQ}${per > 1 ? ` · ${per} per bar` : ""}</span></div>`;
  return box;
}
