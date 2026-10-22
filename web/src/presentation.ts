/** Layout only: retain the current copy, form nodes, IDs and event listeners. */
export function presentHome(root: HTMLElement): HTMLElement {
  const grid = root.firstElementChild as HTMLElement;
  const intro = grid.children[0] as HTMLElement;
  const access = grid.children[1] as HTMLElement;
  const facts = intro.querySelector<HTMLElement>(".facts")!;
  const rail = root.querySelector<HTMLElement>(".rail")!;
  const node = (tag: string, cls: string, text?: string) => { const n = document.createElement(tag); n.className = cls; if (text) n.textContent = text; return n; };

  // one screen: the statement and its facts on the left, the open panel on the right
  const top = node("section", "v-top");
  intro.classList.add("v-intro");
  access.classList.add("access-panel");
  access.querySelector("#go")?.classList.add("wide");
  top.append(intro, access);

  // the meter every vault page carries, then the three steps
  const keys = node("section", "v-keys");
  const head = node("div", "v-keys-head");
  const more = document.createElement("a"); more.className = "link arrow"; more.href = "/how-it-works"; more.textContent = "How it works";
  head.append(node("h2", "", "1,024 one-time keys. The chain counts every one."), more);
  const strip = node("div", "v-strip");
  strip.setAttribute("aria-hidden", "true");
  for (let i = 0; i < 64; i++) { const b = document.createElement("i"); b.style.setProperty("--n", String(i)); strip.append(b); }
  const legend = node("div", "v-legend");
  legend.append(node("span", "", "Each bar is sixteen keys. Rotate before they run out, same words, same address."), node("span", "spent", "Spent"), node("span", "free", "Unused"));
  keys.append(head, strip, legend, rail);

  root.replaceChildren(top, keys);
  root.classList.add("home");
  intro.append(facts);

  const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }), { threshold: 0.35 });
  io.observe(strip);
  return root;
}
