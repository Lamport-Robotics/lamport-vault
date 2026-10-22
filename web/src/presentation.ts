/** Layout only: retain the current copy, form nodes, IDs and event listeners. */
export function presentHome(root: HTMLElement): HTMLElement {
  const grid = root.firstElementChild as HTMLElement;
  const intro = grid.children[0] as HTMLElement;
  const access = grid.children[1] as HTMLElement;
  const facts = intro.querySelector<HTMLElement>(".facts")!;
  const rail = root.querySelector<HTMLElement>(".rail")!;
  const node = (tag: string, cls: string, text?: string) => { const n = document.createElement(tag); n.className = cls; if (text) n.textContent = text; return n; };

  // the statement, centred, then the vault door itself: the open panel
  const hero = node("section", "v-hero");
  hero.append(...Array.from(intro.children).filter((c) => c !== facts));
  access.classList.add("access-panel");
  access.querySelector("#go")?.classList.add("wide");
  const stage = node("section", "v-stage");
  stage.append(access);

  // what makes it post-quantum, shown as the meter every vault page carries
  const keys = node("section", "v-keys");
  const head = node("div", "v-keys-head");
  head.append(node("h2", "", "1,024 one-time keys. The chain counts every one."),
    node("p", "", "Each signature spends exactly one key, and the program refuses a key it has seen before. When the keys run low you rotate to the next set from the same 24 words, at the same address."));
  const strip = node("div", "v-strip");
  strip.setAttribute("aria-hidden", "true");
  for (let i = 0; i < 64; i++) { const b = document.createElement("i"); b.style.setProperty("--n", String(i)); strip.append(b); }
  const legend = node("div", "v-legend");
  legend.append(node("span", "", "Each bar is sixteen keys"), node("span", "spent", "Spent"), node("span", "free", "Unused"));
  keys.append(head, strip, legend);

  const how = node("section", "v-how");
  const howHead = node("div", "v-how-head");
  const more = document.createElement("a"); more.className = "link arrow"; more.href = "/how-it-works"; more.textContent = "How it works";
  howHead.append(node("h2", "", "Three steps, and the words never go online."), more);
  how.append(howHead, rail);

  root.replaceChildren(hero, stage, facts, keys, how);
  root.classList.add("home");

  const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }), { threshold: 0.35 });
  io.observe(strip);
  return root;
}
