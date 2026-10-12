/** Layout only: retain the current copy, form nodes, IDs and event listeners. */
export function presentHome(root: HTMLElement): HTMLElement {
  const grid = root.firstElementChild as HTMLElement;
  const intro = grid.children[0] as HTMLElement;
  const access = grid.children[1] as HTMLElement;
  const facts = intro.querySelector<HTMLElement>(".facts")!;
  const eyebrow = intro.querySelector<HTMLElement>(".eyebrow")!;
  const rail = root.querySelector<HTMLElement>(".rail")!;

  root.classList.add("home", "restored-home");
  grid.className = "home-grid";
  intro.classList.add("home-intro");
  intro.querySelector("p")?.classList.add("home-description");
  access.classList.add("access-panel");
  access.querySelector(".eyebrow")?.classList.add("access-title");
  access.querySelector("#go")?.classList.add("wide", "arrow");

  const masthead = document.createElement("div");
  masthead.className = "masthead";
  const meta = document.createElement("div");
  meta.className = "masthead-meta";
  meta.append(eyebrow);
  // Brand typography is decorative; the original heading remains the page's h1.
  const wordmark = document.createElement("div");
  wordmark.className = "restored-wordmark";
  wordmark.setAttribute("aria-hidden", "true");
  wordmark.append("VAULT");
  const period = document.createElement("span");
  period.className = "title-period";
  period.textContent = ".";
  wordmark.append(period);
  masthead.append(meta, wordmark);

  const strips = document.createElement("div");
  strips.className = "key-strips restored-strips";
  strips.setAttribute("aria-hidden", "true");
  for (let i = 0; i < 64; i++) {
    const bar = document.createElement("i");
    bar.style.setProperty("--n", String(i));
    strips.append(bar);
  }
  intro.append(strips);
  root.prepend(masthead);
  root.insertBefore(facts, rail);
  return root;
}
