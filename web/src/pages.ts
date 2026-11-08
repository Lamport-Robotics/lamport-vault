import "./style.css";
import "./pages.css";
import "./interface.css";

// reveal on scroll; the svg animations key off the same class
const io = new IntersectionObserver((es) => { for (const e of es) if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }, { rootMargin: "0px 0px -12% 0px", threshold: 0.15 });
document.querySelectorAll(".reveal").forEach((n) => io.observe(n));

// mark the current page in the nav
const here = location.pathname.replace(/\.html$/, "").replace(/\/$/, "") || "/";
document.querySelectorAll<HTMLAnchorElement>(".nav a").forEach((a) => { const p = a.getAttribute("href")!.replace(/\.html$/, ""); if (p === here || (here === "" && p === "/")) a.classList.add("on"); });

// the key meter on "how it works": fills one more segment every second while in view
const meter = document.querySelector<SVGElement>("#meter");
if (meter) {
  const segs = Array.from(meter.querySelectorAll<SVGRectElement>("rect.seg"));
  let i = 0, timer = 0;
  const step = () => { if (i < segs.length) { segs[i].setAttribute("class", "seg v-fill"); if (i + 1 < segs.length) segs[i + 1].setAttribute("class", "seg v-mid"); i++; } else { segs.forEach((s) => s.setAttribute("class", "seg v-dim")); i = 0; } };
  const mo = new IntersectionObserver((es) => { for (const e of es) { if (e.isIntersecting && !timer) timer = window.setInterval(step, 420); else if (!e.isIntersecting && timer) { clearInterval(timer); timer = 0; } } }, { threshold: 0.3 });
  mo.observe(meter);
}
