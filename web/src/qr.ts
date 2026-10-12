/** qr in and out. a signature is ~3.4 kB of base64, more than one code holds, so it travels as frames. */
import QRCode from "qrcode";
import jsQR from "jsqr";
import { el } from "./common.ts";

const FRAME = 900; // bytes per frame, comfortably inside QR v30 byte mode at L
const TAG = "LV1:";

export function frames(text: string): string[] {
  const n = Math.ceil(text.length / FRAME);
  const out: string[] = [];
  for (let i = 0; i < n; i++) out.push(`${TAG}${i + 1}/${n}:${text.slice(i * FRAME, (i + 1) * FRAME)}`);
  return out;
}

/** draws the code(s); several frames cycle every 700 ms. returns a stop function. */
export async function show(container: HTMLElement, text: string): Promise<() => void> {
  container.innerHTML = "";
  const fr = frames(text);
  const urls = await Promise.all(fr.map((f) => QRCode.toDataURL(f, { errorCorrectionLevel: "L", margin: 1, scale: 4, color: { dark: "#0a0a0a", light: "#f2eee3" } })));
  const img = el("img", { alt: "qr", style: "width:min(100%,360px);display:block;image-rendering:pixelated;background:#f2eee3;padding:8px" });
  const cap = el("div", { class: "cap mono", style: "font-size:11px;color:var(--mute);margin-top:6px" });
  container.append(img, cap);
  let i = 0, timer: number | undefined;
  const paint = () => { img.src = urls[i]; cap.textContent = fr.length > 1 ? `frame ${i + 1} of ${fr.length} · hold the camera on it` : "one frame"; i = (i + 1) % fr.length; };
  paint();
  if (fr.length > 1) timer = window.setInterval(paint, 700);
  return () => { if (timer) clearInterval(timer); container.innerHTML = ""; };
}

/** opens the camera inside `container`, collects frames until the set is complete, resolves with the text. */
export function scan(container: HTMLElement): { done: Promise<string>; stop: () => void } {
  container.innerHTML = "";
  const video = el("video", { playsinline: "", muted: "", autoplay: "", style: "width:100%;max-width:360px;display:block;background:#000" }) as HTMLVideoElement;
  const cap = el("div", { class: "mono", style: "font-size:11px;color:var(--mute);margin-top:6px" }, "starting camera…");
  const canvas = document.createElement("canvas");
  container.append(video, cap);
  let stream: MediaStream | null = null, raf = 0, stopped = false;
  const parts = new Map<number, string>(); let total = 0;
  const stop = () => { stopped = true; cancelAnimationFrame(raf); stream?.getTracks().forEach((t) => t.stop()); container.innerHTML = ""; };
  const done = new Promise<string>((resolve, reject) => {
    navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } }).then((s) => {
      stream = s; video.srcObject = s; void video.play();
      const tick = () => {
        if (stopped) return;
        if (video.readyState >= 2) {
          canvas.width = video.videoWidth; canvas.height = video.videoHeight;
          const ctx = canvas.getContext("2d", { willReadFrequently: true })!;
          ctx.drawImage(video, 0, 0);
          const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(img.data, img.width, img.height, { inversionAttempts: "attemptBoth" });
          if (code?.data) {
            const m = code.data.match(/^LV1:(\d+)\/(\d+):([\s\S]*)$/);
            if (m) {
              total = Number(m[2]); parts.set(Number(m[1]), m[3]);
              cap.textContent = `${parts.size} of ${total} frames`;
              if (parts.size === total) { const text = Array.from({ length: total }, (_, i) => parts.get(i + 1) ?? "").join(""); stop(); resolve(text); return; }
            } else { stop(); resolve(code.data); return; }
          }
        }
        raf = requestAnimationFrame(tick);
      };
      raf = requestAnimationFrame(tick);
    }).catch((e) => { cap.textContent = `camera: ${(e as Error).message}`; reject(e); });
  });
  return { done, stop };
}
