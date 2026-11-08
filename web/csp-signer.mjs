// the single-file signer inlines its only script; put that script's hash into the page's csp so
// script-src allows exactly it and nothing else. run after the signer build, before the copy to dist.
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const file = process.argv[2];
const html = readFileSync(file, "utf8");
const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
if (scripts.length !== 1 || !scripts[0].trim()) throw new Error(`${file}: expected one inline script, found ${scripts.length}`);
if (/<script\b[^>]*\bsrc=/.test(html)) throw new Error(`${file}: an external script survived the single-file build`);
const hash = `'sha256-${createHash("sha256").update(scripts[0], "utf8").digest("base64")}'`;
const out = html.replace(/(<meta http-equiv="Content-Security-Policy" content="[^"]*script-src )'self'/, `$1${hash}`);
if (out === html) throw new Error(`${file}: csp meta with script-src 'self' not found`);
writeFileSync(file, out);
console.log(`csp: signer script-src ${hash}`);
