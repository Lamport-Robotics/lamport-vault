/**
 * Writes kat/succession_encoding.json (see succession-kat.ts).
 *
 *   node packages/vault/scripts/write-succession-kat.ts        (from sdk/)
 */
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildSuccessionKat } from "./succession-kat.ts";

const out = fileURLToPath(new URL("../../../../kat/succession_encoding.json", import.meta.url));
writeFileSync(out, JSON.stringify(buildSuccessionKat(), null, 2) + "\n");
console.log(`wrote ${out}`);
