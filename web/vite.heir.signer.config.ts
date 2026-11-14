import { execSync } from "node:child_process";
import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";
import { heirAlias, heirDefine } from "./vite.heir.config.ts";

// the Heir build of the cold signer: one self-contained html file, like vite.signer.config.ts makes
const commit = (() => { try { return execSync("git rev-parse --short=10 HEAD", { stdio: ["ignore", "pipe", "ignore"] }).toString().trim(); } catch { return "unknown"; } })();

export default defineConfig({
  plugins: [viteSingleFile()],
  build: { outDir: "dist-heir-signer", target: "es2022", rollupOptions: { input: "signer.html" } },
  define: { ...heirDefine, __SIGNER_BUILD__: JSON.stringify(commit) },
  resolve: { alias: heirAlias },
});
