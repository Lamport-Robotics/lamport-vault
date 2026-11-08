import { execSync } from "node:child_process";
import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

// the cold signer is one self-contained html file: download it, open it offline
const commit = (() => { try { return execSync("git rev-parse --short=10 HEAD", { stdio: ["ignore", "pipe", "ignore"] }).toString().trim(); } catch { return "unknown"; } })();

export default defineConfig({
  plugins: [viteSingleFile()],
  build: { outDir: "dist-signer", target: "es2022", rollupOptions: { input: "signer.html" } },
  // the footer shows which commit the file was built from; CI prints the file's sha256 for that commit
  define: { "process.env.NODE_DEBUG": "false", __SIGNER_BUILD__: JSON.stringify(commit) },
  resolve: { alias: { buffer: "buffer/" } },
});
