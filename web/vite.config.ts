import { defineConfig } from "vite";

export default defineConfig({
  build: { outDir: "dist", target: "es2022", sourcemap: false, rollupOptions: { input: { main: "index.html", how: "how-it-works.html", security: "security.html", cold: "cold-signer.html", faq: "faq.html" } } },
  // __HEIR__ is true only in the Heir build (vite.heir.config.ts); false here, and what it guards is left out
  define: { "process.env.NODE_DEBUG": "false", __HEIR__: "false", __HEIR_RPC__: '""' },
  resolve: { alias: { buffer: "buffer/" } },
  optimizeDeps: { include: ["buffer"] },
});
