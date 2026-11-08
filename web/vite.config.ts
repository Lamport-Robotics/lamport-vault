import { defineConfig } from "vite";

export default defineConfig({
  build: { outDir: "dist", target: "es2022", sourcemap: false, rollupOptions: { input: { main: "index.html", how: "how-it-works.html", security: "security.html", cold: "cold-signer.html", faq: "faq.html" } } },
  define: { "process.env.NODE_DEBUG": "false" },
  resolve: { alias: { buffer: "buffer/" } },
  optimizeDeps: { include: ["buffer"] },
});
