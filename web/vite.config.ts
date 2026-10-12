import { defineConfig } from "vite";

export default defineConfig({
  build: { outDir: "dist", target: "es2022", sourcemap: false },
  define: { "process.env.NODE_DEBUG": "false" },
  resolve: { alias: { buffer: "buffer/" } },
  optimizeDeps: { include: ["buffer"] },
});
