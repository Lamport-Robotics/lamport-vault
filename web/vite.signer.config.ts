import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

// the cold signer is one self-contained html file: download it, open it offline
export default defineConfig({
  plugins: [viteSingleFile()],
  build: { outDir: "dist-signer", target: "es2022", rollupOptions: { input: "signer.html" } },
  define: { "process.env.NODE_DEBUG": "false" },
  resolve: { alias: { buffer: "buffer/" } },
});
