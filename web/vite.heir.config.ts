import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

// The Heir build of the vault page: the same source as vite.config.ts, for vaults of the
// Heir-enabled program (docs/SUCCESSION.md). It is served under /heir/ on the vault's origin.
// HEIR_CLOCK=short builds it for the `short-clocks` test program, where a day lasts a second.
// HEIR_RPC=http://127.0.0.1:8899 points it at another endpoint and lets the page's CSP reach it: a
// test build for a local validator, never one to publish.
const rpc = process.env.HEIR_RPC ?? "";
export const heirDefine = { "process.env.NODE_DEBUG": "false", __HEIR__: "true", __HEIR_SHORT_CLOCKS__: JSON.stringify(process.env.HEIR_CLOCK === "short"), __HEIR_RPC__: JSON.stringify(rpc) };
export const heirAlias = { buffer: "buffer/", "@lamport-robotics/vault": fileURLToPath(new URL("./src/heir-sdk.ts", import.meta.url)) };

/** the page's CSP names the endpoints it may talk to; a test build names its own instead */
const testEndpoint = { name: "heir-test-endpoint", transformIndexHtml: (html: string) => (rpc ? html.replace("https://api.devnet.solana.com wss://api.devnet.solana.com", `${rpc} ${rpc.replace(/^http/, "ws").replace(/:(\d+)$/, (_m, p) => `:${Number(p) + 1}`)}`) : html) };

export default defineConfig({
  plugins: [testEndpoint],
  base: "/heir/",
  build: { outDir: "dist-heir", target: "es2022", sourcemap: false, rollupOptions: { input: { index: "index.html" } } },
  define: heirDefine,
  resolve: { alias: heirAlias },
  optimizeDeps: { include: ["buffer"] },
});
