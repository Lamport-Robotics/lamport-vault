import { fileURLToPath } from "node:url";

// Which cluster a build is for. LAMPORT_CLUSTER=mainnet makes the mainnet build: the mainnet program
// ids (docs/VERIFY.md), the mainnet genesis hash in every key derivation, the mainnet endpoints in
// the page's CSP. Unset, or "devnet", is the devnet build, which is what these configs always made.
const wanted = process.env.LAMPORT_CLUSTER ?? "devnet";
if (wanted !== "devnet" && wanted !== "mainnet") throw new Error(`LAMPORT_CLUSTER is "${wanted}": it is "devnet" or "mainnet"`);
export const mainnet = wanted === "mainnet";
// a build for the `short-clocks` test program, or one pointed at another endpoint, is a test build
if (mainnet && (process.env.HEIR_CLOCK === "short" || process.env.HEIR_RPC)) throw new Error("a mainnet build is never a test build: unset HEIR_CLOCK and HEIR_RPC");

export const clusterDefine = { __MAINNET__: JSON.stringify(mainnet) };

/** a mainnet build goes to folders of its own, so that neither build can be mistaken for the other */
export const out = (dir: string) => (mainnet ? `${dir}-mainnet` : dir);

/** in a mainnet build of the vault's own page and signer, the SDK's two program ids are the mainnet ones */
export const mainnetAlias: Record<string, string> = mainnet ? { "@lamport-robotics/vault": fileURLToPath(new URL("./src/mainnet-sdk.ts", import.meta.url)) } : {};

const DEVNET_ENDPOINTS = "https://api.devnet.solana.com wss://api.devnet.solana.com";
const MAINNET_ENDPOINTS = "https://api.mainnet-beta.solana.com wss://api.mainnet-beta.solana.com";

// What the pages say about where the programs run. The source says it for devnet; a mainnet build
// says it for mainnet. Each line here replaces one sentence of the source, and a mainnet page that
// still names devnet after them fails the build: a page must not say "devnet only" over a program
// that holds value, and must not promise an audit that has not happened.
const MAINNET_WORDS: [from: string, to: string][] = [
  ["<small>devnet</small>", "<small>mainnet</small>"],
  [
    "<p>On devnet, for now. Mainnet follows an independent audit; until then the program holds no real funds and the page says so.</p>",
    "<p>On Solana mainnet. The programs have not had an independent audit. The repository's VERIFY document records what is deployed: the program ids, the hash of each build, and whether anyone can still change the code.</p>",
  ],
  ["reproducible builds, devnet deployments.", "reproducible builds, deployments."],
  ["<h3>Current deployment (devnet)</h3>", "<h3>Current deployment (mainnet)</h3>"],
  ['<dd class="mono">B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH</dd>', '<dd class="mono">7EiE5pRP5byrY7mzvUBfXS2UD8GwGtPhbGne6D1BTR5H</dd>'],
  ['<dd class="mono">48J2BtWFjEUbGPYf1yMPBkHxpy4dLo69gK2znQR2q2ad</dd>', '<dd class="mono">9MYg9uqYBrTPXA6MNRZ6cbpwHSissY3496Y84iofTaNF</dd>'],
  [
    "<dd>devnet only; an independent audit comes before any mainnet deployment. Hashes and slots are recorded in the repository's VERIFY document.</dd>",
    "<dd>mainnet; not independently audited. Hashes and slots are recorded in the repository's VERIFY document.</dd>",
  ],
];

/**
 * The page's CSP names the endpoints it may talk to, and its words name the cluster: a mainnet
 * build names mainnet in both, and devnet in neither.
 */
export const clusterEndpoints = {
  name: "cluster-endpoints",
  transformIndexHtml(html: string): string {
    if (!mainnet) return html;
    if (html.includes("Content-Security-Policy") && !html.includes(DEVNET_ENDPOINTS)) throw new Error("the page's CSP no longer names the devnet endpoints this build replaces: fix cluster.config.ts");
    let page = html.replace(DEVNET_ENDPOINTS, MAINNET_ENDPOINTS);
    for (const [from, to] of MAINNET_WORDS) page = page.split(from).join(to);
    const left = page.match(/[^<>]{0,60}devnet[^<>]{0,60}/i);
    if (left) throw new Error(`a mainnet page still names devnet: "${left[0].trim()}". Say it for mainnet in cluster.config.ts`);
    return page;
  },
};
