# web

vault.lamportrobotics.com. Vite, no framework. The page talks to devnet from the browser; on the hosted site JSON-RPC goes through a same-origin `/rpc` that the server forwards to a provider (Origin-checked), elsewhere straight to the public devnet endpoint.

```sh
npm i
npm run dev
npm run build   # dist/ + dist/signer.html (single file, works offline)
```

`signer.html` is the cold signer: download it, open it on an offline machine, paste the request the
vault page gives you, type the words, bring the signature back. The main page only ever sees the
signature.

Build in CI: the `web` job of `.github/workflows/test.yml` runs `npm ci` and `npm run build` and prints `sha256(dist/signer.html)` in its summary; a deploy is that artifact. Deploy: rsync `dist/` to `/opt/lamportvault/site` on the box, Caddy serves it.

## The Heir build

```sh
npm run build:heir                       # dist-heir/ + dist-heir/signer.html, served under /heir/
HEIR_CLOCK=short npm run build:heir      # for the short-clocks test program (a day lasts a second)
npm test                                 # the Heir build's request code, against kat/succession_encoding.json
```

The same source, built for vaults of the Heir-enabled program: the page gets an Inheritance tab
and the signer learns to show and sign a plan. `docs/SUCCESSION.md`, section 9, says how it is put
together and why `npm run build` still produces exactly the files it did. The Heir build is not
part of a deploy of this site; Lamport Heir ships its own, built from this source.

To try it against a local validator that has the test program loaded:

```sh
HEIR_CLOCK=short HEIR_RPC=http://127.0.0.1:8899 npm run build:heir
npx vite preview -c vite.heir.config.ts --port 4173      # http://localhost:4173/heir/
```

`HEIR_RPC` also widens the page's CSP to that endpoint. It makes a test build, never one to publish.

## Interface

The app and information pages import `src/interface.css` after the base styles.
`src/presentation.ts` restores the Vault layout by moving the existing home-page
nodes, preserving the copy, form IDs, and listeners in `app.ts`. Keep the
`presentHome(s)` call when editing the home page. The standalone offline signer
continues using its own existing base stylesheet.
