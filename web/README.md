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

## Interface

The app and information pages import `src/interface.css` after the base styles.
`src/presentation.ts` restores the Vault layout by moving the existing home-page
nodes, preserving the copy, form IDs, and listeners in `app.ts`. Keep the
`presentHome(s)` call when editing the home page. The standalone offline signer
continues using its own existing base stylesheet.
