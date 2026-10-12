# web

vault.lamportrobotics.com. Vite, no framework, no backend; talks to devnet from the browser.

```sh
npm i
npm run dev
npm run build   # dist/ + dist/signer.html (single file, works offline)
```

`signer.html` is the cold signer: download it, open it on an offline machine, paste the request the
vault page gives you, type the words, bring the signature back. The main page only ever sees the
signature.

Deploy: rsync `dist/` to `/opt/lamportvault/site` on the box, Caddy serves it.
