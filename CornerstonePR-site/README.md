# CornerstonePR — Penny Performance Scorecard

Single-page, password-protected static site for Vercel.

- `index.html` — the deployed page. Shows a password screen; the scorecard HTML is AES-256-GCM encrypted inside the page and only decrypts with the correct password (it is not readable via view-source).
- `scorecard-source.html` — the unencrypted scorecard (kept out of the Vercel deploy via `.vercelignore`).
- `tools/build.mjs` — regenerates `index.html` from `scorecard-source.html`.

## Updating the page

1. Edit `scorecard-source.html` (or replace it with a new export).
2. Rebuild: `node tools/build.mjs` (or `node tools/build.mjs "NewPassword"` to change the password).
3. Commit and push — Vercel redeploys `index.html`.

## Vercel

Connect this repo as a static project (no framework, no build command, output directory = repo root). Map the domain/subdomain to the project and the page is live at `/`.
