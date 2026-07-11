#!/usr/bin/env node
// Encrypts scorecard-source.html into index.html behind a password gate.
// Usage: node tools/build.mjs [password]   (default password baked in below)
import { webcrypto as crypto } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const PASSWORD = process.argv[2] || 'Manage2026!';
const ITERATIONS = 600000;

const plaintext = readFileSync(join(root, 'scorecard-source.html'), 'utf8');

const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(PASSWORD), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
  baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
);
const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, gzipSync(plaintext)));

const b64 = (u8) => Buffer.from(u8).toString('base64');
const ctChunks = b64(ciphertext).match(/.{1,1000}/gs).map(c => JSON.stringify(c)).join(',\n');
const payload = `{salt:'${b64(salt)}',iv:'${b64(iv)}',it:${ITERATIONS},ct:[\n${ctChunks}\n].join('')}`;

const page = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Manage AI · Protected Report</title>
<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#faf9f5;--ink:#1E293B;--blue:#4A8FD6;--blue2:#2D6AAF;--bd:#E2E6EC;--slate:#475569;--mut:#7A8B9A;--red:#DC2626;--head:'Montserrat',system-ui,sans-serif;--body:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--slate);font-family:var(--body);display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:400px;background:#fff;border:1px solid var(--bd);border-radius:18px;padding:34px 32px 30px;box-shadow:0 1px 3px rgba(0,0,0,.04),0 12px 30px rgba(30,51,72,.08);text-align:center}
.lock{width:52px;height:52px;margin:0 auto 16px;border-radius:14px;background:var(--blue);display:flex;align-items:center;justify-content:center}
.lock svg{width:26px;height:26px;fill:#fff}
.brand{font:800 11px/1.3 var(--head);letter-spacing:.14em;text-transform:uppercase;color:var(--blue2);margin-bottom:6px}
h1{font:800 22px/1.15 var(--head);letter-spacing:-.01em;color:var(--ink);margin:0 0 6px}
p.sub{font-size:13px;color:var(--mut);margin:0 0 20px}
input{width:100%;padding:12px 14px;font-size:15px;font-family:var(--body);color:var(--ink);background:#fff;border:1px solid var(--bd);border-radius:10px;outline:none;text-align:center}
input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(74,143,214,.15)}
button{width:100%;margin-top:12px;padding:12px 14px;font:700 14px/1 var(--head);letter-spacing:.03em;color:#fff;background:var(--blue2);border:0;border-radius:10px;cursor:pointer}
button:hover{background:#255c99}
button:disabled{opacity:.6;cursor:wait}
.err{display:none;margin-top:12px;font-size:12.5px;color:var(--red);font-weight:600}
.foot{margin-top:20px;font-size:10.5px;color:var(--mut)}
</style></head><body>
<div class="card">
  <div class="lock"><svg viewBox="0 0 24 24"><path d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5zm-3 8V7a3 3 0 1 1 6 0v3H9zm3 4a1.5 1.5 0 0 1 .75 2.8V19h-1.5v-2.2A1.5 1.5 0 0 1 12 14z"/></svg></div>
  <div class="brand">Manage AI</div>
  <h1>Protected Report</h1>
  <p class="sub">Enter the password to view this page.</p>
  <form id="f">
    <input id="pw" type="password" placeholder="Password" autocomplete="current-password" autofocus>
    <button id="btn" type="submit">Unlock</button>
  </form>
  <div class="err" id="err">Incorrect password. Please try again.</div>
  <div class="foot">Prepared by Manage AI · Access is restricted</div>
</div>
<script>
const DATA = ${payload};
const b = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function decrypt(pw){
  const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt:b(DATA.salt), iterations:DATA.it, hash:'SHA-256'}, baseKey, {name:'AES-GCM', length:256}, false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:b(DATA.iv)}, key, b(DATA.ct));
  const stream = new Blob([pt]).stream().pipeThrough(new DecompressionStream('gzip'));
  return await new Response(stream).text();
}
function show(html){
  document.open(); document.write(html); document.close();
}
async function attempt(pw, silent){
  const btn = document.getElementById('btn');
  btn.disabled = true; btn.textContent = 'Unlocking…';
  try {
    const html = await decrypt(pw);
    try { sessionStorage.setItem('mai_pw', pw); } catch(e){}
    show(html);
  } catch(e) {
    btn.disabled = false; btn.textContent = 'Unlock';
    if (!silent) {
      document.getElementById('err').style.display = 'block';
      const el = document.getElementById('pw'); el.value = ''; el.focus();
    }
  }
}
document.getElementById('f').addEventListener('submit', ev => {
  ev.preventDefault();
  const pw = document.getElementById('pw').value;
  if (pw) attempt(pw, false);
});
try { const saved = sessionStorage.getItem('mai_pw'); if (saved) attempt(saved, true); } catch(e){}
</script>
</body></html>
`;

writeFileSync(join(root, 'index.html'), page);
console.log('index.html written (' + page.length + ' bytes), password: ' + PASSWORD);
