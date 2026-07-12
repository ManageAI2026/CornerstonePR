#!/usr/bin/env node
// Encrypts scorecard-source.html into PennyPR/index.html behind a password gate,
// and writes a root index.html that redirects to /PennyPR.
// Usage: node tools/build.mjs [password]   (default password baked in below)
import { webcrypto as crypto } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const PASSWORD = process.argv[2] || 'Manage2026!';
const ITERATIONS = 600000;

const plaintext = readFileSync(join(root, 'scorecard-source.html'), 'utf8');
const logoDataUri = 'data:image/png;base64,' + readFileSync(join(root, 'assets', 'logo.png')).toString('base64');

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
<title>Manage AI · Cornerstone PR</title>
<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--navy:#101D3A;--ink:#1E293B;--blue:#2F5FC4;--blue2:#254FA8;--bd:#E2E6EC;--slate:#475569;--mut:#8A97A8;--red:#DC2626;--head:'Montserrat',system-ui,sans-serif;--body:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:radial-gradient(1200px 800px at 50% 38%,#182B57 0%,var(--navy) 65%);color:var(--slate);font-family:var(--body);display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:400px;background:#fff;border-radius:14px;padding:38px 36px 34px;box-shadow:0 20px 60px rgba(10,18,32,.45)}
.logorow{display:flex;align-items:center;gap:10px;margin-bottom:26px}
.logorow img{height:24px;width:auto;display:block}
.logorow .tag{font:700 10.5px/1 var(--head);letter-spacing:.12em;text-transform:uppercase;color:var(--mut);padding-left:10px;border-left:1px solid var(--bd)}
h1{font:800 26px/1.15 var(--head);letter-spacing:-.01em;color:var(--ink);margin:0 0 6px}
p.sub{font-size:13.5px;color:var(--mut);margin:0 0 24px}
label{display:block;font:700 10.5px/1 var(--head);letter-spacing:.1em;text-transform:uppercase;color:var(--slate);margin-bottom:8px}
input{width:100%;padding:13px 14px;font-size:15px;font-family:var(--body);color:var(--ink);background:#fff;border:1px solid var(--bd);border-radius:9px;outline:none}
input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(47,95,196,.2)}
button{width:100%;margin-top:18px;padding:13px 14px;font:700 14.5px/1 var(--head);letter-spacing:.02em;color:#fff;background:var(--blue);border:0;border-radius:9px;cursor:pointer;transition:background .15s}
button:hover{background:var(--blue2)}
button:disabled{opacity:.6;cursor:wait}
.err{display:none;margin-top:14px;font-size:12.5px;color:var(--red);font-weight:600}
.foot{margin-top:22px;font-size:10.5px;color:var(--mut)}
@media(max-width:440px){.card{padding:30px 24px 26px}}
</style></head><body>
<div class="card">
  <div class="logorow"><img src="${logoDataUri}" alt="Manage AI"><span class="tag">Cornerstone&nbsp;PR</span></div>
  <h1>Welcome back</h1>
  <p class="sub">Sign in to view the Cornerstone performance review.</p>
  <form id="f">
    <label for="pw">Password</label>
    <input id="pw" type="password" placeholder="••••••••••••" autocomplete="current-password" autofocus>
    <button id="btn" type="submit">Sign In</button>
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
  btn.disabled = true; btn.textContent = 'Signing in…';
  try {
    const html = await decrypt(pw);
    try { sessionStorage.setItem('mai_pw', pw); } catch(e){}
    show(html);
  } catch(e) {
    btn.disabled = false; btn.textContent = 'Sign In';
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

const redirect = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow">
<meta http-equiv="refresh" content="0;url=/PennyPR/">
<title>Manage AI</title></head>
<body style="margin:0;min-height:100vh;background:#101D3A"></body></html>
`;

mkdirSync(join(root, 'PennyPR'), { recursive: true });
writeFileSync(join(root, 'PennyPR', 'index.html'), page);
writeFileSync(join(root, 'index.html'), redirect);
console.log('PennyPR/index.html written (' + page.length + ' bytes), root redirect written, password: ' + PASSWORD);
