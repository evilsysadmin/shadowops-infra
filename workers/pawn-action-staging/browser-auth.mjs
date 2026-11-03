// Candidate-only browser entry for Pawn Action's separate staging Identity.
// Static: no tokens in URL, storage, logs or HTML. NOT in deployed holding shell.
import {ISSUER} from './identity-gate.mjs';
export const SCRIPT_PATH = '/_shadowops/session.js';
export const LOGIN_LINK = ISSUER + '/login?app=pawn-action';
const JS_HEADERS = {
  'Content-Type': 'text/javascript; charset=utf-8',
  'Cache-Control': 'no-store, max-age=0',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Resource-Policy': 'same-origin',
};
const HTML_HEADERS = {
  'Content-Type': 'text/html; charset=utf-8',
  'Cache-Control': 'no-store, max-age=0',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Resource-Policy': 'same-origin',
  // Keep this login response separate from the isolated Godot WASM page;
  // the external credentialed IdP fetch is governed by pinned Identity CORS.
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self' " +
    ISSUER + "; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};
export const SESSION_SCRIPT = "const status=document.querySelector('[role=\"status\"]');\n(async()=>{\n  try {\n    const identity=await fetch('https://id-staging.shadowops.dpdns.org/api/identity/token',{\n      method:'POST',credentials:'include',cache:'no-store',\n      headers:{'Content-Type':'application/json'},body:'{}',\n      signal:AbortSignal.timeout(8000)\n    });\n    if(identity.status===401||identity.status===403){\n      status.textContent='Inicia sesión en ShadowOps ID para jugar.';\n      return;\n    }\n    if(!identity.ok)throw Error('identity unavailable');\n    const payload=await identity.json();\n    if(!payload||typeof payload.token!=='string'||payload.token.length===0||payload.token.length>3500)\n      throw Error('invalid response');\n    const session=await fetch('/api/pawn-action/session',{\n      method:'POST',credentials:'same-origin',cache:'no-store',\n      headers:{'Content-Type':'application/json'},\n      body:JSON.stringify({token:payload.token}),\n      signal:AbortSignal.timeout(8000)\n    });\n    if(!session.ok)throw Error('exchange denied');\n    location.replace('/');\n  }catch{\n    status.textContent='El acceso a Pawn Action no está disponible ahora. Inténtalo de nuevo.';\n  }\n})();";
const LOGIN_HTML = "<!doctype html>\n<html lang=\"es\"><head><meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>Pawn Action · ShadowOps ID</title>\n<style>\n:root{color-scheme:dark}\nbody{margin:0;min-height:100vh;display:grid;place-items:center;background:#141b21;\n color:#f5f0dc;font:18px/1.55 system-ui, sans-serif}\nmain{max-width:34rem;margin:1rem;padding:2rem;border:1px solid #7d826f;border-radius:14px}\nsmall{color:#cacbbf;letter-spacing:.1em}\nh1{margin:.6rem 0;font-size:clamp(1.6rem,4vw,2.1rem)}\na{display:inline-block;margin:.5rem 0;padding:.8rem 1.1rem;border-radius:8px;\n background:#e3bd6c;color:#171d21;font-weight:650;text-decoration:none}\na:focus-visible{outline:3px solid #d5ed91;outline-offset:4px}\n</style></head><body><main>\n<small>PAWN ACTION · STAGING</small>\n<h1>Accede con ShadowOps ID</h1>\n<p role=\"status\" aria-live=\"polite\">Comprobando tu sesión…</p>\n<a href=\"https://id-staging.shadowops.dpdns.org/login?app=pawn-action\">Entrar con ShadowOps ID</a>\n<p><small>El juego se entrega únicamente tras verificar tu sesión.\nNo se guardan credenciales en el navegador.</small></p>\n</main><script src=\"/_shadowops/session.js\" defer></script></body></html>";

export function loginPage(status = 401, method = 'GET') {
  if (status !== 401 && status !== 503) status = 503;
  return new Response(method === 'HEAD' ? null : LOGIN_HTML,
    {status, headers: HTML_HEADERS});
}
export function sessionScript(method = 'GET') {
  return new Response(method === 'HEAD' ? null : SESSION_SCRIPT,
    {status: 200, headers: JS_HEADERS});
}
