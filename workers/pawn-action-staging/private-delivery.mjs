// Review-only Pawn Action staging candidate: authenticated, private R2 delivery.
// DO NOT deploy this Worker until a dedicated non-public R2 bucket exists.
// No public assets URL, no env.ASSETS, no public CDN fallback.
import {authorizeRequest, IdentityDenied} from './identity-gate.mjs';
import {handleSessionExchange} from './session-exchange.mjs';

const HOST = 'staging.pawnaction.shadowops.dpdns.org';
const PREFIX = 'pawn-action/releases/';
const RELEASE = /^[a-f0-9]{16}$/;
const MAX_OBJECT_BYTES = 128 * 1024 * 1024;
const FILES = Object.freeze({
  'index.html': 'text/html; charset=utf-8',
  'index.js': 'text/javascript; charset=utf-8',
  'index.wasm': 'application/wasm',
  'index.pck': 'application/octet-stream',
  'index.png': 'image/png',
  'index.icon.png': 'image/png',
  'index.apple-touch-icon.png': 'image/png',
  'index.audio.worklet.js': 'text/javascript; charset=utf-8',
  'index.audio.position.worklet.js': 'text/javascript; charset=utf-8',
});
const SECURITY = Object.freeze({
  'Cache-Control': 'private, no-store, max-age=0',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'self' blob: 'unsafe-inline' 'wasm-unsafe-eval'; connect-src 'self'; worker-src 'self' blob:; img-src 'self' data:; style-src 'self' 'unsafe-inline'",
});
function json(body, status, method = 'GET') {
  return new Response(method === 'HEAD' ? null : JSON.stringify(body), {
    status, headers: {...SECURITY, 'Content-Type': 'application/json; charset=utf-8'},
  });
}
function canonical(url) {
  return url.protocol === 'https:' && url.hostname === HOST && !url.port &&
    !url.username && !url.password && !url.search && !url.hash;
}
function fileForPath(pathname) {
  const file = pathname === '/' ? 'index.html' : pathname.slice(1);
  // Only the nine files present in the admitted Godot Web export. A future
  // asset-list expansion must be reviewed; no arbitrary release.json/pointers.
  return Object.hasOwn(FILES, file) && (pathname === '/' || pathname === '/' + file) ?
    file : null;
}
function privateBucket(env) {
  return env?.PAWN_ACTION_PRIVATE_R2;
}
function releaseConfig(env) {
  return typeof env?.PAWN_ACTION_PRIVATE_RELEASE === 'string' &&
    RELEASE.test(env.PAWN_ACTION_PRIVATE_RELEASE) ? env.PAWN_ACTION_PRIVATE_RELEASE : null;
}
async function readPrivateAsset(env, file, method) {
  const bucket = privateBucket(env);
  const revision = releaseConfig(env);
  // R2 bindings must be a dedicated bucket with NO public access and no
  // r2.dev/custom domain. That inventory is a separate deployment preflight.
  if (!revision || !bucket || typeof bucket.get !== 'function' ||
    typeof bucket.head !== 'function') return json({error: 'access_unavailable'}, 503, method);
  const key = PREFIX + revision + '/' + file;
  let object;
  try {
    object = method === 'HEAD' ? await bucket.head(key) : await bucket.get(key);
  } catch {
    return json({error: 'access_unavailable'}, 503, method);
  }
  if (object === null || object === undefined) return json({error: 'not_found'}, 404, method);
  if (!Number.isSafeInteger(object.size) || object.size <= 0 ||
      object.size > MAX_OBJECT_BYTES ||
      (method !== 'HEAD' && (!object.body || typeof object.body.getReader !== 'function'))) {
    return json({error: 'access_unavailable'}, 503, method);
  }
  // R2 streams are length-bound by their own metadata. Do not set a
  // synthetic Content-Length on a streamed Worker Response.
  const headers = {...SECURITY, 'Content-Type': FILES[file]};
  return new Response(method === 'HEAD' ? null : object.body, {status: 200, headers});
}
async function handle(request, env, options = {}) {
  let url;
  try { url = new URL(request.url); }
  catch { return json({error: 'not_found'}, 404, request.method); }
  if (!canonical(url)) return json({error: 'not_found'}, 404, request.method);
  if (url.pathname === '/_shadowops/status' && (request.method === 'GET' || request.method === 'HEAD')) {
    return json({application: 'pawn-action', environment: 'staging',
      state: 'candidate_not_deployed', game_ready: false}, 200, request.method);
  }
  if (url.pathname === '/api/pawn-action/session') {
    return handleSessionExchange(request, env, options);
  }
  const file = fileForPath(url.pathname);
  if (!file) return json({error: 'not_found'}, 404, request.method);
  if (!['GET', 'HEAD'].includes(request.method)) {
    return json({error: 'method_not_allowed'}, 405, request.method);
  }
  try {
    await authorizeRequest(request, env, options);
  } catch (error) {
    const status = error instanceof IdentityDenied ? error.status : 503;
    return json({error: status === 401 ? 'authentication_required' : 'access_unavailable'}, status, request.method);
  }
  // Never accept partial transfers: every chunk must come through a newly
  // verified session. Godot's original nine-file export uses full fetches.
  if (request.headers.has('Range')) return json({error: 'range_not_supported'}, 416, request.method);
  return readPrivateAsset(env, file, request.method);
}
export default {fetch: handle};
