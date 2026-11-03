// Pawn Action staging holding edge: fail closed until ShadowOps ID consumer exists.
// No cookie, JWT, spoofed header or environment flag can enable gameplay.
const HOST = 'staging.pawnaction.shadowops.dpdns.org';
const HEADERS = {
  'Cache-Control': 'no-store, max-age=0',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};
const STATUS = JSON.stringify({application: 'pawn-action', environment: 'staging', state: 'locked', game_ready: false});
const PAGE = [
  '<!doctype html><html lang="es"><meta charset="utf-8">',
  '<meta name="viewport" content="width=device-width,initial-scale=1">',
  '<title>Pawn Action · Staging protegido</title>',
  '<body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#091017;color:#f5ecd7;font:18px system-ui">',
  '<main style="max-width:36rem;padding:2rem"><h1>Pawn Action</h1>',
  '<p>Staging protegido mientras se valida ShadowOps ID.</p>',
  '<p>El juego aún no se ha publicado en este dominio.</p></main></body></html>',
].join('');
function respond(body, status, contentType, method) {
  return new Response(method === 'HEAD' ? null : body,
    {status, headers: {...HEADERS, 'Content-Type': contentType}});
}
function handle(request, _env) {
  let url;
  try { url = new URL(request.url); }
  catch { return respond('Not found', 404, 'text/plain; charset=utf-8', request.method); }
  if (url.protocol !== 'https:' || url.hostname !== HOST || url.port || url.username || url.password) {
    return respond('Not found', 404, 'text/plain; charset=utf-8', request.method);
  }
  if (url.pathname === '/_shadowops/status' && !url.search && ['GET', 'HEAD'].includes(request.method)) {
    return respond(STATUS, 200, 'application/json; charset=utf-8', request.method);
  }
  if (['/', '/index.html'].includes(url.pathname) && !url.search && ['GET', 'HEAD'].includes(request.method)) {
    return respond(PAGE, 503, 'text/html; charset=utf-8', request.method);
  }
  // Intentionally NEVER forward to static assets, even when an environment variable suggests activation.
  return respond('{"error":"staging_locked"}', 503, 'application/json; charset=utf-8', request.method);
}
export default {fetch: handle};
