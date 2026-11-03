// Pawn Action staging-only identity verifier, NOT yet connected to Pages delivery.
// Session exchange, deployment and gameplay are intentionally gated in later PRs.
// No signing seed, JWT or service proof is stored client-side or logged.
export const ISSUER = 'https://id-staging.shadowops.dpdns.org';
export const AUDIENCE = 'pawn-action';
export const COOKIE = '__Host-pawnaction_staging';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const JTI = /^[A-Za-z0-9_-]{22}$/;
const PROOF = /^soc1_[A-Za-z0-9_-]{43}$/;
const B64 = /^[A-Za-z0-9_-]+$/;
const NOW_SKEW = 5;
const MAX_TOKEN = 8192;
const publicRequest = (...args) => globalThis.fetch(...args); // workerd receiver is mandatory

export class IdentityDenied extends Error {
  constructor(status = 401, stage = 'session') {
    super('Pawn Action staging Identity unavailable');
    this.name = 'IdentityDenied';
    this.status = status;
    this.stage = stage; // fixed diagnostic category; never contain secrets
  }
}
function denied(condition) { if (condition) throw new IdentityDenied(); }
function jsonSegment(segment, maxBytes = 4096) {
  denied(typeof segment !== 'string' || segment.length > maxBytes * 2 ||
    !B64.test(segment) || segment.length % 4 === 1);
  try {
    const binary = atob(segment.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    denied(bytes.length > maxBytes);
    const canonical = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    denied(canonical !== segment);
    return bytes;
  } catch { throw new IdentityDenied(); }
}
function parseObject(bytes) {
  try {
    const obj = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
    denied(!obj || typeof obj !== 'object' || Array.isArray(obj));
    return obj;
  } catch { throw new IdentityDenied(); }
}
function clock() { return Math.floor(Date.now() / 1000); }
async function responseJSON(response, limit) {
  if (!response || response.ok !== true || !response.body?.getReader) {
    throw new IdentityDenied(503, 'identity_transport');
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', {fatal: true});
  let bytes = 0, body = '';
  try {
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > limit) {
        await reader.cancel();
        throw new IdentityDenied(503, 'identity_transport');
      }
      body += decoder.decode(value, {stream: true});
    }
    body += decoder.decode();
    const obj = JSON.parse(body);
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
      throw new IdentityDenied(503, 'identity_transport');
    }
    return obj;
  } catch {
    throw new IdentityDenied(503, 'identity_transport');
  } finally {
    try { reader.releaseLock(); } catch {}
  }
}
async function fetchJSON(request, endpoint, init, stage, size) {
  try {
    const response = await request(ISSUER + endpoint, {
      ...init, redirect: 'manual', signal: AbortSignal.timeout(5000),
    });
    if (!response?.ok) throw new IdentityDenied(response?.status === 401 ? 401 : 503, stage);
    return await responseJSON(response, size);
  } catch (error) {
    if (error instanceof IdentityDenied && error.stage === stage) throw error;
    throw new IdentityDenied(503, stage);
  }
}

// Verify signed, short-lived JWT from the REAL staging issuer only.
// This verifies cryptographic provenance, NOT a live session: use authorize().
export async function verifyIdentityToken(token, {
  request = publicRequest, subtle = crypto.subtle, now = clock(),
} = {}) {
  denied(typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN);
  const parts = token.split('.');
  denied(parts.length !== 3);
  const header = parseObject(jsonSegment(parts[0], 1024));
  const claims = parseObject(jsonSegment(parts[1], 4096));
  const signature = jsonSegment(parts[2], 128);
  denied(signature.byteLength !== 64);
  // The Go issuer signs precisely alg/typ/kid. Never honor URL/key hints.
  denied(Object.keys(header).length !== 3 || header.alg !== 'EdDSA' ||
    header.typ !== 'JWT' || typeof header.kid !== 'string' ||
    header.kid.length === 0 || header.kid.length > 128);
  denied(claims.iss !== ISSUER || claims.aud !== AUDIENCE || !UUID.test(claims.sub) ||
    !Number.isSafeInteger(claims.sv) || claims.sv <= 0 ||
    !JTI.test(claims.jti) ||
    ![claims.iat, claims.nbf, claims.exp].every(Number.isSafeInteger) ||
    claims.iat > now + NOW_SKEW || claims.nbf > now + NOW_SKEW ||
    claims.nbf < claims.iat - NOW_SKEW ||
    claims.exp <= now || claims.exp <= claims.iat ||
    claims.exp - claims.iat > 120);
  const jwks = await fetchJSON(request, '/api/identity/jwks', {
    headers: {Accept: 'application/json', 'User-Agent': 'ShadowOps-PawnAction-Edge/1'},
  }, 'identity_keys', 32768);
  if (!Array.isArray(jwks.keys) || jwks.keys.length < 1 || jwks.keys.length > 20) {
    throw new IdentityDenied(503, 'identity_keys');
  }
  const matching = jwks.keys.filter(key => key && typeof key === 'object' &&
    !Array.isArray(key) && key.kid === header.kid);
  denied(matching.length !== 1);
  const key = matching[0];
  denied(key.kty !== 'OKP' || key.crv !== 'Ed25519' || key.use !== 'sig' ||
    key.d !== undefined || typeof key.x !== 'string' ||
    (key.alg !== undefined && key.alg !== 'EdDSA'));
  try {
    const publicKey = await subtle.importKey('jwk', key, {name: 'Ed25519'}, false, ['verify']);
    const signed = new TextEncoder().encode(parts[0] + '.' + parts[1]);
    denied(!(await subtle.verify({name: 'Ed25519'}, publicKey, signature, signed)));
  } catch { throw new IdentityDenied(); }
  return claims;
}

// This must be invoked for EVERY protected request, not once per login:
// live transactional freshness fences account, session and exact JTI.
export async function authorize(token, env, options = {}) {
  const proof = env?.SHADOWOPS_PAWN_ACTION_SERVICE_CREDENTIAL;
  if (typeof proof !== 'string' || !PROOF.test(proof)) {
    throw new IdentityDenied(503, 'edge_configuration');
  }
  const now = options.now ?? clock();
  const request = options.request ?? publicRequest;
  const claims = await verifyIdentityToken(token, {...options, now, request});
  const live = await fetchJSON(request, '/api/identity/freshness', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + proof,
      'User-Agent': 'ShadowOps-PawnAction-Edge/1'},
    body: JSON.stringify({subject: claims.sub, session_version: claims.sv, token_jti: claims.jti}),
  }, 'identity_freshness', 8192);
  denied(live.issuer !== ISSUER || live.audience !== AUDIENCE ||
    live.subject !== claims.sub || live.session_version !== claims.sv ||
    live.token_jti !== claims.jti ||
    live.account_active !== true || live.session_active !== true || live.token_active !== true ||
    !Number.isSafeInteger(live.checked_at) || live.checked_at > now + NOW_SKEW ||
    now - live.checked_at > NOW_SKEW || claims.exp <= clock());
  return claims;
}

export function sessionToken(request) {
  // Cookies are host-only, HttpOnly and Secure when the future exchange is implemented.
  // Never accept URL params, Authorization or CF-Access headers as a substitute.
  const raw = request.headers.get('Cookie') || '';
  const matched = raw.split(';').map(s => s.trim()).filter(s => s.startsWith(COOKIE + '='));
  denied(matched.length !== 1 || matched[0].length > MAX_TOKEN + COOKIE.length + 1);
  const token = matched[0].slice(COOKIE.length + 1);
  denied(token.length === 0 || token.length > MAX_TOKEN);
  return token;
}

export async function authorizeRequest(request, env, options = {}) {
  const url = new URL(request.url);
  denied(url.protocol !== 'https:' || url.hostname !== 'staging.pawnaction.shadowops.dpdns.org' ||
    !!url.port || !!url.search || !['GET', 'HEAD'].includes(request.method));
  return authorize(sessionToken(request), env, options);
}
