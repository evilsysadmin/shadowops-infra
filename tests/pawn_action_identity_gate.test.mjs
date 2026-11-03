import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {AUDIENCE, ISSUER, COOKIE, IdentityDenied, verifyIdentityToken, authorize, sessionToken, authorizeRequest} from '../workers/pawn-action-staging/identity-gate.mjs';
import worker from '../workers/pawn-action-staging/edge.mjs';
const lockedHandle = worker.fetch;
const HOST = 'staging.pawnaction.shadowops.dpdns.org';

const origin = 'https://' + HOST;
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
async function fixture() {
  const pair = await webcrypto.subtle.generateKey({name: 'Ed25519'}, true, ['sign', 'verify']);
  const jwk = {...await webcrypto.subtle.exportKey('jwk', pair.publicKey), kid: 'synthetic-ed25519',
    use: 'sig', alg: 'EdDSA'};
  const now = Math.floor(Date.now() / 1000);
  const claims = {iss: ISSUER, aud: AUDIENCE,
    sub: '11111111-1111-4111-8111-111111111111',
    iat: now, nbf: now, exp: now + 120, sv: 1,
    jti: Buffer.alloc(16, 4).toString('base64url')};
  const proof = 'soc1_' + Buffer.alloc(32, 7).toString('base64url');
  let active = true, lookup = 0, freshness = 0;
  async function sign(overrides = {}, header = {}) {
    const message = encode({alg: 'EdDSA', typ: 'JWT', kid: jwk.kid, ...header}) +
      '.' + encode({...claims, ...overrides});
    const signature = Buffer.from(await webcrypto.subtle.sign('Ed25519', pair.privateKey,
      Buffer.from(message))).toString('base64url');
    return message + '.' + signature;
  }
  async function request(url, init = {}) {
    if (url === ISSUER + '/api/identity/jwks') {
      lookup++;
      assert.equal(init.redirect, 'manual');
      return Response.json({keys: [jwk]});
    }
    if (url === ISSUER + '/api/identity/freshness') {
      freshness++;
      assert.equal(init.redirect, 'manual');
      assert.equal(init.headers.Authorization, 'Bearer ' + proof);
      const body = JSON.parse(init.body);
      if (!active) return new Response('', {status: 401});
      return Response.json({issuer: ISSUER, audience: AUDIENCE,
        subject: body.subject, session_version: body.session_version,
        token_jti: body.token_jti, checked_at: now,
        account_active: true, session_active: true, token_active: true});
    }
    throw Error('Untrusted endpoint invoked');
  }
  return {sign, claims, proof, jwk, request, subtle: webcrypto.subtle, now,
    revoke: () => {active = false;}, counters: () => ({lookup, freshness})};
}
const denied = async fn => assert.rejects(fn, error => error instanceof IdentityDenied);

test('valid Ed25519 JWT authorizes only with exact Pawn Action proof and transactional freshness', async () => {
  const f = await fixture(), token = await f.sign();
  const opts = {request: f.request, subtle: f.subtle, now: f.now};
  assert.equal((await verifyIdentityToken(token, opts)).aud, AUDIENCE);
  assert.equal((await authorize(token, {SHADOWOPS_PAWN_ACTION_SERVICE_CREDENTIAL: f.proof}, opts)).sub, f.claims.sub);
  assert.deepEqual(f.counters(), {lookup: 2, freshness: 1});
  await denied(() => authorize(token, {}, opts));
  assert.deepEqual(f.counters(), {lookup: 2, freshness: 1});
  f.revoke();
  await denied(() => authorize(token, {SHADOWOPS_PAWN_ACTION_SERVICE_CREDENTIAL: f.proof}, opts));
  assert.equal(f.counters().freshness, 2);
});

test('JWT cannot change issuer, audience, lifetime, subject, token registry or algorithm', async () => {
  const f = await fixture(), opts = {request: f.request, subtle: f.subtle, now: f.now};
  for (const claim of [{iss: 'https://id.shadowops.dpdns.org'}, {aud: 'football'},
    {aud: 'chronicles'}, {sub: 'admin'}, {sv: 0},
    {jti: 'forged'}, {exp: f.now}, {exp: f.now + 121}, {iat: f.now + 10},
    {nbf: f.now + 10}, {nbf: f.now - 10}]) {
    await denied(async () => verifyIdentityToken(await f.sign(claim), opts));
  }
  for (const header of [{alg: 'none'}, {alg: 'HS256'}, {kid: 'other'},
    {typ: 'not-JWT'}, {jku: 'https://evil.test/key'}, {crit: ['alg']}]) {
    await denied(async () => verifyIdentityToken(await f.sign({}, header), opts));
  }
  const valid = await f.sign(), parts = valid.split('.');
  const tampered = [...parts];
  tampered[1] = encode({...f.claims, sv: 9});
  await denied(() => verifyIdentityToken(tampered.join('.'), opts));
  for (const malformed of ['', 'header.body', valid + '.again', '%%%%',
    parts[0] + '.' + parts[1] + '.AA', valid + '=']) {
    await denied(() => verifyIdentityToken(malformed, opts));
  }
});

test('Identity JWKS unavailable, redirects, duplicate kid, private key and oversized response fail closed', async () => {
  const f = await fixture(), token = await f.sign();
  const cases = [
    () => new Response('', {status: 302, headers: {Location: 'https://evil.test'}}),
    () => new Response('', {status: 503}),
    () => Response.json({keys: [f.jwk, f.jwk]}),
    () => Response.json({keys: [{...f.jwk, d: 'private'}]}),
    () => Response.json({keys: Array(21).fill(f.jwk)}),
    () => Response.json({keys: [f.jwk], padding: 'x'.repeat(40000)}),
  ];
  for (const response of cases) {
    const opts = {request: async () => response(), subtle: f.subtle, now: f.now};
    await denied(() => verifyIdentityToken(token, opts));
  }
  await denied(() => verifyIdentityToken(token, {request: async () => {throw Error('secret');},
    subtle: f.subtle, now: f.now}));
});

test('wrong or stale live evidence, network failures and redirects deny signed JWT', async () => {
  const f = await fixture(), token = await f.sign(), env = {SHADOWOPS_PAWN_ACTION_SERVICE_CREDENTIAL: f.proof};
  const errors = [{issuer: 'https://id.shadowops.dpdns.org'}, {audience: 'football'},
    {subject: '22222222-2222-4222-8222-222222222222'}, {session_version: 2},
    {token_jti: 'wrong'}, {account_active: false}, {session_active: false},
    {token_active: false}, {checked_at: f.now - 6}, {checked_at: f.now + 6}];
  for (const wrong of errors) {
    await denied(() => authorize(token, env, {now: f.now, subtle: f.subtle,
      request: async (url, init) => {
        const response = await f.request(url, init);
        return url.endsWith('/freshness') ? Response.json({...await response.json(), ...wrong}) : response;
      }}));
  }
  await denied(() => authorize(token, env, {now: f.now, subtle: f.subtle,
    request: async (url, init) => url.endsWith('/jwks') ? f.request(url, init)
      : new Response('Moved', {status: 302})}));
  await denied(() => authorize(token, env, {now: f.now, subtle: f.subtle,
    request: async (url, init) => url.endsWith('/jwks') ? f.request(url, init)
      : new Response('', {status: 503})}));
});

test('session cookie is exact host-only name; duplicate, query, spoofed headers and wrong host rejected', async () => {
  const f = await fixture(), token = await f.sign(), env = {SHADOWOPS_PAWN_ACTION_SERVICE_CREDENTIAL: f.proof};
  const options = {request: f.request, subtle: f.subtle, now: f.now};
  const request = (url = origin + '/', cookie = COOKIE + '=' + token, init = {}) =>
    new Request(url, {headers: {Cookie: cookie, ...(init.headers || {})}, method: init.method || 'GET'});
  assert.equal(sessionToken(request()), token);
  assert.equal((await authorizeRequest(request(), env, options)).sub, f.claims.sub);
  for (const req of [
    request(origin + '/', COOKIE + '=' + token + '; ' + COOKIE + '=' + token),
    request(origin + '/?token=' + token),
    request('https://pawn-action-staging.pages.dev/'),
    request('https://staging.football.shadowops.dpdns.org/'),
    request('http://' + HOST + '/'),
    request(origin + '/', COOKIE + '=' + token, {method: 'POST'}),
    request(origin + '/', 'other=' + token, {headers: {Authorization: 'Bearer ' + token}}),
  ]) await denied(() => authorizeRequest(req, env, options));
});

test('native Worker default fetch retains global receiver; only Identity JWKS and freshness called', async () => {
  const f = await fixture(), token = await f.sign(), original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = function(url, init) {
    assert.equal(this, globalThis, 'workerd global fetch receiver must be retained');
    calls++;
    return f.request(url, init);
  };
  try {
    const claims = await authorize(token, {SHADOWOPS_PAWN_ACTION_SERVICE_CREDENTIAL: f.proof},
      {subtle: f.subtle, now: f.now});
    assert.equal(claims.sub, f.claims.sub);
    assert.equal(calls, 2);
  } finally { globalThis.fetch = original; }
});

test('locked Pages holding shell still denies a valid signed session; no asset reads or activation flag', async () => {
  const f = await fixture(), token = await f.sign();
  const env = {SHADOWOPS_PAWN_ACTION_SERVICE_CREDENTIAL: f.proof, PAWN_ACTION_STAGING_ENABLED: 'true',
    ASSETS: {fetch() {throw Error('Never serve an asset before separate rollout');}}};
  const req = new Request(origin + '/', {headers: {Cookie: COOKIE + '=' + token}});
  const response = lockedHandle(req, env);
  assert.equal(response.status, 503);
  assert.match(await response.text(), /El juego aún no se ha publicado/);
  assert.equal(lockedHandle(new Request(origin + '/index.wasm'), env).status, 503);
});
