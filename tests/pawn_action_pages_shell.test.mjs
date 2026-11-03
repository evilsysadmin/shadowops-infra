import test from 'node:test';
import assert from 'node:assert/strict';
import {handle, HOST} from '../workers/pawn-action-staging/edge.mjs';
const origin = 'https://' + HOST;
const env = {ASSETS: {fetch() { throw Error('Static game asset leak'); }},
  PAWN_ACTION_STAGING_ENABLED: 'true',
  AUTH_BYPASS: 'true',
  SHADOWOPS_PAWN_ACTION_SERVICE_CREDENTIAL: 'soc1_fake'};

test('the canonical status endpoint always reports locked and cannot expose game', async () => {
  const r = handle(new Request(origin + '/_shadowops/status'), env);
  assert.equal(r.status, 200);
  assert.deepEqual(await r.json(), {application: 'pawn-action', environment: 'staging',
    state: 'locked', game_ready: false});
  assert.equal(r.headers.get('Cache-Control'), 'no-store, max-age=0');
  assert.equal(handle(new Request(origin + '/_shadowops/status?token=spoof'), env).status, 503);
});

test('wrong-host and Pages aliases never become valid alternate hosts', async () => {
  for (const url of ['https://pawn-action-staging.pages.dev/',
      'https://staging.football.shadowops.dpdns.org/',
      'http://' + HOST + '/', origin + ':8443/']) {
    assert.equal(handle(new Request(url), env).status, 404, url);
  }
});

test('root remains locked regardless of token, cookies, spoofed access headers or config', async () => {
  for (const headers of [{}, {Authorization: 'Bearer forged'},
       {Cookie: '__Host-pawnaction_staging=signed'},
       {'CF-Access-Jwt-Assertion': 'fake'}]) {
    const r = handle(new Request(origin + '/', {headers}), env);
    assert.equal(r.status, 503);
    assert.match(await r.text(), /El juego aún no se ha publicado/);
    assert.equal(r.headers.get('X-Frame-Options'), 'DENY');
    assert.match(r.headers.get('Content-Security-Policy'), /frame-ancestors 'none'/);
  }
});

test('all Web exports, R2 pointers, API paths and mutations denied without static fetch', async () => {
  for (const path of ['/index.wasm', '/index.pck', '/index.js', '/_worker.js',
      '/release.json', '/pawn-action/current.json', '/pawn-slug-godot/current.json',
      '/api/pawn-action/session', '/../../index.wasm']) {
    const r = handle(new Request(origin + path), env);
    assert.equal(r.status, 503, path);
    assert.deepEqual(await r.json(), {error: 'staging_locked'});
  }
  for (const method of ['POST', 'PUT', 'DELETE']) {
    assert.equal(handle(new Request(origin + '/', {method}), env).status, 503);
  }
  const head = handle(new Request(origin + '/index.wasm', {method: 'HEAD'}), env);
  assert.equal(head.status, 503);
  assert.equal(await head.text(), '');
});
