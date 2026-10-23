import test from 'node:test';
import assert from 'node:assert/strict';
import { BASE, validateRelease } from '../scripts/staradvs_public_browser_smoke.mjs';

const SHA = 'a'.repeat(40);
const JS_HASH = 'b'.repeat(64);
const valid = () => ({
  build: SHA, environment: 'staging',
  entry_js: { path: '/assets/index-4bc2f0.js', sha256: JS_HASH },
});

test('release manifest admits one exact staging SHA with a local entrypoint hash', () => {
  assert.equal(BASE, 'https://staging.staradvs.shadowops.dpdns.org');
  assert.deepEqual(validateRelease(valid()), valid());
});

test('refuse malformed or mutable release identity', () => {
  for (const build of ['main', 'A'.repeat(40), 'f'.repeat(39), '', null]) {
    const m = valid();
    m.build = build;
    assert.throws(() => validateRelease(m));
  }
  const wrongEnv = { ...valid(), environment: 'production' };
  assert.throws(() => validateRelease(wrongEnv));
});

test('refuse third-party, traversal, missing and ambiguous JS asset provenance', () => {
  for (const path of [
    'https://foreign.test/index.js',
    '//evil.example/assets/index.js',
    '/assets/../admin.js',
    '/script.js',
    '/assets/index.js?cache=1',
    '/assets/index.js/other',
    null,
  ]) {
    const manifest = valid();
    manifest.entry_js.path = path;
    assert.throws(() => validateRelease(manifest));
  }
  const missing = valid();
  delete missing.entry_js;
  assert.throws(() => validateRelease(missing));
});

test('refuse absent or syntactically invalid JS digests', () => {
  for (const digest of [null, '', 'b'.repeat(63), 'B'.repeat(64), 'x'.repeat(64)]) {
    const m = valid();
    m.entry_js.sha256 = digest;
    assert.throws(() => validateRelease(m));
  }
});
