import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SNOOKER_ORIGIN, IDENTITY_ORIGIN, requireLiveBrowser,
  assertAuthenticatedSession, assertRelease } from '../scripts/snooker_live_browser_contract.mjs';

const sha = 'a'.repeat(40);
const valid = {
  SNOOKER_LIVE_BROWSER: '1', SNOOKER_SOURCE_SHA: sha,
  SNOOKER_E2E_USERNAME: 'snooker_e2e', SNOOKER_E2E_PASSWORD: 'dedicated-test-only-password-2026',
};

test('exact staging origins and explicit test account are mandatory', () => {
  assert.equal(SNOOKER_ORIGIN, 'https://staging.snooker.shadowops.dpdns.org');
  assert.equal(IDENTITY_ORIGIN, 'https://id-staging.shadowops.dpdns.org');
  assert.deepEqual(requireLiveBrowser(valid), { sha });
  for (const [key, invalid] of [
    ['SNOOKER_LIVE_BROWSER', '0'], ['SNOOKER_SOURCE_SHA', 'main'],
    ['SNOOKER_SOURCE_SHA', 'A'.repeat(40)],
    ['SNOOKER_E2E_USERNAME', ''],
    ['SNOOKER_E2E_USERNAME', 'bad/name'],
    ['SNOOKER_E2E_PASSWORD', 'short'],
  ]) assert.throws(() => requireLiveBrowser({ ...valid, [key]: invalid }), /BLOCKED/);
});

test('only exact private build and correct authentication contract are accepted', () => {
  const release = { schema: 1, application: 'snooker-of-matthias',
    environment: 'staging', source_sha: sha,
    authentication: { provider: 'shadowops-id', audience: 'snooker', required: true } };
  assert.doesNotThrow(() => assertRelease(release, sha));
  for (const [key, value] of [
    ['source_sha', 'b'.repeat(40)], ['environment', 'production'],
    ['application', 'other'], ['schema', 2],
  ]) assert.throws(() => assertRelease({ ...release, [key]: value }, sha));
  assert.throws(() => assertRelease({ ...release, authentication:
    { ...release.authentication, required: false } }, sha));
});

test('signed-in session must have server-provided UUID and unexpired edge token', () => {
  const session = { identity: 'snooker',
    subject: '123e4567-e89b-42d3-a456-426614174000',
    expires_at: Math.floor(Date.now() / 1000) + 60 };
  assert.doesNotThrow(() => assertAuthenticatedSession(session));
  for (const changed of [
    { subject: 'synthetic' }, { identity: 'football' },
    { expires_at: 123 }, { expires_at: 0 },
  ]) assert.throws(() => assertAuthenticatedSession({ ...session, ...changed }));
});

test('workflow gates actual remote play behind protected manual staging approval', () => {
  const yml = readFileSync('.github/workflows/snooker-live-browser-journey.yml', 'utf8');
  const browser = readFileSync('scripts/snooker_live_browser_journey.mjs', 'utf8');
  assert.match(yml, /workflow_dispatch:/);
  assert.match(yml, /github.event_name == 'workflow_dispatch'/);
  assert.match(yml, /environment:\s+name: staging/);
  assert.match(yml, /secrets.SNOOKER_E2E_USERNAME/);
  assert.match(yml, /secrets.SNOOKER_E2E_PASSWORD/);
  assert.match(yml, /snooker_staging_publish.py smoke-audit/);
  assert.match(yml, /snooker_staging_publish.py release-audit/);
  assert.match(yml, /repository: evilsysadmin\/snooker-of-matthias/);
  assert.match(yml, /ref: \$\{\{ steps.source.outputs.sha \}\}/);
  assert.match(yml, /npm ci --prefix snooker-source --ignore-scripts/);
  assert.doesNotMatch(yml, /wrangler pages deploy|register|cloudflare pages deploy/);
  assert.match(browser, /getByRole\('button', \{ name: 'Entrar y continuar' \}\)/);
  assert.match(browser, /getByLabel\('Usuario ShadowOps'\)/);
  assert.match(browser, /screenshotShowsFelt/);
  assert.match(browser, /api\/identity\/logout/);
  assert.match(browser, /api\/snooker\/logout/);
  assert.doesNotMatch(browser, /page\.route\(|ignoreHTTPSErrors|addCookies\(|setExtraHTTPHeaders\(/);
});
