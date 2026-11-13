import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SNOOKER_ORIGIN, IDENTITY_ORIGIN, LOGIN_URL, RETURN_URL,
  GUEST_DENIED_PATHS, assertGuestStatus, assertLoginReturnUrl,
  assertNoPrivilegedCookies } from '../scripts/snooker_guest_browser_contract.mjs';

test('guest/browser checks pin both real staging hosts and a single Snooker return', () => {
  assert.equal(SNOOKER_ORIGIN, 'https://staging.snooker.shadowops.dpdns.org');
  assert.equal(IDENTITY_ORIGIN, 'https://id-staging.shadowops.dpdns.org');
  assert.equal(LOGIN_URL, IDENTITY_ORIGIN + '/login?app=snooker');
  assert.equal(RETURN_URL, SNOOKER_ORIGIN + '/?shadowops=central');
  assert.doesNotThrow(() => assertLoginReturnUrl(RETURN_URL));
  for (const value of [
    IDENTITY_ORIGIN + '/login?app=football',
    SNOOKER_ORIGIN + '/?shadowops=central&token=hello',
    SNOOKER_ORIGIN.replace('staging.snooker', 'evil.snooker') + '/?shadowops=central',
    SNOOKER_ORIGIN + '/?shadowops=central#extra',
  ]) assert.throws(() => assertLoginReturnUrl(value), /RETURN_URL_FAILED/);
});
test('all guest private routes deny access with real 401; 200 is never green', () => {
  assert.ok(GUEST_DENIED_PATHS.length >= 5);
  for (const path of GUEST_DENIED_PATHS) {
    assert.doesNotThrow(() => assertGuestStatus(path, 401));
    for (const status of [200, 301, 302, 403, 404, 503]) {
      assert.throws(() => assertGuestStatus(path, status), /DENIAL_FAILED/);
    }
  }
  assert.throws(() => assertGuestStatus('/_shadowops/session.js', 401), /DENIAL_FAILED/);
});
test('guest cookies never include Edge or central Identity browser sessions', () => {
  assert.doesNotThrow(() => assertNoPrivilegedCookies([]));
  assert.doesNotThrow(() => assertNoPrivilegedCookies([{ name: 'anonymous-preference' }]));
  for (const name of ['__Host-snooker_staging', '__Host-shadowops_sso_staging']) {
    assert.throws(() => assertNoPrivilegedCookies([{ name }]), /COOKIE_LEAK/);
  }
  assert.throws(() => assertNoPrivilegedCookies(null), /COOKIE_LEAK/);
});
test('live browser uses no synthetic authentication or cloud write authority', () => {
  const workflow = readFileSync('.github/workflows/snooker-guest-browser-journey.yml', 'utf8');
  const browser = readFileSync('scripts/snooker_guest_browser_journey.mjs', 'utf8');
  assert.match(workflow, /schedule:/);
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /actions\/checkout@v4/);
  assert.match(workflow, /npm ci --prefix snooker-source --ignore-scripts/);
  assert.doesNotMatch(workflow, /secrets\.|actions: write|environment:\s+name: staging|wrangler/);
  assert.match(browser, /page\.goto\(SNOOKER_ORIGIN/);
  assert.match(browser, /login\.click\(\)/);
  assert.match(browser, /Volver a Snooker of Matthias/);
  assert.match(browser, /GUEST_DENIED_PATHS/);
  assert.doesNotMatch(browser, /page\.route\(|addCookies\(|setExtraHTTPHeaders\(|ignoreHTTPSErrors|api\/identity\/register/);
  assert.doesNotMatch(browser, /SNOOKER_E2E_PASSWORD|SNOOKER_E2E_USERNAME/);
});
