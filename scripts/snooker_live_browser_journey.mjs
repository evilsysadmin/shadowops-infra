// REAL remote browser E2E against protected Cloudflare Pages and Identity.
// No route mocks, no token injection, no TLS override, no account creation.
// Runs only via manual staging-approved GitHub workflow with dedicated account.
import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { SNOOKER_ORIGIN, IDENTITY_ORIGIN, requireLiveBrowser,
  assertRelease, assertAuthenticatedSession } from './snooker_live_browser_contract.mjs';

const { sha } = requireLiveBrowser(process.env);
const gameRequire = createRequire(new URL('../snooker-source/package.json', import.meta.url));
const { chromium } = gameRequire('@playwright/test');
const { screenshotShowsFelt } = await import('../snooker-source/e2e/pngFeltProbe.mjs');
const username = process.env.SNOOKER_E2E_USERNAME;
const password = process.env.SNOOKER_E2E_PASSWORD;
mkdirSync('artifacts', { recursive: true });
const browser = await chromium.launch({
  headless: true,
  args: ['--enable-webgl', '--use-angle=swiftshader', '--enable-unsafe-swiftshader'],
});

async function readSession(page) {
  const data = await page.evaluate(async () => {
    const response = await fetch('/api/snooker/session', {
      credentials: 'same-origin', cache: 'no-store',
    });
    if (response.status !== 200) throw new Error('No authenticated Snooker edge session');
    return response.json();
  });
  assertAuthenticatedSession(data);
}

async function verifyRelease(page) {
  const release = await page.evaluate(async () => {
    const response = await fetch('/release.json', { credentials: 'same-origin', cache: 'no-store' });
    if (response.status !== 200) throw new Error('Release manifest not authenticated');
    return response.json();
  });
  assertRelease(release, sha);
}

async function verifyWebGL(page, label) {
  const canvas = page.locator('#viewport canvas');
  await canvas.waitFor({ state: 'visible', timeout: 30000 });
  // Require a real rasterized frame, not only WebGL initialization flags.
  await page.waitForTimeout(650);
  const rect = await canvas.boundingBox();
  assert.ok(rect && rect.width > 250 && rect.height > 300,
    'Real WebGL playing field must have useful visible dimensions');
  const png = await page.screenshot({
    path: 'artifacts/snooker-live-' + label + '.png',
    fullPage: true, animations: 'disabled',
  });
  assert.ok(screenshotShowsFelt(png, rect),
    'Real protected Pages WebGL felt must be visible in PNG pixels');
}

async function revokeAndLogout(page) {
  // Revocation happens at central Identity first, while the Snooker JWT and
  // HttpOnly edge cookie still exist. This must deny *existing* asset access.
  const identityLogout = await page.evaluate(async issuer => {
    const response = await fetch(issuer + '/api/identity/logout', {
      method: 'POST', credentials: 'include', cache: 'no-store',
      headers: { 'Content-Type': 'application/json' }, body: '{}',
    });
    return response.status;
  }, IDENTITY_ORIGIN);
  assert.equal(identityLogout, 204, 'Central Identity must revoke the actual session');
  const denied = await page.evaluate(async () => ({
    session: (await fetch('/api/snooker/session', { credentials: 'same-origin', cache: 'no-store' })).status,
    manifest: (await fetch('/release.json', { credentials: 'same-origin', cache: 'no-store' })).status,
  }));
  assert.deepEqual(denied, { session: 401, manifest: 401 },
    'Live Identity revocation must deny a still-present product cookie');
  const localLogout = await page.evaluate(async () =>
    (await fetch('/api/snooker/logout', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
    })).status);
  assert.equal(localLogout, 200, 'Edge logout must clear the product session');
  await page.reload({ waitUntil: 'domcontentloaded' });
  await page.getByRole('link', { name: 'Entrar con ShadowOps ID' }).waitFor();
  assert.equal(await page.locator('#viewport canvas').count(), 0,
    'Anonymous user must never see the WebGL game after logout');
  assert.equal(await page.evaluate(async () =>
    (await fetch('/release.json', { credentials: 'same-origin', cache: 'no-store' })).status), 401);
}

async function playViewport(label, viewport) {
  const context = await browser.newContext({
    viewport, deviceScaleFactor: 1, isMobile: label === 'mobile',
    hasTouch: label === 'mobile',
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.name));
  try {
    // Confirm the real guest shell is present before opening central login.
    await page.goto(SNOOKER_ORIGIN + '/', { waitUntil: 'domcontentloaded' });
    await page.getByRole('link', { name: 'Entrar con ShadowOps ID' }).waitFor();
    assert.equal(await page.locator('#viewport canvas').count(), 0);
    await page.goto(IDENTITY_ORIGIN + '/login?app=snooker', { waitUntil: 'domcontentloaded' });
    await page.getByRole('heading', { name: 'Una cuenta para tus proyectos' }).waitFor();
    await page.getByLabel('Usuario ShadowOps').fill(username);
    await page.getByLabel('Contraseña', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Entrar y continuar' }).click();
    await page.waitForURL(u => u.origin === SNOOKER_ORIGIN, { timeout: 30000 });
    await page.locator('#viewport canvas').waitFor({ state: 'visible', timeout: 30000 });
    await readSession(page);
    await verifyRelease(page);
    assert.equal(await page.locator('#shots').innerText(), '00');
    assert.match(await page.locator('#potted').innerText(), /15 en mesa/);
    await verifyWebGL(page, label + '-signed-in');

    const strike = page.locator('#strike');
    if (label === 'mobile') await strike.tap();
    else await strike.click();
    await page.waitForFunction(() => document.querySelector('#shots')?.textContent === '01',
      null, { timeout: 20000 });
    assert.equal(await page.locator('#shots').innerText(), '01');
    await verifyWebGL(page, label + '-stroke');

    // The POC intentionally reracks on F5: verify that authentication and the
    // WebGL renderer survive, without inventing unsaved game continuity.
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.locator('#viewport canvas').waitFor({ state: 'visible', timeout: 30000 });
    await readSession(page);
    await verifyRelease(page);
    assert.equal(await page.locator('#shots').innerText(), '00');
    assert.match(await page.locator('#potted').innerText(), /15 en mesa/);
    await verifyWebGL(page, label + '-reload');

    await revokeAndLogout(page);
    assert.deepEqual(errors, [], 'Real authenticated browser JS errors');
    console.log('SNOOKER_LIVE_AUTH_BROWSER_PASS viewport=' + label + ' source=' + sha.slice(0, 12));
  } finally {
    // Best-effort cleanup on any assertion/timeout: do not intentionally
    // leave the dedicated test account logged in on a failed runner.
    try {
      if (page.url().startsWith(SNOOKER_ORIGIN)) {
        await page.evaluate(async issuer => {
          await fetch(issuer + '/api/identity/logout', { method: 'POST',
            credentials: 'include', headers: { 'Content-Type': 'application/json' },
            body: '{}' }).catch(() => {});
          await fetch('/api/snooker/logout', { method: 'POST', credentials: 'same-origin' })
            .catch(() => {});
        }, IDENTITY_ORIGIN);
      }
    } catch { /* already revoked or navigated away */ }
    await context.close();
  }
}
try {
  await playViewport('desktop', { width: 1440, height: 900 });
  await playViewport('mobile', { width: 390, height: 844 });
} finally {
  await browser.close();
}
