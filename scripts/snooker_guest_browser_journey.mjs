// Live, read-only Chromium guest-to-Identity-to-guest journey against real
// Cloudflare Pages and the real staging login. NO credentials or route mocks.
// It proves that the untrusted browser sees no game/cookie/manifest, that
// central login is reachable and return navigation stays pinned to Snooker.
import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { SNOOKER_ORIGIN, IDENTITY_ORIGIN, LOGIN_URL, RETURN_URL,
  GUEST_DENIED_PATHS, assertGuestStatus, assertLoginReturnUrl,
  assertNoPrivilegedCookies } from './snooker_guest_browser_contract.mjs';

const gameRequire = createRequire(new URL('../snooker-source/package.json', import.meta.url));
const { chromium } = gameRequire('@playwright/test');
mkdirSync('artifacts', { recursive: true });
const browser = await chromium.launch({ headless: true });
try {
  for (const config of [
    { name: 'desktop', viewport: { width: 1440, height: 900 }, isMobile: false, hasTouch: false },
    { name: 'mobile', viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true },
  ]) {
    const context = await browser.newContext({
      viewport: config.viewport, deviceScaleFactor: 1,
      isMobile: config.isMobile, hasTouch: config.hasTouch,
    });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.name));
    try {
      assertNoPrivilegedCookies(await context.cookies());
      const guest = await page.goto(SNOOKER_ORIGIN + '/', {
        waitUntil: 'domcontentloaded', timeout: 30000,
      });
      assertGuestStatus('/', guest?.status());
      const login = page.getByRole('link', { name: 'Entrar con ShadowOps ID' });
      await login.waitFor({ state: 'visible', timeout: 15000 });
      assert.equal(await login.getAttribute('href'), LOGIN_URL);
      assert.equal(await page.locator('#viewport canvas').count(), 0);
      assert.equal(await page.locator('#app').count(), 0);
      await page.waitForFunction(() => {
        const status = document.querySelector('[role="status"]')?.textContent || '';
        return status.includes('Entra con tu cuenta de ShadowOps ID para jugar.') ||
          status.includes('El acceso con ShadowOps ID aún no está disponible.');
      }, null, { timeout: 18000 });
      assert.match(await page.locator('[role="status"]').innerText(),
        /Entra con tu cuenta de ShadowOps ID para jugar/,
        'Identity token endpoint must return a normal anonymous 401, not an outage');
      for (const path of GUEST_DENIED_PATHS) {
        const response = await context.request.get(SNOOKER_ORIGIN + path, {
          failOnStatusCode: false, timeout: 12000,
        });
        assertGuestStatus(path, response.status());
      }
      // Screenshots show the PUBLIC guest shell only, never the login form,
      // credentials, JWT, cookies, subject or authenticated session.
      await page.screenshot({
        path: 'artifacts/snooker-guest-' + config.name + '.png',
        fullPage: true, animations: 'disabled',
      });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
        config.name + ' guest login shell must fit the viewport');
      assertNoPrivilegedCookies(await context.cookies());

      await login.click();
      await page.waitForURL(url => url.origin === IDENTITY_ORIGIN, { timeout: 20000 });
      await page.getByRole('heading', { name: 'Una cuenta para tus proyectos' })
        .waitFor({ state: 'visible', timeout: 15000 });
      assertLoginReturnUrl(await page.locator('body').getAttribute('data-return-url'));
      assert.ok(await page.getByLabel('Usuario ShadowOps').isVisible());
      assert.ok(await page.getByLabel('Contraseña', { exact: true }).isVisible());
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
        config.name + ' real Identity login must fit the viewport');
      assertNoPrivilegedCookies(await context.cookies());
      await page.getByRole('link', { name: 'Volver a Snooker of Matthias' }).click();
      await page.waitForURL(url => url.origin === SNOOKER_ORIGIN, { timeout: 20000 });
      assert.equal(new URL(page.url()).search, new URL(RETURN_URL).search);
      await page.getByRole('link', { name: 'Entrar con ShadowOps ID' }).waitFor();
      assert.equal(await page.locator('#viewport canvas').count(), 0);
      assertNoPrivilegedCookies(await context.cookies());
      assert.deepEqual(errors, [], 'Browser JavaScript errors in public guest/login journey');
      console.log('SNOOKER_LIVE_GUEST_BROWSER_PASS viewport=' + config.name +
        ' host=private identity=reachable guest_assets=denied');
    } finally {
      await context.close();
    }
  }
} finally {
  await browser.close();
}
