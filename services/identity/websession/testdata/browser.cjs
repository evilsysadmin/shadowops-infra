const { chromium } = require('playwright');
const { createPublicKey, verify } = require('node:crypto');
const { mkdir } = require('node:fs/promises');
const path = require('node:path');

const identity = 'https://id-staging.shadowops.dpdns.org';
const origins = {
  chronicles: 'https://staging.chronicles.shadowops.dpdns.org',
  'chess-studio': 'https://staging.chess-studio.shadowops.dpdns.org',
  'cka-simulator': 'https://staging.cka.shadowops.dpdns.org',
};
const check = (condition, message) => { if (!condition) throw new Error(message); };
let browser;
(async () => {
  browser = await chromium.launch({
    headless: true,
    executablePath: process.env.IDENTITY_BROWSER_EXECUTABLE || undefined,
    args: ['--no-proxy-server', `--host-resolver-rules=${[identity, ...Object.values(origins)].map(origin => `MAP ${new URL(origin).hostname} 127.0.0.1:19443`).join(', ')}`],
  });
  const artifacts = process.env.IDENTITY_BROWSER_ARTIFACTS;
  if (artifacts) await mkdir(artifacts, { recursive: true });
  for (const [name, viewport] of [['desktop', { width: 1440, height: 900 }], ['mobile', { width: 390, height: 844 }]]) {
    const context = await browser.newContext({ viewport, ignoreHTTPSErrors: true, isMobile: name === 'mobile', hasTouch: name === 'mobile' });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(`${identity}/login?app=chronicles`);
    await page.getByRole('heading', { name: 'Una cuenta para tus proyectos' }).waitFor();
    check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'login overflows viewport');
    if (artifacts) await page.screenshot({ path: path.join(artifacts, `identity-login-${name}.png`), fullPage: true });
    await page.getByRole('button', { name: 'Crear cuenta', exact: true }).click();
    if (artifacts) await page.screenshot({ path: path.join(artifacts, `identity-register-${name}.png`), fullPage: true });
    const username = `browser_${name}`;
    let password = 'synthetic-browser-password-2026';
    await page.getByLabel('Usuario ShadowOps').fill(username);
    await page.getByLabel('Contraseña nueva', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Crear mi cuenta ShadowOps', exact: true }).click();
    await page.locator('#backup').waitFor({ state: 'visible' });
    let recovery = await page.locator('#backup-code').textContent();
    check(/^sor1_[A-Za-z0-9_-]{43}$/.test(recovery), 'registration did not show a recovery secret');
    await page.getByRole('button', { name: 'Lo he guardado. Iniciar sesión' }).click();
    await page.getByLabel('Contraseña', { exact: true }).fill(password);
    const jwks = await page.evaluate(() => fetch('/api/identity/jwks').then(r => r.json()));
    await page.getByRole('button', { name: 'Entrar y continuar' }).click();
    await page.waitForURL(`${origins.chronicles}/?shadowops=central`);
    const cookies = await context.cookies(identity);
    const cookie = cookies.find(c => c.name === '__Host-shadowops_sso_staging');
    check(cookie && cookie.secure && cookie.httpOnly && cookie.path === '/' && cookie.sameSite === 'Lax' && cookie.domain === new URL(identity).hostname, 'browser did not accept a host-only secure session');
    let subject;
    for (const [audience, origin] of Object.entries(origins)) {
      await page.goto(origin);
      await page.waitForSelector('body[data-done="true"]');
      check(await page.evaluate(() => window.fixtureStatus) === 200, `${audience} cross-origin token exchange failed`);
      const token = await page.evaluate(() => window.fixtureToken);
      const [head, payload, signature] = token.split('.');
      const header = JSON.parse(Buffer.from(head, 'base64url'));
      const claims = JSON.parse(Buffer.from(payload, 'base64url'));
      const key = jwks.keys.find(k => k.kid === header.kid);
      check(key && header.alg === 'EdDSA' && verify(null, Buffer.from(`${head}.${payload}`), createPublicKey({ key, format: 'jwk' }), Buffer.from(signature, 'base64url')), 'JWT signature invalid');
      check(claims.iss === identity && claims.aud === audience && claims.exp > Date.now() / 1000 && claims.exp - claims.iat <= 120, 'JWT binding or lifetime invalid');
      check(!subject || subject === claims.sub, 'each product received a different central identity');
      subject = claims.sub;
    }
    check(!(await context.cookies(origins.chronicles)).some(c => c.name === cookie.name), 'central cookie leaked to product domain');
    const logout = await page.evaluate(url => fetch(`${url}/api/identity/logout`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then(r => r.status), identity);
    check(logout === 204, 'browser logout failed');
    await page.goto(origins.chronicles);
    await page.waitForSelector('body[data-done="true"]');
    check(await page.evaluate(() => window.fixtureStatus) === 401, 'product exchange survived central logout');
    await page.goto(`${identity}/login?app=chronicles`);
    await page.getByRole('button', { name: 'Recuperar', exact: true }).click();
    await page.getByLabel('Usuario ShadowOps').fill(username);
    await page.getByLabel('Código de recuperación', { exact: true }).fill(recovery);
    password = 'replacement-browser-password-2026';
    await page.getByLabel('Contraseña nueva', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Recuperar mi cuenta', exact: true }).click();
    await page.locator('#backup').waitFor({ state: 'visible' });
    check(await page.locator('#backup-code').textContent() !== recovery, 'recovery secret was not rotated');
    await page.getByRole('button', { name: 'Lo he guardado. Iniciar sesión' }).click();
    await page.getByLabel('Contraseña', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Entrar y continuar' }).click();
    await page.waitForURL(`${origins.chronicles}/?shadowops=central`);
    await page.waitForSelector('body[data-done="true"]');
    check(await page.evaluate(() => window.fixtureStatus) === 200, 'recovered account could not enter synthetic consumer');
    check(errors.length === 0, 'browser JavaScript errors');
    await context.close();
    console.log(`${name}: real registration/login/recovery, TLS cookies, CORS for three synthetic consumers, JWT signatures and logout passed`);
  }
})().catch(error => { console.error(error.message); process.exitCode = 1; }).finally(async () => { if (browser) await browser.close(); });
