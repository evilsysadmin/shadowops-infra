#!/usr/bin/env node
// Read-only Chromium proof for the protected Star Adventures guest shell.
import assert from 'node:assert/strict';

export const BASE = 'https://staging.staradvs.shadowops.dpdns.org';
export const LOGIN = 'https://id-staging.shadowops.dpdns.org/login?app=staradvs';
const DENIED = ['/index.html', '/bridge', '/release.json', '/assets/guest-probe.js'];

export async function checkGuestResponse(path, method = 'GET') {
  const response = await fetch(BASE + path, {
    method, redirect: 'manual', signal: AbortSignal.timeout(20000),
    headers: { 'Cache-Control': 'no-cache' },
  });
  assert.equal(response.status, 401, `Guest ${method} ${path} must be denied`);
  assert.equal(response.headers.get('cache-control'), 'no-store');
}

export async function runSmoke() {
  for (const path of DENIED) {
    await checkGuestResponse(path);
    await checkGuestResponse(path, 'HEAD');
  }
  const { chromium } = await import('@playwright/test');
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  try {
    for (const width of [390, 1280]) {
      const context = await browser.newContext({ viewport: { width, height: 850 } });
      const page = await context.newPage();
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      try {
        const response = await page.goto(BASE + '/', { waitUntil: 'domcontentloaded', timeout: 30000 });
        assert.equal(response?.status(), 401, 'Guest root must render a 401 login shell');
        await page.getByRole('heading', { name: 'Tu cuenta ShadowOps ID' }).waitFor();
        const link = page.getByRole('link', { name: 'Entrar con ShadowOps ID' });
        assert.equal(await link.getAttribute('href'), LOGIN);
        assert.equal(await page.getByTestId('game-shell').count(), 0);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        assert.deepEqual(errors, [], 'Guest shell raised a browser exception');
        console.log(`STARADVS_PRIVATE_GUEST_BROWSER_OK viewport=${width}`);
      } finally {
        await context.close();
      }
    }
  } finally {
    await browser.close();
  }
}

if (process.env.STARADVS_PRIVATE_LIVE_BROWSER === '1') {
  runSmoke().catch(error => { console.error(error); process.exitCode = 1; });
}
