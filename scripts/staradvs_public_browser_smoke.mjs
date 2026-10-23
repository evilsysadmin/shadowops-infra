#!/usr/bin/env node
/**
 * Read-only, real-browser proof for the exact build served by Star Adventures Pages.
 * Infra owns the test; game source provides only its pinned Playwright runtime.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir } from 'node:fs/promises';

export const BASE = 'https://staging.staradvs.shadowops.dpdns.org';
const CHROME_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36';
const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ASSET_PATH = /^\/assets\/[a-zA-Z0-9._-]+\.js$/;

export function validateRelease(release) {
  assert.ok(release && typeof release === 'object' && !Array.isArray(release), 'Invalid public release manifest');
  assert.match(release.build ?? '', HEX40, 'Public release SHA must be an immutable commit');
  assert.equal(release.environment, 'staging', 'Wrong deployment environment');
  const entry = release.entry_js;
  assert.ok(entry && typeof entry === 'object' && !Array.isArray(entry), 'Missing JS integrity proof');
  assert.match(entry.path ?? '', ASSET_PATH, 'Release JS path must be a local Vite asset');
  assert.match(entry.sha256 ?? '', HEX64, 'Release JS SHA-256 missing or malformed');
  return release;
}

export async function readPublicRelease(runId = 'probe') {
  const url = BASE + '/release.json?browser=' + encodeURIComponent(runId);
  const response = await fetch(url, {
    redirect: 'manual',
    signal: AbortSignal.timeout(20000),
    headers: { 'User-Agent': CHROME_UA, 'Cache-Control': 'no-cache', 'Accept': 'application/json' },
  });
  assert.equal(response.status, 200, 'Public staging manifest must be direct HTTPS 200');
  assert.match(response.headers.get('content-type') ?? '', /json/i, 'Public manifest must be JSON');
  const raw = await response.text();
  assert.ok(raw.length > 0 && raw.length <= 65536, 'Public manifest size invalid');
  return validateRelease(JSON.parse(raw));
}

export async function verifyPublicEntrypoint(release) {
  const response = await fetch(BASE + release.entry_js.path, {
    redirect: 'manual',
    signal: AbortSignal.timeout(20000),
    headers: { 'User-Agent': CHROME_UA, 'Cache-Control': 'no-cache', 'Accept': 'application/javascript' },
  });
  assert.equal(response.status, 200, 'Published JS entrypoint must be direct HTTPS 200');
  assert.match(response.headers.get('content-type') ?? '', /javascript/i, 'Published JS is not JavaScript');
  const body = Buffer.from(await response.arrayBuffer());
  assert.ok(body.length > 0 && body.length <= 16_000_000, 'Published JS is missing or oversized');
  assert.equal(createHash('sha256').update(body).digest('hex'), release.entry_js.sha256,
    'Published JS is not the JS attested by the current release');
}

async function exerciseBridge(browser, width) {
  const context = await browser.newContext({
    viewport: { width, height: width <= 430 ? 850 : 820 },
    deviceScaleFactor: 1,
    reducedMotion: 'reduce',
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  try {
    const { expect } = await import('@playwright/test');
    // Pages must serve index.html for a deep link too, not only for /.
    const navigation = await page.goto(BASE + '/bridge?staging-smoke=1', { waitUntil: 'domcontentloaded', timeout: 30000 });
    assert.equal(navigation?.status(), 200, 'Public SPA deep link did not return 200');
    await expect(page.getByRole('heading', { name: /Ecos en la frontera/i })).toBeVisible({ timeout: 15000 });
    await expect(page.getByTestId('explore-area')).toContainText('Puente');
    await expect(page.getByTestId('console-locked')).toBeVisible();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true,
      'Public bridge overflows horizontally at ' + width + 'px');

    // Follow the real first-person navigation from source bridge.spec.ts.
    await page.getByTestId('explore-left').click();
    await page.getByTestId('explore-forward').click();
    await page.getByTestId('explore-forward').click();
    await page.getByTestId('explore-right').click();
    await page.getByTestId('explore-forward').click();
    await page.getByTestId('explore-use').click();
    await expect(page.getByTestId('choice-scan')).toBeVisible();
    await page.getByTestId('choice-scan').click();
    await expect(page.getByTestId('science-score')).toHaveText('02');

    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('science-score')).toHaveText('02');
    await expect(page.getByTestId('console-locked')).toBeVisible();
    await page.getByTestId('explore-use').click();
    await expect(page.getByTestId('choice-broadcast')).toBeVisible();
    await page.getByTestId('choice-broadcast').click();
    await expect(page.getByTestId('ending')).toContainText('Paz negociada');

    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('science-score')).toHaveText('05');
    await expect(page.getByTestId('ending')).toContainText('Paz negociada');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true,
      'Public endgame overflows horizontally at ' + width + 'px');
    assert.deepEqual(errors, [], 'Uncaught browser exceptions on the public game');
    await mkdir('staradvs-public-captures', { recursive: true });
    await page.screenshot({ path: 'staradvs-public-captures/bridge-' + width + '.png', fullPage: true });
    console.log('STARADVS_PUBLIC_BROWSER_OK viewport=' + width);
  } finally {
    await context.close();
  }
}

export async function runSmoke() {
  const expected = process.env.STARADVS_PUBLIC_SHA || '';
  assert.match(expected, HEX40, 'Expected published SHA missing');
  const release = await readPublicRelease(process.env.GITHUB_RUN_ID || 'live');
  assert.equal(release.build, expected, 'Published SHA changed before browser test');
  await verifyPublicEntrypoint(release);
  const { chromium } = await import('@playwright/test');
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  try {
    for (const width of [390, 1280]) await exerciseBridge(browser, width);
  } finally {
    await browser.close();
  }
  const after = await readPublicRelease(process.env.GITHUB_RUN_ID || 'after');
  assert.equal(after.build, expected, 'Published SHA changed during browser journey');
  assert.deepEqual(after.entry_js, release.entry_js, 'Published JS changed during browser journey');
  console.log('STARADVS_PUBLIC_JOURNEY_READY sha=' + expected);
}

if (process.argv.includes('--release-sha')) {
  readPublicRelease(process.env.GITHUB_RUN_ID || 'release').then(
    release => process.stdout.write(release.build + '\n'),
    error => { console.error(error); process.exitCode = 1; },
  );
} else if (process.env.STARADVS_LIVE_BROWSER === '1') {
  runSmoke().catch(error => { console.error(error); process.exitCode = 1; });
}
