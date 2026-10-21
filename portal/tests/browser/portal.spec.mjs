import { test, expect } from '@playwright/test';

for (const width of [360, 390, 430, 1440]) {
  test(`viewport ${width}: catalog, screenshot and zero horizontal overflow`, async ({page}, testInfo) => {
    await page.setViewportSize({width, height: width < 500 ? 844 : 900});
    await page.emulateMedia({reducedMotion: 'reduce'});
    await page.goto('/');
    await expect(page.getByRole('heading', {name: /Hay mundos que no deberían existir/})).toBeVisible();
    await expect(page.locator('.world-button')).toHaveCount(3);
    await page.locator('.stage-area').scrollIntoViewIfNeeded();
    await page.waitForFunction(() => {
      const state = document.querySelector('.stage')?.dataset.scene;
      return state === 'active' || state === 'unavailable';
    }, null, {timeout: 15000});
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1);
    await testInfo.attach(`shadowops-${width}-scene`, {
      body: await page.screenshot({fullPage: true, animations:'disabled'}),
      contentType: 'image/png',
    });
    await page.getByRole('button', {name: /Star Adventures/}).click();
    await expect(page.locator('.detail-title')).toHaveText('Star Adventures');
    await expect(page.getByText('EN DESARROLLO')).toBeVisible();
    await expect(page.locator('a.enter-link')).toHaveCount(0);
    await page.getByRole('button', {name: /Chess Studio/}).click();
    await expect(page.locator('a.enter-link')).toHaveAttribute('href', 'https://chess-studio.shadowops.dpdns.org/');
    await expect(page.locator('.world-button.active')).toHaveCount(1);
    await expect(page.locator('.world-button.active')).toHaveAttribute('aria-pressed', 'true');
  });
}

test('no WebGL: links and keyboard selection still work, scene stays optional', async ({page}, testInfo) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, 'WebGLRenderingContext', {value: undefined, configurable: true});
  });
  await page.goto('/');
  const stage = page.locator('.stage');
  await stage.scrollIntoViewIfNeeded();
  await expect(stage).toHaveAttribute('data-scene', 'unavailable');
  await expect(page.locator('.fallback')).toBeVisible();
  const star = page.getByRole('button', {name: /Star Adventures/});
  await star.focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('.detail-title')).toHaveText('Star Adventures');
  await expect(page.locator('a.enter-link')).toHaveCount(0);
  const chronicles = page.getByRole('button', {name: /Chronicles/});
  await chronicles.focus();
  await page.keyboard.press('Space');
  await expect(page.locator('.detail-title')).toHaveText('Chronicles');
  await expect(page.locator('a.enter-link')).toHaveAttribute('href', 'https://chronicles.shadowops.dpdns.org/');
  await testInfo.attach('shadowops-without-webgl', {
    body: await page.screenshot({fullPage:true, animations:'disabled'}),
    contentType: 'image/png',
  });
});

test('catalog is usable before heavy 3D module loads', async ({page}) => {
  await page.route('**/src/world.js', async route => {
    // Deliberately fail the GPU module, without interfering with the catalog.
    await route.abort();
  });
  await page.goto('/');
  await page.getByRole('button', {name: /Chronicles/}).click();
  await expect(page.locator('.detail-title')).toHaveText('Chronicles');
  await expect(page.locator('a.enter-link')).toHaveAttribute('href', 'https://chronicles.shadowops.dpdns.org/');
  await page.locator('.stage-area').scrollIntoViewIfNeeded();
  await expect(page.locator('.stage')).toHaveAttribute('data-scene', 'unavailable');
});
