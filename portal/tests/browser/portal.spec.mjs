import { test, expect } from '@playwright/test';
import pngjs from 'pngjs';
const { PNG } = pngjs;

function assertVisibleWebGLContent(screenshot) {
  const png = PNG.sync.read(screenshot);
  let coloredSamples = 0;
  for (let y = Math.floor(png.height * .13); y < Math.floor(png.height * .87); y += 6) {
    for (let x = Math.floor(png.width * .08); x < Math.floor(png.width * .92); x += 6) {
      const i = (y * png.width + x) * 4;
      const rgb = [png.data[i], png.data[i + 1], png.data[i + 2]];
      if (Math.max(...rgb) >= 31 && Math.max(...rgb) - Math.min(...rgb) >= 14) coloredSamples++;
    }
  }
  // A clear WebGL canvas with the default dark background is NOT a 3D scene.
  expect(coloredSamples, 'Visible portal geometry / material color').toBeGreaterThan(18);
}

for (const width of [360, 390, 430, 1440]) {
  test(`viewport ${width}: catalog, screenshot and zero horizontal overflow`, async ({page}, testInfo) => {
    await page.setViewportSize({width, height: width < 500 ? 844 : 900});
    await page.emulateMedia({reducedMotion: 'reduce'});
    const shaderErrors=[];
    page.on('console', message => {
      if (message.type()==='error' && /shader|WebGLProgram|VALIDATE_STATUS/i.test(message.text())) shaderErrors.push(message.text());
    });
    await page.goto('/');
    await expect(page.getByRole('heading', {name: /Hay mundos que no deberían existir/})).toBeVisible();
    await expect(page.locator('.world-button')).toHaveCount(3);
    await page.locator('.stage-area').scrollIntoViewIfNeeded();
    await page.waitForFunction(() => {
      const state = document.querySelector('.stage')?.dataset.scene;
      return state === 'active' || state === 'unavailable';
    }, null, {timeout: 15000});
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1);
    expect(shaderErrors, 'WebGL shader compiles cleanly').toEqual([]);
    if (await page.locator('.stage').getAttribute('data-scene') === 'active') {
      await expect(page.locator('.stage')).toHaveAttribute('data-gallery-frame','loaded',{timeout:15000});
      await expect(page.locator('.stage')).toHaveAttribute('data-celestial-vault','loaded',{timeout:15000});
      const budgets = await page.locator('.stage').evaluate(stage => ({
        calls: Number(stage.dataset.drawCalls), tris: Number(stage.dataset.triangles),
      }));
      expect(budgets.calls, '3D gallery bounded draw calls').toBeGreaterThan(0);
      expect(budgets.calls, '3D gallery bounded draw calls').toBeLessThan(86);
      expect(budgets.tris, '3D gallery bounded triangles').toBeLessThan(260000);
      await expect(page.locator('.stage')).toHaveAttribute('data-render-budget', width < 500 ? '30' : '45');
    }
    if (await page.locator('.stage').getAttribute('data-scene') === 'active') {
      if (width === 1440) {
        await expect(page.locator('.stage')).toHaveAttribute('data-art-asset','loaded',{timeout:15000});
        await expect(page.locator('.stage')).toHaveAttribute('data-world-relics','loaded',{timeout:15000});
      }
      else {
        await expect(page.locator('.stage')).toHaveAttribute('data-art-asset','skipped-mobile');
        await expect(page.locator('.stage')).toHaveAttribute('data-world-relics','skipped-mobile');
      }
      const canvasScreenshot = await page.locator('.stage canvas').screenshot({animations:'disabled'});
      assertVisibleWebGLContent(canvasScreenshot);
    }
    await testInfo.attach(`shadowops-${width}-scene`, {
      body: await page.screenshot({fullPage: true, animations:'disabled'}),
      contentType: 'image/png',
    });
    await page.getByRole('button', {name: /Star Adventures/}).click();
    await expect(page.locator('.detail-title')).toHaveText('Star Adventures');
    await expect(page.getByText('EN DESARROLLO')).toBeVisible();
    if (await page.locator('.stage').getAttribute('data-scene') === 'active') {
      const selected = await page.locator('.stage').evaluate(stage => ({
        world: stage.dataset.focusWorld,
        blend: Number(stage.dataset.focusBlend),
      }));
      expect(selected.world).toBe('star');
      expect(selected.blend, 'Reduced motion focus applies immediately').toBeGreaterThan(.95);
    }
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


test('gallery GLB fetch failure restores existing masonry without blocking navigation', async ({page})=>{
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.route('**/art/gallery-frame-*.glb', route=>route.abort());
  await page.goto('/');
  await page.locator('.stage-area').scrollIntoViewIfNeeded();
  await expect(page.locator('.stage')).toHaveAttribute('data-scene','active',{timeout:15000});
  await expect(page.locator('.stage')).toHaveAttribute('data-gallery-frame','fallback',{timeout:15000});
  await page.getByRole('button',{name:/Chronicles/}).click();
  await expect(page.locator('.detail-title')).toHaveText('Chronicles');
  await expect(page.locator('a.enter-link')).toHaveAttribute('href','https://chronicles.shadowops.dpdns.org/');
});


test('Blender vault GLB failure preserves functional world navigation',async({page})=>{
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.route('**/art/celestial-vault-*.glb',route=>route.abort());
  await page.goto('/');
  await page.locator('.stage-area').scrollIntoViewIfNeeded();
  await expect(page.locator('.stage')).toHaveAttribute('data-scene','active',{timeout:15000});
  await expect(page.locator('.stage')).toHaveAttribute('data-celestial-vault','fallback',{timeout:15000});
  await page.getByRole('button',{name:/Chronicles/}).click();
  await expect(page.locator('.detail-title')).toHaveText('Chronicles');
  await expect(page.locator('a.enter-link')).toHaveAttribute('href','https://chronicles.shadowops.dpdns.org/');
});
