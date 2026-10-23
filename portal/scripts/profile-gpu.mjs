#!/usr/bin/env node
// Local-only, headed Chromium GPU evidence capture. Never invoked by CI
// or by the public portal. Requires a running local Vite/preview server.
import {chromium} from '@playwright/test';
import {mkdir, writeFile} from 'node:fs/promises';
import {resolve, join} from 'node:path';
import {toProfileUrl, assessGpuSnapshot} from './gpu-profile-utils.mjs';

const address = process.env.PORTAL_PROFILE_URL || 'http://127.0.0.1:4173/';
const outDir = resolve(process.env.PORTAL_PROFILE_DIR || '.gpu-profile');
const url = toProfileUrl(address);
const profiles = [];
let browser;

try {
  await mkdir(outDir, {recursive:true});
  // Deliberately headed: headless CI often uses SwiftShader/software raster.
  // This STILL does not guarantee hardware acceleration; inspect the report.
  browser = await chromium.launch({headless:false});
  for (const width of [390,1440]) {
    const height = width === 390 ? 844 : 900;
    const context = await browser.newContext({
      viewport:{width,height},
      deviceScaleFactor:1,
      reducedMotion:'no-preference',
    });
    try {
      const page = await context.newPage();
      await page.goto(url,{waitUntil:'domcontentloaded',timeout:30000});
      const stage = page.locator('.stage');
      await stage.scrollIntoViewIfNeeded();
      await page.waitForFunction(() => {
        const root=document.querySelector('.stage');
        return root?.dataset.scene === 'active' &&
          root.dataset.galleryFrame === 'loaded' &&
          root.dataset.celestialVault === 'loaded';
      },null,{timeout:60000});
      // The portal retains 120 recent samples, and the GPU query may take
      // additional frames to become available without synchronous waiting.
      await page.waitForFunction(() =>
        (document.querySelector('.stage')?.portalPerfSnapshot?.().samples ?? 0) >= 45,
      null,{timeout:90000});
      const result = await stage.evaluate(root => {
        const canvas = root.querySelector('canvas');
        const gl = canvas?.getContext('webgl2');
        const debug = gl?.getExtension('WEBGL_debug_renderer_info');
        return {
          metrics:root.portalPerfSnapshot(),
          webgl:{
            version:gl ? String(gl.getParameter(gl.VERSION)) : null,
            renderer:gl
              ? String(gl.getParameter(debug?.UNMASKED_RENDERER_WEBGL || gl.RENDERER))
              : null,
            vendor:gl
              ? String(gl.getParameter(debug?.UNMASKED_VENDOR_WEBGL || gl.VENDOR))
              : null,
            timerExtension:!!gl?.getExtension('EXT_disjoint_timer_query_webgl2'),
          },
        };
      });
      const screenshot = `portal-${width}.png`;
      await page.screenshot({path:join(outDir,screenshot),fullPage:true,animations:'disabled'});
      const assessment = assessGpuSnapshot(result.metrics,result.webgl.renderer);
      profiles.push({width,height,screenshot,...result,assessment});
      console.log(`${width}px · ${result.webgl.renderer ?? 'unidentified GPU'} · timer ${result.metrics.gpuTimeMs.status} · ${assessment.state}`);
    } finally {
      await context.close();
    }
  }

  const report = {
    kind:'ShadowOps local browser GPU evidence',
    capturedAt:new Date().toISOString(),
    source:url,
    browser:'Chromium '+browser.version(),
    automatedHardwareCertification:false,
    note:'Desktop width emulation is not a physical phone. Inspect chrome://gpu and run separately on real mobile hardware.',
    profiles,
  };
  const file=join(outDir,'gpu-profile.json');
  await writeFile(file,JSON.stringify(report,null,2)+'\n','utf8');
  console.log('Local-only evidence written to '+file);
  console.log('Do not treat review-required as accepted: verify real GPU, sustained performance and device battery/thermals.');
} catch(error) {
  console.error('GPU profiling failed:',error?.message || String(error));
  console.error('Start the portal locally on 127.0.0.1:4173 and install Playwright Chromium in a desktop session with a display.');
  process.exitCode=1;
} finally {
  await browser?.close();
}
