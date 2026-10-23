import {test,expect} from '@playwright/test';
import pngjs from 'pngjs';
const {PNG}=pngjs;

for(const width of [360,390,430,1440]){
  test('Atlas Chamber experiment '+width+'px: real diorama, controls, no overflow',async({page},testInfo)=>{
    await page.setViewportSize({width,height:width<500?844:900});
    await page.emulateMedia({reducedMotion:'reduce'});
    const errors=[];
    page.on('pageerror',e=>errors.push(e.message));
    await page.goto('/experiments/atlas-chamber/index.html');
    await expect(page.getByRole('heading',{name:/No es una puerta/})).toBeVisible();
    await expect(page.getByRole('navigation',{name:'Selección de universos'}).locator('button')).toHaveCount(3);
    await expect(page.getByRole('button',{name:/Chronicles/})).toBeDisabled();
    await expect(page.getByRole('button',{name:/Star Adventures/})).toBeDisabled();
    await expect(page.locator('.atlas-seal-current')).toHaveAttribute('aria-current','true');
    await expect(page.locator('#atlas-enter a')).toHaveCount(0);
    await expect(page.getByText('Concepto en desarrollo — entrada desactivada')).toBeVisible();
    await expect(page.locator('#atlas-viewport')).toHaveAttribute('data-scene','ready',{timeout:15000});
    await expect(page.locator('#atlas-viewport')).toHaveAttribute('data-stone-floor','flags-140');
    await expect(page.locator('#atlas-viewport')).toHaveAttribute('data-light-rig','moon-window-practical');
    await expect(page.locator('#atlas-viewport')).toHaveAttribute('data-archive-volumes','24');
    await expect(page.locator('#atlas-viewport')).toHaveAttribute('data-carved-table','apron-8');
    if(process.env.REQUIRE_BLENDER_ART==='1'){
      await expect(page.locator('#atlas-viewport')).toHaveAttribute('data-atlas-knight','loaded',{timeout:15000});
    }else{
      await expect(page.locator('#atlas-viewport')).toHaveAttribute('data-atlas-knight',/^(fallback|loaded)$/,{timeout:15000});
    }
    await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth-window.innerWidth)).toBeLessThanOrEqual(1);
    const stats=await page.locator('#atlas-viewport').evaluate(e=>({
      calls:Number(e.dataset.drawCalls),
      triangles:Number(e.dataset.triangles),
      masonryBlocks:Number(e.dataset.masonryBlocks),
      motion:e.dataset.motion,
    }));
    expect(stats.calls,'composed 3D scenery needs actual draw calls').toBeGreaterThan(15);
    expect(stats.calls,'limit GPU workload in this study').toBeLessThan(150);
    expect(stats.triangles,'bounded hand-authored geometry').toBeLessThan(160000);
    expect(stats.masonryBlocks,'the wall needs real stone faces, not drawn stripes').toBeGreaterThan(50);
    expect(stats.masonryBlocks,'the wall must remain sparse and GPU-batched').toBeLessThan(90);
    expect(stats.motion).toBe('reduced');
    const canvas=PNG.sync.read(await page.locator('#atlas-viewport canvas').screenshot());
    let nonDark=0,warm=0,cool=0;
    for(let y=0;y<canvas.height;y+=11)for(let x=0;x<canvas.width;x+=11){
      const i=(y*canvas.width+x)*4;
      const r=canvas.data[i],g=canvas.data[i+1],b=canvas.data[i+2];
      if(Math.max(r,g,b)>65){
        nonDark++;
        if(r>g+14&&g>b+7)warm++;
        if(b>r+10)cool++;
      }
    }
    expect(nonDark,'a real illuminated table and environment, not a blank clear color').toBeGreaterThan(30);
    expect(warm,'amber practical light needs visible warm surfaces').toBeGreaterThan(8);
    expect(cool,'moonlit surfaces need visible blue bounce').toBeGreaterThan(15);
    expect(errors).toEqual([]);
    await testInfo.attach('atlas-chamber-'+width+'px',{body:await page.screenshot({fullPage:true,animations:'disabled'}),contentType:'image/png'});
  });
}

test('Atlas Chamber concept remains accessible and never invents links without WebGL',async({page})=>{
  await page.addInitScript(()=>{
    Object.defineProperty(window,'WebGLRenderingContext',{value:undefined,configurable:true});
  });
  await page.goto('/experiments/atlas-chamber/index.html');
  await expect(page.locator('#atlas-viewport')).toHaveAttribute('data-scene','unavailable');
  await expect(page.getByRole('heading',{name:/No es una puerta/})).toBeVisible();
  await expect(page.locator('#atlas-enter a')).toHaveCount(0);
  await expect(page.getByText('Concepto en desarrollo — entrada desactivada')).toBeVisible();
  await page.getByRole('button',{name:/Chess Studio/}).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('button',{name:/Chess Studio/})).toHaveAttribute('aria-current','true');
});

test('Atlas Chamber preserves original chess knight on optional GLB failure',async({page})=>{
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.route('**/experiments/atlas-chamber/compiled/atlas-knight-*.glb',route=>route.abort());
  await page.goto('/experiments/atlas-chamber/index.html');
  await expect(page.locator('#atlas-viewport')).toHaveAttribute('data-scene','ready',{timeout:15000});
  await expect(page.locator('#atlas-viewport')).toHaveAttribute('data-atlas-knight','fallback',{timeout:15000});
  await expect(page.locator('#atlas-viewport canvas')).toBeVisible();
  await expect(page.locator('#atlas-enter a')).toHaveCount(0);
});
