// Read-only validation of the actual public staging and its cross-origin WASM.
import {chromium} from 'playwright';
import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
const origin='https://staging.football.shadowops.dpdns.org';
const out=process.env.FOOTBALL_SCREENSHOTS;
assert.ok(out);await mkdir(out,{recursive:true});
let browser;
try {
 const release=await (await fetch(origin+'/release.json')).json();
 assert.equal(release.application,'football-of-matthias');
 assert.equal(release.environment,'staging');
 assert.match(release.source_sha,/^[a-f0-9]{40}$/);
 if(process.env.SOURCE_SHA)assert.equal(release.source_sha,process.env.SOURCE_SHA);
 const captures=[];
 for(const viewport of [{width:1280,height:800},{width:390,height:844}]) {
  // Desktop and phone represent separate devices, including GPU processes.
  browser=await chromium.launch({headless:true});
  const page=await browser.newPage({viewport,hasTouch:viewport.width===390,isMobile:viewport.width===390});const errors=[];const messages=[];
  page.on('console',message=>{if(['warning','error'].includes(message.type())&&messages.length<100)messages.push(message.type()+': '+message.text());});
  page.on('pageerror',error=>errors.push(String(error)));
  await page.goto(origin);await page.getByRole('button',{name:/Modo mánager/}).waitFor();
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await page.screenshot({path:out+'/'+viewport.width+'-welcome.png'});
  await page.getByRole('button',{name:/Modo mánager/}).click();
  await page.getByRole('button',{name:'Elegir FC Matthias',exact:true}).waitFor();
  await page.screenshot({path:out+'/'+viewport.width+'-manager.png'});
  await page.goto(origin);
  // Set landscape before the user gesture requests real fullscreen. Chromium
  // refuses window bounds changes while that fullscreen transition is active.
  if(viewport.width===390)await page.setViewportSize({width:844,height:390});
  await page.locator('.chess-football-entry__choice--quick').click();
  const host=page.locator('.chess-football-godot-host');
  await host.waitFor();
  await page.waitForFunction(()=>document.querySelector('.chess-football-godot-host')?.dataset.runtimeReady==='true',null,{timeout:120000});
  const frame=page.frames().find(frame=>frame.url()===release.runtime.index);
  assert.ok(frame,'exact immutable runtime loaded');
  assert.equal(await frame.locator('canvas').count(),1);
  // Match the canonical Web smoke's settling budget for first-use GPU textures.
  await page.waitForTimeout(5000);
  const canvas=frame.locator('canvas');await canvas.click();
  await page.keyboard.down('KeyD');await page.waitForTimeout(400);await page.keyboard.up('KeyD');
  await page.screenshot({path:out+'/'+viewport.width+'-real-match.png'});
  assert.deepEqual(errors,[]);
  captures.push({viewport,runtime:frame.url(),ready:true,page_errors:errors,console_messages:messages});await page.close();await browser.close();browser=null;
 }
 await writeFile(out+'/proof.json',JSON.stringify({source_sha:release.source_sha,captures},null,2));
 console.log('FOOTBALL_PUBLIC_BROWSER_DESKTOP_MOBILE_WASM_OK source_sha='+release.source_sha);
}finally{await browser?.close();}
