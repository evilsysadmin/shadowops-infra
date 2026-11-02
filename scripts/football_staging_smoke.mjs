// Read-only by default. The explicit activation journey uses one ordinary,
// disposable staging account; credentials stay in memory and all sessions revoke.
import {chromium} from 'playwright';
import {randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
const origin='https://staging.football.shadowops.dpdns.org';
const issuer='https://id-staging.shadowops.dpdns.org';
const out=process.env.FOOTBALL_SCREENSHOTS;
assert.ok(out);await mkdir(out,{recursive:true});
const release=await (await fetch(origin+'/release.json')).json();
assert.equal(release.application,'football-of-matthias');assert.equal(release.environment,'staging');
assert.deepEqual(release.authentication,{provider:'shadowops-id',audience:'football',required:true});
assert.match(release.source_sha,/^[a-f0-9]{40}$/);
if(process.env.SOURCE_SHA)assert.equal(release.source_sha,process.env.SOURCE_SHA);
const captures=[];let centralCookie=null;
const browser=await chromium.launch({headless:true,args:['--enable-webgl','--use-gl=angle','--use-angle=swiftshader','--enable-unsafe-swiftshader']});
async function native(path,body,cookie){return fetch(issuer+path,{method:'POST',headers:{Origin:issuer,'Content-Type':'application/json','User-Agent':'ShadowOps-Football-Smoke/1.0',...(cookie?{Cookie:cookie}:{})},body:JSON.stringify(body),redirect:'error'});}
async function issueFootballToken(cookie){return fetch(issuer+'/api/identity/token',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json',Cookie:cookie},body:'{}',redirect:'error'});}
try{
 for(const viewport of [{width:1280,height:800},{width:390,height:844}]){
  const page=await browser.newPage({viewport,hasTouch:viewport.width===390,isMobile:viewport.width===390});
  const response=await page.goto(origin);assert.ok([401,503].includes(response.status()));
  const login=page.getByRole('link',{name:'Entrar con ShadowOps ID',exact:true});await login.waitFor();
  assert.equal(await login.getAttribute('href'),issuer+'/login?app=football');
  assert.equal(await page.locator('.chess-football-entry,iframe').count(),0);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await page.screenshot({path:out+'/'+viewport.width+'-login.png'});
  for(const path of ['/api/football/session','/runtime.json']){
   const denied=await page.request.get(origin+path);assert.ok([401,503].includes(denied.status()));
  }
  captures.push({viewport,anonymous_denied:true});await page.close();
 }
 // A different Pages hostname must never become an unauthenticated mirror.
 const forged=await fetch(origin+'/api/football/session',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:JSON.stringify({token:'unsigned.claims.value'})});
 assert.ok([401,503].includes(forged.status));
 if(process.env.FOOTBALL_REAL_IDENTITY_SMOKE==='true'){
  const username='football_smoke_'+randomBytes(5).toString('hex'),password=randomBytes(32).toString('base64url');
  assert.match(username,/^[a-z][a-z0-9_]{2,31}$/);
  const registered=await native('/api/identity/register',{username,password});
  assert.equal(registered.status,201,'native ordinary staging registration');await registered.body?.cancel();
  const signed=await native('/api/identity/login',{username,password});assert.equal(signed.status,204,'native staging login');
  const cookie=signed.headers.getSetCookie().find(value=>value.startsWith('__Host-shadowops_sso_staging='));assert.ok(cookie);
  centralCookie=cookie.split(';')[0];
  // Isolate service exchange failures before waiting for browser rendering.
  // Only fixed stage/status diagnostics may leave this ordinary test session.
  const tokenResponse=await issueFootballToken(centralCookie);
  assert.equal(tokenResponse.status,200,'native Football audience issuance');
  const ephemeral=await tokenResponse.json();
  const exchange=await fetch(origin+'/api/football/session',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:JSON.stringify({token:ephemeral.token}),redirect:'error'});
  const allowedStages=new Set(['edge_configuration','identity_keys','identity_freshness','edge_runtime','session']);
  const stage=exchange.headers.get('X-Football-Identity-Error');
  assert.equal(exchange.status,200,'native edge session exchange stage='+(allowedStages.has(stage)?stage:'unreported'));
  await exchange.body?.cancel();
  for(const viewport of [{width:1280,height:800},{width:390,height:844}]){
   const context=await browser.newContext({viewport,hasTouch:viewport.width===390,isMobile:viewport.width===390});
   await context.addCookies([{name:'__Host-shadowops_sso_staging',value:centralCookie.slice(centralCookie.indexOf('=')+1),url:issuer+'/',secure:true,httpOnly:true,sameSite:'Lax'}]);
   const page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(String(error)));
   const network=[];
   page.on('response',response=>{const url=new URL(response.url());if([origin,issuer].includes(url.origin)&&['/api/identity/token','/api/football/session','/_shadowops/session.js'].includes(url.pathname))network.push({origin:url.origin,path:url.pathname,status:response.status()});});
   try{await page.goto(origin);await page.getByRole('button',{name:/Modo mánager/}).waitFor({timeout:60000});}
   catch(error){await page.screenshot({path:out+'/'+viewport.width+'-handoff-failure.png'});await writeFile(out+'/handoff-network.json',JSON.stringify(network,null,2));throw error;}
   const me=await page.request.get(origin+'/api/football/session');assert.equal(me.status(),200);
   const identity=await me.json();assert.match(identity.subject,/^[0-9a-f-]{36}$/);
   await page.getByRole('button',{name:'Salir de ShadowOps ID',exact:true}).click({trial:true});
   await page.screenshot({path:out+'/'+viewport.width+'-authenticated-welcome.png'});
   await page.getByRole('button',{name:/Modo mánager/}).click();
   await page.getByRole('button',{name:'Elegir FC Matthias',exact:true}).waitFor();
   await page.screenshot({path:out+'/'+viewport.width+'-authenticated-manager.png'});
   if(viewport.width===1280){
    await page.goto(origin);await page.locator('.chess-football-entry__choice--quick').click();
    await page.waitForFunction(()=>document.querySelector('.chess-football-godot-host')?.dataset.runtimeReady==='true',null,{timeout:120000});
    const frame=page.frames().find(frame=>frame.url()===release.runtime.index);assert.ok(frame);
    await page.waitForTimeout(5000);await frame.locator('canvas').click();
    await page.keyboard.down('KeyD');await page.waitForTimeout(400);await page.keyboard.up('KeyD');
    await page.screenshot({path:out+'/1280-authenticated-real-match.png'});
   }
   assert.deepEqual(errors,[]);captures.push({viewport,authenticated:true,page_errors:errors});
   if(viewport.width===390){
    const retained=(await context.cookies(origin)).find(value=>value.name==='__Host-football_staging');assert.ok(retained?.httpOnly&&retained?.secure);
    const claims=JSON.parse(Buffer.from(retained.value.split('.')[1],'base64url').toString());
    assert.ok(claims.exp>Math.floor(Date.now()/1000)+30,'retained token is still cryptographically unexpired');
    await page.getByRole('button',{name:'Salir de ShadowOps ID',exact:true}).click();
    await page.getByRole('link',{name:'Entrar con ShadowOps ID',exact:true}).waitFor({timeout:30000});
    assert.equal(await page.locator('.chess-football-entry').count(),0);
    const replay=await issueFootballToken(centralCookie);assert.equal(replay.status,401);
    const replayEdge=await fetch(origin+'/api/football/session',{headers:{Cookie:retained.name+'='+retained.value}});
    assert.equal(replayEdge.status,401,'edge rejects the unexpired token after real global logout');
    centralCookie=null;
   }
   await context.close();
  }
  console.log('FOOTBALL_REAL_IDENTITY_BROWSER_OK source_sha='+release.source_sha);
 }
 await writeFile(out+'/proof.json',JSON.stringify({source_sha:release.source_sha,authentication:release.authentication,captures},null,2));
 console.log('FOOTBALL_PUBLIC_IDENTITY_GATE_OK source_sha='+release.source_sha);
}finally{
 if(centralCookie){try{await native('/api/identity/logout',{},centralCookie);}catch{/* Never log the credential or private response. */}}
 await browser.close();
}
