'use strict';
// Real Chromium + real production native login, Mongo sessions, JWT and CORS;
// only the game document is synthetic. No public DNS and no production secrets.
const {chromium} = require('playwright');
const {createPublicKey, verify} = require('node:crypto');
const {mkdir} = require('node:fs/promises');
const path = require('node:path');
const identity = 'https://id.shadowops.dpdns.org';
const game = 'https://bridgesquad.shadowops.dpdns.org';
const check = (ok, message) => { if (!ok) throw new Error(message); };
let browser;
(async () => {
 browser = await chromium.launch({
  headless:true,
  executablePath:process.env.IDENTITY_BROWSER_EXECUTABLE || undefined,
  args:['--no-proxy-server',
   '--host-resolver-rules=MAP id.shadowops.dpdns.org 127.0.0.1:19444, MAP bridgesquad.shadowops.dpdns.org 127.0.0.1:19444'],
 });
 const artifacts = process.env.IDENTITY_BROWSER_ARTIFACTS;
 if (artifacts) await mkdir(artifacts,{recursive:true});
 for (const [label,viewport] of [['desktop',{width:1440,height:900}],['mobile',{width:390,height:844}]]) {
  const context = await browser.newContext({
   viewport,ignoreHTTPSErrors:true,isMobile:label==='mobile',hasTouch:label==='mobile',
  });
  const page=await context.newPage();
  const errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto(game);
  await page.waitForSelector('body[data-done="true"]');
  check(await page.evaluate(()=>window.fixtureStatus)===401,'guest obtained a production token');
  await page.goto(identity+'/login?app=bridgesquad');
  await page.getByRole('heading',{name:'Entrar en Bridge Squad'}).waitFor();
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'production login overflows '+label);
  if(artifacts)await page.screenshot({path:path.join(artifacts,'bridgesquad-prod-login-'+label+'.png'),fullPage:true});
  const jwks=await page.evaluate(()=>fetch('/api/identity/jwks').then(r=>r.json()));
  await page.getByLabel('Usuario').fill('matthias');
  await page.getByLabel('Contraseña').fill('a very strong unique password for prod 2026');
  await page.getByRole('button',{name:'Entrar y continuar'}).click();
  await page.waitForURL(game+'/?shadowops=central');
  await page.waitForSelector('body[data-done="true"]');
  check(await page.evaluate(()=>window.fixtureStatus)===200,'cross-origin session token failed for '+label);
  const token=await page.evaluate(()=>window.fixtureToken);
  check(typeof token==='string'&&token.length>90,'missing production JWT');
  const parts=token.split('.');
  check(parts.length===3,'bad JWT encoding');
  const header=JSON.parse(Buffer.from(parts[0],'base64url'));
  const claims=JSON.parse(Buffer.from(parts[1],'base64url'));
  const key=jwks.keys.find(x=>x.kid===header.kid);
  check(key&&header.alg==='EdDSA'&&verify(null,Buffer.from(parts.slice(0,2).join('.')),
    createPublicKey({key,format:'jwk'}),Buffer.from(parts[2],'base64url')),'JWKS signature verification failed');
  check(claims.iss===identity&&claims.aud==='bridgesquad'&&
   /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(claims.sub)&&
   claims.exp>Date.now()/1000&&claims.exp-claims.iat<=120,'production audience, subject or JWT expiry wrong');
  const cookies=await context.cookies(identity);
  const cookie=cookies.find(x=>x.name==='__Host-shadowops_sso_production');
  check(cookie&&cookie.secure&&cookie.httpOnly&&cookie.path==='/'&&
    cookie.sameSite==='None'&&cookie.domain==='id.shadowops.dpdns.org','host-only production cookie rejected');
  check(!(await context.cookies(game)).some(x=>x.name===cookie.name),'central Identity cookie leaked into Bridge Squad');
  const checkToken=async()=>await page.evaluate(async tok=>(
   await fetch('/api/fixture-check',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({token:tok})})).status,token);
  check(await checkToken()===204,'real Mongo freshness did not validate issued JWT');
  // Logout must happen on the exact production Identity origin, not on game.
  await page.goto(identity+'/login?app=bridgesquad');
  const logout=await page.evaluate(()=>fetch('/api/identity/logout',{
   method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
   body:'{}'}).then(r=>r.status));
  check(logout===204,'production Identity logout failed');
  await page.goto(game);
  await page.waitForSelector('body[data-done="true"]');
  check(await page.evaluate(()=>window.fixtureStatus)===401,'logged-out cookie still issued tokens');
  check(await checkToken()===401,'revoked JWT still passed live Mongo freshness');
  check(errors.length===0,'browser JavaScript errors: '+errors.join(', '));
  await context.close();
  console.log(label+': production HTML login, TLS host cookie, CORS token, EdDSA JWT, Mongo freshness and logout OK');
 }
})().catch(error=>{console.error(error.stack||error.message);process.exitCode=1;})
 .finally(async()=>{if(browser)await browser.close();});
