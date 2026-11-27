import test from 'node:test';
import assert from 'node:assert/strict';
import {handle,authorize,ISSUER,HOST,AUDIENCE} from '../edge/bridgesquad-staging-identity-gate.mjs';
const now=Math.floor(Date.now()/1000),base='https://'+HOST;
const PROOF='soc1_'+'Q'.repeat(43),COOKIE='__Host-bridgesquad_staging';
const SUBJECT='123e4567-e89b-42d3-a456-426614174000';
const url=(path,init)=>new Request(base+path,init);
const env=(onAsset=()=>{})=>({SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL:PROOF,
 ASSETS:{fetch:async req=>{onAsset(req);return new Response('game',{status:200})}}});
async function signed(change={},freshChange={}){
 const keys=await crypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
 const jwk=await crypto.subtle.exportKey('jwk',keys.publicKey);
 const claims={iss:ISSUER,aud:AUDIENCE,sub:SUBJECT,sv:3,jti:'bridgesquad-jti',
  iat:now-5,nbf:now-5,exp:now+75,...change};
 const encode=v=>Buffer.from(JSON.stringify(v)).toString('base64url');
 const message=encode({alg:'EdDSA',kid:'bridgesquad-key'})+'.'+encode(claims);
 const signature=Buffer.from(await crypto.subtle.sign('Ed25519',keys.privateKey,
  new TextEncoder().encode(message))).toString('base64url');
 const jwt=message+'.'+signature;
 const fresh={issuer:ISSUER,audience:AUDIENCE,subject:claims.sub,session_version:claims.sv,
  token_jti:claims.jti,account_active:true,session_active:true,token_active:true,
  checked_at:now,...freshChange};
 const request=async(req,opts)=>{
  if(req===ISSUER+'/api/identity/jwks')
   return Response.json({keys:[{...jwk,kid:'bridgesquad-key',use:'sig'}]});
  if(req===ISSUER+'/api/identity/freshness')
   return opts.headers.Authorization==='Bearer '+PROOF?
     Response.json(fresh):new Response('no',{status:401});
  throw Error('Unknown Identity origin');
 };
 return {
  jwt,options:{request,now,subtle:crypto.subtle},
  revoke(){ fresh.session_active=false; },
 };
}
test('Pages aliases, spoofed hosts, and guest app files never reach static assets',async()=>{
 let served=0;
 for(const name of ['https://bridgesquad-staging.pages.dev/',
                    'https://preview.bridgesquad-staging.pages.dev/index.html',
                    'https://'+HOST+'.evil.test/']){
  assert.equal((await handle(new Request(name),env(()=>served++))).status,404);
 }
 for(const path of ['/','/index.html','/bridge','/bridge/','/assets/game.js','/assets/game.css','/release.json']){
  const res=await handle(url(path),env(()=>served++));
  assert.equal(res.status,401,path);
  assert.equal(res.headers.get('Cache-Control'),'no-store');
 }
 assert.equal(served,0);
});
test('only 401 login/bootstrap is accessible to unauthenticated custom host',async()=>{
 const script=await (await handle(url('/_shadowops/session.js'),env())).text();
 assert.ok(script.includes('/api/bridgesquad/session'));
 assert.ok(!script.includes(PROOF));
 const html=await (await handle(url('/'),env())).text();
 assert.ok(html.includes(ISSUER+'/login?app=bridgesquad'));
 assert.ok(!html.includes('token='));
});
test('global logout navigates to IdP confirmation; local logout never claims SSO revocation',async()=>{
 let assets=0;
 const stub=env(()=>assets++);
 const link=await handle(url('/_shadowops/logout'),stub);
 assert.equal(link.status,303);
 assert.equal(link.headers.get('Location'),ISSUER+'/logout?app=bridgesquad');
 assert.equal(link.headers.get('Cache-Control'),'no-store');
 assert.equal(link.headers.get('Set-Cookie'),null,'GET navigation cannot mutate cookies');
 const guestShell=await (await handle(url('/'),stub)).text();
 assert.ok(guestShell.includes('href="/_shadowops/logout"'));
 const local=await handle(url('/api/bridgesquad/logout',{
  method:'POST',headers:{Origin:base},
 }),stub);
 assert.equal(local.status,200);
 assert.deepEqual(await local.json(),{
  local_cookie_cleared:true,identity_session_revoked:false,
  central_logout_url:ISSUER+'/logout?app=bridgesquad',
 });
 assert.match(local.headers.get('Set-Cookie'),/Max-Age=0/);
 assert.match(local.headers.get('Set-Cookie'),/HttpOnly/);
 for(const request of [
  url('/_shadowops/logout?next=https://evil.invalid'),
  url('/_shadowops/logout',{method:'POST'}),
  url('/api/bridgesquad/logout',{method:'POST',headers:{Origin:'https://evil.invalid'}}),
 ]) {
  const response=await handle(request,stub);
  assert.notEqual(response.status,303,'untrusted logout navigation must not redirect');
  assert.equal(response.headers.get('Set-Cookie'),null,'untrusted logout cannot mutate cookies');
 }
 assert.equal(assets,0,'logout and confirmation navigation cannot read game assets');
});

test('HTTPS canonical host and exact port are required even with signed session',async()=>{
 const f=await signed();
 let assets=0;
 for(const target of [
  'http://'+HOST+'/assets/game.js',
  'https://'+HOST+':8443/assets/game.js',
  'https://'+HOST+'.evil.test/assets/game.js',
 ]) {
  const response=await handle(new Request(target,{
   headers:{Cookie:COOKIE+'='+f.jwt},
  }),env(()=>assets++),f.options);
  assert.equal(response.status,404,target);
 }
 assert.equal(assets,0);
});

test('wrong-origin token exchange is rejected before any SSO authorization',async()=>{
 for(const origin of ['https://staging.football.shadowops.dpdns.org','http://'+HOST]){
  const res=await handle(url('/api/bridgesquad/session',{method:'POST',
   headers:{Origin:origin,'Content-Type':'application/json'},body:'{"token":"a.b.c"}'}),env());
  assert.equal(res.status,403);
 }
});
test('Ed25519 Bridge Squad staging SSO requires live freshness; correct token gets HttpOnly cookie',async()=>{
 const f=await signed(),verified=await authorize(f.jwt,env(),f.options);
 assert.equal(verified.aud,'bridgesquad');
 const session=await handle(url('/api/bridgesquad/session',{method:'POST',headers:{
  Origin:base,'Content-Type':'application/json'},body:JSON.stringify({token:f.jwt})}),env(),f.options);
 assert.equal(session.status,200);
 const setCookie=session.headers.get('Set-Cookie');
 assert.ok(setCookie.includes(COOKIE+'=')&&setCookie.includes('Secure')&&setCookie.includes('HttpOnly'));
 let served=0;
 const app=await handle(url('/assets/game.js',{headers:{Cookie:COOKIE+'='+f.jwt}}),
  env(()=>served++),f.options);
 assert.equal(app.status,200);assert.equal(served,1);
});
test('wrong audience, expiry, future validity and missing proof are rejected',async()=>{
 for(const change of [{aud:'football'},{exp:now-1},{nbf:now+30}]){
  const f=await signed(change);
  await assert.rejects(()=>authorize(f.jwt,env(),f.options),e=>e.status===401);
 }
 const f=await signed();
 await assert.rejects(()=>authorize(f.jwt,{ASSETS:env().ASSETS},f.options),e=>e.status===503);
 const parts=f.jwt.split('.');
 parts[1]=Buffer.from('{"aud":"bridgesquad"}').toString('base64url');
 await assert.rejects(()=>authorize(parts.join('.'),env(),f.options),e=>e.status===401);
});
test('revocation, wrong live audience, and Identity outages fail closed',async()=>{
 for(const x of [{account_active:false},{session_active:false},{token_active:false},
                 {audience:'football'},{checked_at:now-10}]){
  const f=await signed({},x);
  await assert.rejects(()=>authorize(f.jwt,env(),f.options),e=>e.status===401);
 }
 const f=await signed();
 await assert.rejects(()=>authorize(f.jwt,env(),{now,subtle:crypto.subtle,
  request:async()=>{throw Error('Identity unavailable')}}),e=>e.status===503);
});

test('signed-in release is protected end to end; logout and live revocation deny assets',async()=>{
 // The *real* Ed25519 JWT and edge Worker execute with deterministic mock
 // JWKS/freshness, not a bypass or a fabricated signed-in HTTP 200.
 const f=await signed();
 const release={
  schema:1, application:'star-adventures', environment:'staging',
  source_sha:'a'.repeat(40),
  authentication:{provider:'shadowops-id',audience:'bridgesquad',required:true},
 };
 let assetsFetched=0;
 const appEnv={
  SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL:PROOF,
  ASSETS:{fetch:async(req)=>{
   assetsFetched++;
   assert.equal(new URL(req.url).pathname,'/release.json');
   return Response.json(release);
  }},
 };
 const guest=await handle(url('/release.json'),appEnv,f.options);
 assert.equal(guest.status,401);
 assert.equal(assetsFetched,0,'guest never reaches a protected manifest');

 const handshake=await handle(url('/api/bridgesquad/session',{
  method:'POST',headers:{Origin:base,'Content-Type':'application/json'},
  body:JSON.stringify({token:f.jwt}),
 }),appEnv,f.options);
 assert.equal(handshake.status,200);
 const setCookie=handshake.headers.get('Set-Cookie');
 assert.match(setCookie,/^__Host-bridgesquad_staging=/);
 assert.match(setCookie,/HttpOnly/);
 assert.match(setCookie,/Secure/);
 assert.match(setCookie,/SameSite=Lax/);
 const cookie=setCookie.split(';')[0];
 const granted=await handle(url('/release.json',{headers:{Cookie:cookie}}),appEnv,f.options);
 assert.equal(granted.status,200);
 assert.deepEqual(await granted.json(),release);
 assert.equal(granted.headers.get('Cache-Control'),'no-store');
 assert.equal(assetsFetched,1);

 const status=await handle(url('/api/bridgesquad/session',{headers:{Cookie:cookie}}),appEnv,f.options);
 assert.equal(status.status,200);
 assert.equal((await status.json()).identity,'bridgesquad');

 // Identical signed JWT and cookie, but Identity freshness now revokes it.
 // The Worker may not serve a cached asset simply because JWT exp is future.
 f.revoke();
 const denied=await handle(url('/release.json',{headers:{Cookie:cookie}}),appEnv,f.options);
 assert.equal(denied.status,401);
 assert.equal(assetsFetched,1,'revoked sessions cannot read the release artifact');

 const logout=await handle(url('/api/bridgesquad/logout',{
  method:'POST',headers:{Origin:base,Cookie:cookie},
 }),appEnv,f.options);
 assert.equal(logout.status,200);
 assert.match(logout.headers.get('Set-Cookie'),/Max-Age=0/);
 assert.match(logout.headers.get('Set-Cookie'),/HttpOnly/);
 const cleared=await handle(url('/release.json'),appEnv,f.options);
 assert.equal(cleared.status,401);
 assert.equal(assetsFetched,1,'logout clears browser cookie; no guest asset leak');
});

test('silent renewal is fenced to the expected verified account, including after cookie expiry',async()=>{
 const f=await signed(), other='123e4567-e89b-42d3-a456-426614174001';
 let assets=0;
 const stub=env(()=>assets++);
 const renew=(body,origin=base)=>handle(url('/api/bridgesquad/session/renew',{
  method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},
  body:JSON.stringify(body),
 }),stub,f.options);
 const matched=await renew({token:f.jwt,expected_subject:SUBJECT});
 assert.equal(matched.status,200);
 assert.equal((await matched.json()).subject,SUBJECT);
 assert.match(matched.headers.get('Set-Cookie'),/^__Host-bridgesquad_staging=/);
 for(const [body,origin,status] of [
  [{token:f.jwt,expected_subject:other},base,401],
  [{token:f.jwt},base,400],
  [{token:f.jwt,expected_subject:'invalid'},base,400],
  [{token:f.jwt,expected_subject:SUBJECT,extra:true},base,400],
  [{token:'a.b.c',expected_subject:SUBJECT},base,401],
  [{token:f.jwt,expected_subject:SUBJECT},'https://evil.invalid',403],
 ]){
  const denied=await renew(body,origin);
  assert.equal(denied.status,status);
  assert.equal(denied.headers.get('Set-Cookie'),null);
 }
 f.revoke();
 const revoked=await renew({token:f.jwt,expected_subject:SUBJECT});
 assert.equal(revoked.status,401);
 assert.equal(revoked.headers.get('Set-Cookie'),null);
 assert.equal(assets,0);
});

test('staging gate never serves the production host nor accepts production-issuer tokens',async()=>{
 assert.equal(HOST,'staging.bridgesquad.shadowops.dpdns.org');
 assert.equal(ISSUER,'https://id-staging.shadowops.dpdns.org');
 for(const name of ['https://bridgesquad.shadowops.dpdns.org/','https://bridgesquad-production.pages.dev/']){
  const res=await handle(new Request(name),env());
  assert.equal(res.status,404);assert.equal(await res.text(),'Not found');
 }
 const forged=await signed({iss:'https://id.shadowops.dpdns.org'});
 await assert.rejects(authorize(forged.jwt,env(),forged.options));
 const prodAudience=await signed({aud:'bridgesquad-production'});
 await assert.rejects(authorize(prodAudience.jwt,env(),prodAudience.options));
});
