import test from 'node:test';
import assert from 'node:assert/strict';
import {handle,authorize,ISSUER,HOST,AUDIENCE} from '../edge/snooker-identity-gate.mjs';
const now=Math.floor(Date.now()/1000),base='https://'+HOST;
const PROOF='soc1_'+'Q'.repeat(43),COOKIE='__Host-snooker_staging';
const SUBJECT='123e4567-e89b-42d3-a456-426614174000';
const url=(path,init)=>new Request(base+path,init);
const env=(onAsset=()=>{})=>({SHADOWOPS_SNOOKER_SERVICE_CREDENTIAL:PROOF,
 ASSETS:{fetch:async req=>{onAsset(req);return new Response('game',{status:200})}}});
async function signed(change={},freshChange={}){
 const keys=await crypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
 const jwk=await crypto.subtle.exportKey('jwk',keys.publicKey);
 const claims={iss:ISSUER,aud:AUDIENCE,sub:SUBJECT,sv:3,jti:'snooker-jti',
  iat:now-5,nbf:now-5,exp:now+75,...change};
 const encode=v=>Buffer.from(JSON.stringify(v)).toString('base64url');
 const message=encode({alg:'EdDSA',kid:'snooker-key'})+'.'+encode(claims);
 const signature=Buffer.from(await crypto.subtle.sign('Ed25519',keys.privateKey,
  new TextEncoder().encode(message))).toString('base64url');
 const jwt=message+'.'+signature;
 const fresh={issuer:ISSUER,audience:AUDIENCE,subject:claims.sub,session_version:claims.sv,
  token_jti:claims.jti,account_active:true,session_active:true,token_active:true,
  checked_at:now,...freshChange};
 const request=async(req,opts)=>{
  if(req===ISSUER+'/api/identity/jwks')
   return Response.json({keys:[{...jwk,kid:'snooker-key',use:'sig'}]});
  if(req===ISSUER+'/api/identity/freshness')
   return opts.headers.Authorization==='Bearer '+PROOF?
     Response.json(fresh):new Response('no',{status:401});
  throw Error('Unknown Identity origin');
 };
 return {jwt,options:{request,now,subtle:crypto.subtle}};
}
test('Pages aliases, spoofed hosts, and guest app files never reach static assets',async()=>{
 let served=0;
 for(const name of ['https://snooker-staging.pages.dev/',
                    'https://preview.snooker-staging.pages.dev/index.html',
                    'https://'+HOST+'.evil.test/']){
  assert.equal((await handle(new Request(name),env(()=>served++))).status,404);
 }
 for(const path of ['/','/index.html','/assets/game.js','/assets/game.css','/release.json']){
  const res=await handle(url(path),env(()=>served++));
  assert.equal(res.status,401,path);
  assert.equal(res.headers.get('Cache-Control'),'no-store');
 }
 assert.equal(served,0);
});
test('only 401 login/bootstrap is accessible to unauthenticated custom host',async()=>{
 const script=await (await handle(url('/_shadowops/session.js'),env())).text();
 assert.ok(script.includes('/api/snooker/session'));
 assert.ok(!script.includes(PROOF));
 const html=await (await handle(url('/'),env())).text();
 assert.ok(html.includes(ISSUER+'/login?app=snooker'));
 assert.ok(!html.includes('token='));
});
test('wrong-origin token exchange is rejected before any SSO authorization',async()=>{
 for(const origin of ['https://staging.football.shadowops.dpdns.org','http://'+HOST]){
  const res=await handle(url('/api/snooker/session',{method:'POST',
   headers:{Origin:origin,'Content-Type':'application/json'},body:'{"token":"a.b.c"}'}),env());
  assert.equal(res.status,403);
 }
});
test('Ed25519 Snooker SSO requires live freshness; correct token gets HttpOnly cookie',async()=>{
 const f=await signed(),verified=await authorize(f.jwt,env(),f.options);
 assert.equal(verified.aud,'snooker');
 const session=await handle(url('/api/snooker/session',{method:'POST',headers:{
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
 parts[1]=Buffer.from('{"aud":"snooker"}').toString('base64url');
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
