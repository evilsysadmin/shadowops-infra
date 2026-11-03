import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {handleSessionExchange,SESSION_PATH,ORIGIN} from '../workers/pawn-action-staging/session-exchange.mjs';
import {COOKIE,ISSUER,AUDIENCE,authorizeRequest} from '../workers/pawn-action-staging/identity-gate.mjs';
import {handle as locked} from '../workers/pawn-action-staging/edge.mjs';
const b64=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
async function fixture(){
 const pair=await webcrypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
 const jwk={...await webcrypto.subtle.exportKey('jwk',pair.publicKey),kid:'synthetic',use:'sig',alg:'EdDSA'};
 const now=Math.floor(Date.now()/1000);
 const claims={iss:ISSUER,aud:AUDIENCE,sub:'11111111-1111-4111-8111-111111111111',sv:1,
   jti:Buffer.alloc(16,4).toString('base64url'),iat:now,nbf:now,exp:now+120};
 const proof='soc1_'+Buffer.alloc(32,5).toString('base64url');
 let active=true,calls=0;
 async function sign(overrides={}){
  const msg=b64({alg:'EdDSA',typ:'JWT',kid:jwk.kid})+'.'+b64({...claims,...overrides});
  return msg+'.'+Buffer.from(await webcrypto.subtle.sign('Ed25519',pair.privateKey,Buffer.from(msg))).toString('base64url');
 }
 async function idp(url,init){
  calls++;assert.equal(init.redirect,'manual');
  if(url===ISSUER+'/api/identity/jwks')return Response.json({keys:[jwk]});
  if(url===ISSUER+'/api/identity/freshness'){
   assert.equal(init.headers.Authorization,'Bearer '+proof);
   if(!active)return new Response('',{status:401});
   const p=JSON.parse(init.body);
   return Response.json({issuer:ISSUER,audience:AUDIENCE,subject:p.subject,session_version:p.session_version,
    token_jti:p.token_jti,checked_at:now,account_active:true,session_active:true,token_active:true});
  }
  throw Error('unexpected IdP route');
 }
 return {sign,claims,proof,idp,now,subtle:webcrypto.subtle,revoke:()=>{active=false;},calls:()=>calls};
}
const env=f=>({SHADOWOPS_PAWN_ACTION_SERVICE_CREDENTIAL:f.proof});
const options=f=>({request:f.idp,now:f.now,subtle:f.subtle});
const post=(body,headers={},url=ORIGIN+SESSION_PATH)=>new Request(url,
 {method:'POST',headers:{Origin:ORIGIN,'Content-Type':'application/json',...headers},body});
test('signed+live Pawn Action token receives only a short host-only HttpOnly cookie',async()=>{
 const f=await fixture(),token=await f.sign();
 const r=await handleSessionExchange(post(JSON.stringify({token})),env(f),options(f));
 assert.equal(r.status,200);
 const cookie=r.headers.get('Set-Cookie');
 assert.ok(cookie.startsWith(COOKIE+'='+token+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='));
 assert.doesNotMatch(cookie,/Domain=/);
 assert.ok(Number(cookie.match(/Max-Age=(\d+)/)[1])<=120);
 assert.deepEqual(await r.json(),{subject:f.claims.sub,expires_at:f.claims.exp});
 assert.equal(r.headers.get('Cache-Control'),'no-store, max-age=0');
 const check=new Request(ORIGIN+'/',{headers:{Cookie:cookie.split(';')[0]}});
 assert.equal((await authorizeRequest(check,env(f),options(f))).sub,f.claims.sub);
 assert.equal(f.calls(),4,'freshness checked at exchange AND access');
 f.revoke();
 const denied=await handleSessionExchange(post(JSON.stringify({token})),env(f),options(f));
 assert.equal(denied.status,401);assert.equal(denied.headers.get('Set-Cookie'),null);
});
test('CSRF and foreign URLs fail BEFORE any identity network call',async()=>{
 const f=await fixture(),body=JSON.stringify({token:await f.sign()});
 const bad=[
  post(body,{Origin:''}),
  post(body,{Origin:'https://staging.football.shadowops.dpdns.org'}),
  post(body,{'Sec-Fetch-Site':'same-site'}),
  post(body,{'Sec-Fetch-Site':'cross-site'}),
  post(body,{Origin:ORIGIN+', '+ORIGIN}),
  post(body,{},'https://pawn-action-staging.pages.dev'+SESSION_PATH),
  post(body,{},ORIGIN+SESSION_PATH+'?token=stolen'),
  post(body,{},ORIGIN+':8443'+SESSION_PATH),
  post(body,{},'http://staging.pawnaction.shadowops.dpdns.org'+SESSION_PATH),
 ];
 for(const req of bad){
  const r=await handleSessionExchange(req,env(f),options(f));
  assert.ok([403,404].includes(r.status),req.url+' '+r.status);
  assert.equal(r.headers.get('Set-Cookie'),null);
 }
 assert.equal(f.calls(),0);
});
test('non-POST, wrong type, multiple JSON keys, oversized or compressed bodies fail closed',async()=>{
 const f=await fixture(),token=await f.sign(),body=JSON.stringify({token});
 const bad=[
  new Request(ORIGIN+SESSION_PATH,{method:'GET'}),
  post(body,{'Content-Type':'text/plain'}),
  post(body,{'Content-Encoding':'gzip'}),
  post(body,{Authorization:'Bearer injected'}),
  post(body,{'Content-Length':'999999'}),
  post('x'.repeat(9500)),
  post(JSON.stringify({token,role:'admin'})),
  post('{"token":"'+token+'","token":"'+token+'"}'),
  post('{"token":null}'),
  post('["'+token+'"]'),
 ];
 for(const req of bad){
  const r=await handleSessionExchange(req,env(f),options(f));
  assert.notEqual(r.status,200);assert.equal(r.headers.get('Set-Cookie'),null);
 }
 assert.equal(f.calls(),0);
});
test('wrong audience, forged signature and missing proof never create cookie',async()=>{
 const f=await fixture();
 const tokens=[await f.sign({aud:'football'}),await f.sign({aud:'chronicles'})];
 const valid=(await f.sign()).split('.');
 valid[1]=b64({...f.claims,sv:23});
 tokens.push(valid.join('.'));
 for(const token of tokens){
  const r=await handleSessionExchange(post(JSON.stringify({token})),env(f),options(f));
  assert.equal(r.status,401);assert.equal(r.headers.get('Set-Cookie'),null);
 }
 const r=await handleSessionExchange(post(JSON.stringify({token:await f.sign()})),{},options(f));
 assert.equal(r.status,503);assert.equal(r.headers.get('Set-Cookie'),null);
});
test('locked Pages shell ignores a valid exchanged cookie and never serves a game',async()=>{
 const f=await fixture(),token=await f.sign();
 const e={...env(f),ASSETS:{fetch(){throw Error('game exposed')}}};
 const r=locked(new Request(ORIGIN+'/',{headers:{Cookie:COOKIE+'='+token}}),e);
 assert.equal(r.status,503);assert.match(await r.text(),/El juego aún no se ha publicado/);
 assert.equal(locked(new Request(ORIGIN+'/index.wasm'),e).status,503);
});
