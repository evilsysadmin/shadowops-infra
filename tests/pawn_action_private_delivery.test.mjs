import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import protectedWorker from '../workers/pawn-action-staging/private-delivery.mjs';
import lockedWorker from '../workers/pawn-action-staging/edge.mjs';
import {COOKIE,ISSUER,AUDIENCE} from '../workers/pawn-action-staging/identity-gate.mjs';

const HOST='https://staging.pawnaction.shadowops.dpdns.org';
const RELEASE='a1b2c3d4e5f60718';
const FILES=['index.html','index.js','index.wasm','index.pck','index.png',
 'index.icon.png','index.apple-touch-icon.png','index.audio.worklet.js',
 'index.audio.position.worklet.js'];
const encoded=v=>Buffer.from(JSON.stringify(v)).toString('base64url');
async function fixture(){
 const pair=await webcrypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
 const jwk={...await webcrypto.subtle.exportKey('jwk',pair.publicKey),kid:'test-key',alg:'EdDSA',use:'sig'};
 const now=Math.floor(Date.now()/1000);
 const claims={iss:ISSUER,aud:AUDIENCE,sub:'11111111-1111-4111-8111-111111111111',
  iat:now,nbf:now,exp:now+120,sv:1,jti:Buffer.alloc(16,7).toString('base64url')};
 const proof='soc1_'+Buffer.alloc(32,8).toString('base64url');
 const hits=[],objects=new Map();
 for(const file of FILES)objects.set('pawn-action/releases/'+RELEASE+'/'+file,
  Buffer.from('private:'+file));
 let active=true,identityCalls=0;
 const bucket={
  async get(key){hits.push(['get',key]);const b=objects.get(key);
   return b?{size:b.length,body:new Response(b).body}:null;},
  async head(key){hits.push(['head',key]);const b=objects.get(key);
   return b?{size:b.length}:null;},
 };
 async function sign(changes={}){
  const message=encoded({alg:'EdDSA',typ:'JWT',kid:jwk.kid})+'.'+encoded({...claims,...changes});
  return message+'.'+Buffer.from(await webcrypto.subtle.sign('Ed25519',pair.privateKey,
   Buffer.from(message))).toString('base64url');
 }
 async function idp(url,init){
  identityCalls++;assert.equal(init.redirect,'manual');
  if(url===ISSUER+'/api/identity/jwks')return Response.json({keys:[jwk]});
  if(url===ISSUER+'/api/identity/freshness'){
   assert.equal(init.headers.Authorization,'Bearer '+proof);
   const body=JSON.parse(init.body);
   if(!active)return new Response('',{status:401});
   return Response.json({issuer:ISSUER,audience:AUDIENCE,subject:body.subject,
    session_version:body.session_version,token_jti:body.token_jti,checked_at:now,
    account_active:true,session_active:true,token_active:true});
  }
  throw Error('Unexpected Identity endpoint');
 }
 return {sign,proof,claims,now,idp,bucket,hits,objects,
  revoke(){active=false;},calls(){return identityCalls;}};
}
const env=f=>({SHADOWOPS_PAWN_ACTION_SERVICE_CREDENTIAL:f.proof,
 PAWN_ACTION_PRIVATE_RELEASE:RELEASE,PAWN_ACTION_PRIVATE_R2:f.bucket});
const options=f=>({request:f.idp,subtle:webcrypto.subtle,now:f.now});
const fetchPrivate=(r,e,o)=>protectedWorker.fetch(r,e,o);
const req=(url,cookie=null,method='GET',extra={})=>new Request(url,{
 method,headers:{...(cookie?{Cookie:COOKIE+'='+cookie}:{}),...extra}});
test('every one of nine Godot files requires live authentication and streams only private R2 objects',async()=>{
 const f=await fixture(),token=await f.sign();
 for(const file of FILES){
  const path=HOST+'/'+file;
  const no=await fetchPrivate(req(path),env(f),options(f));
  assert.equal(no.status,401);assert.equal(no.headers.get('Content-Length'),null);
  assert.equal(f.hits.length,FILES.indexOf(file));
  const yes=await fetchPrivate(req(path,token),env(f),options(f));
  assert.equal(yes.status,200,file);
  assert.equal(await yes.text(),'private:'+file);
  assert.equal(yes.headers.get('Cache-Control'),'private, no-store, max-age=0');
  assert.equal(yes.headers.get('Cross-Origin-Embedder-Policy'),'require-corp');
  assert.equal(yes.headers.get('Cross-Origin-Resource-Policy'),'same-origin');
  assert.equal(yes.headers.get('Access-Control-Allow-Origin'),null);
  assert.deepEqual(f.hits.at(-1),['get','pawn-action/releases/'+RELEASE+'/'+file]);
 }
 const home=await fetchPrivate(req(HOST+'/',token),env(f),options(f));
 assert.equal(await home.text(),'private:index.html');
 const head=await fetchPrivate(req(HOST+'/index.wasm',token,'HEAD'),env(f),options(f));
 assert.equal(head.status,200);assert.equal(await head.text(),'');
 assert.deepEqual(f.hits.at(-1),['head','pawn-action/releases/'+RELEASE+'/index.wasm']);
 assert.equal(f.calls(),22,'every protected GET and HEAD rechecks JWKS and freshness');
});
test('preview aliases, public asset origin, unknown files, pointers and traversal cannot read R2',async()=>{
 const f=await fixture(),token=await f.sign();
 for(const target of [
  'https://pawn-action-staging.pages.dev/index.wasm',
  'https://assets.chess-studio.shadowops.dpdns.org/pawn-action/releases/'+RELEASE+'/index.wasm',
  'http://staging.pawnaction.shadowops.dpdns.org/index.wasm',
  HOST+'/index.wasm?token='+token,
  HOST+'/pawn-action/current.json',
  HOST+'/pawn-slug-godot/current.json',
  HOST+'/release.json', HOST+'/_worker.js',HOST+'/index.wasm/extra',
  HOST+'/index.wasm%2f..',HOST+'/index.js.map',HOST+'/favicon.ico',
  HOST+'/admin',HOST+'/index.js?preview=1'
 ]){
  const res=await fetchPrivate(req(target,token),env(f),options(f));
  assert.equal(res.status,404,target);
 }
 assert.equal(f.hits.length,0);assert.equal(f.calls(),0);
});
test('no private binding or release ID: deny even with signed, live session',async()=>{
 const f=await fixture(),token=await f.sign();
 for(const wrong of [{}, {PAWN_ACTION_PRIVATE_R2:f.bucket},
  {PAWN_ACTION_PRIVATE_R2:f.bucket,PAWN_ACTION_PRIVATE_RELEASE:'latest'},
  {PAWN_ACTION_PRIVATE_R2:f.bucket,PAWN_ACTION_PRIVATE_RELEASE:'pawn-slug-godot'},
  {PAWN_ACTION_PRIVATE_R2:{get(){}},PAWN_ACTION_PRIVATE_RELEASE:RELEASE}]){
  const res=await fetchPrivate(req(HOST+'/index.wasm',token),
   {SHADOWOPS_PAWN_ACTION_SERVICE_CREDENTIAL:f.proof,...wrong},options(f));
  assert.equal(res.status,503);
 }
 assert.equal(f.hits.length,0);
});
test('revoked session, missing cookie, wrong audience and upstream outage never fetch private assets',async()=>{
 const f=await fixture(),token=await f.sign();
 const no=await fetchPrivate(req(HOST+'/index.wasm'),env(f),options(f));
 assert.equal(no.status,401);
 const wrong=await fetchPrivate(req(HOST+'/index.wasm',await f.sign({aud:'football'})),env(f),options(f));
 assert.equal(wrong.status,401);
 f.revoke();
 const rev=await fetchPrivate(req(HOST+'/index.wasm',token),env(f),options(f));
 assert.equal(rev.status,401);
 const down=await fetchPrivate(req(HOST+'/index.wasm',token),env(f),
  {...options(f),request:async()=>{throw Error('secret remote details');}});
 assert.equal(down.status,503);
 assert.equal(f.hits.length,0);
});
test('GET and HEAD never skip auth, write requests, range requests and R2 errors fail closed',async()=>{
 const f=await fixture(),token=await f.sign();
 const deny=await fetchPrivate(req(HOST+'/index.wasm',token,'PUT'),env(f),options(f));
 assert.equal(deny.status,405);
 const range=await fetchPrivate(req(HOST+'/index.wasm',token,'GET',{Range:'bytes=0-512'}),env(f),options(f));
 assert.equal(range.status,416);assert.equal(f.hits.length,0);
 const absent=await fetchPrivate(req(HOST+'/index.wasm',token),
  {...env(f),PAWN_ACTION_PRIVATE_R2:{get:async()=>null,head:async()=>null}},options(f));
 assert.equal(absent.status,404);
 const broken=await fetchPrivate(req(HOST+'/index.wasm',token),
  {...env(f),PAWN_ACTION_PRIVATE_R2:{get:async()=>{throw Error('R2 private transport');},head:async()=>null}},options(f));
 assert.equal(broken.status,503);
 assert.doesNotMatch(await broken.text(),/transport|R2 private/i);
});
test('session exchange followed by private GET succeeds; unauthenticated holding shell remains closed',async()=>{
 const f=await fixture(),token=await f.sign();
 const exchange=new Request(HOST+'/api/pawn-action/session',{method:'POST',
  headers:{Origin:HOST,'Content-Type':'application/json'},body:JSON.stringify({token})});
 const r=await fetchPrivate(exchange,env(f),options(f));
 assert.equal(r.status,200);
 const cookie=r.headers.get('Set-Cookie');
 assert.match(cookie,/; Secure; HttpOnly; SameSite=Lax;/);
 const game=await fetchPrivate(req(HOST+'/index.pck',cookie.slice(COOKIE.length+1).split(';')[0]),env(f),options(f));
 assert.equal(game.status,200);assert.equal(await game.text(),'private:index.pck');
 const legacy=lockedWorker.fetch(req(HOST+'/index.pck',token),env(f));
 assert.equal(legacy.status,503);
 assert.deepEqual(await legacy.json(),{error:'staging_locked'});
});
