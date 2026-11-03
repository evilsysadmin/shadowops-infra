import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import worker from '../workers/pawn-action-staging/private-delivery.mjs';
import holding from '../workers/pawn-action-staging/edge.mjs';
import {LOGIN_LINK, SCRIPT_PATH, SESSION_SCRIPT} from '../workers/pawn-action-staging/browser-auth.mjs';
const HOST='https://staging.pawnaction.shadowops.dpdns.org';
const ID='https://id-staging.shadowops.dpdns.org';
const call=(url,init={},env={})=>worker.fetch(new Request(url,init),env);

test('anonymous homepage and exact central callback display sign-in, never stream Godot assets',async()=>{
 const fake={ASSETS:{fetch(){throw Error('must not use Pages assets')}},PAWN_ACTION_PRIVATE_R2:{
  get(){throw Error('must not read R2')},head(){throw Error('must not read R2')}
 }};
 for(const pathname of ['/', '/index.html', '/?shadowops=central']){
  const r=await call(HOST+pathname,{},fake);
  assert.equal(r.status,401,pathname);
  assert.equal(r.headers.get('Cache-Control'),'no-store, max-age=0');
  assert.equal(r.headers.get('Cross-Origin-Embedder-Policy'),null,
    'IdP cross-origin cookie fetch must not be blocked by Godot COEP');
  const csp=r.headers.get('Content-Security-Policy');
  assert.ok(csp.includes('connect-src \'self\' '+ID));
  assert.ok(csp.includes("script-src 'self'"));
  assert.ok(csp.includes("frame-ancestors 'none'"));
  const html=await r.text();
  assert.ok(html.includes(LOGIN_LINK));
  assert.ok(html.includes('<script src="'+SCRIPT_PATH+'" defer></script>'));
  assert.ok(html.includes('role="status"'));
  assert.doesNotMatch(html,/\.wasm|\.pck|token=/);
 }
 for(const pathname of ['/?shadowops=central&next=https://evil.test',
   '/?shadowops=other','/index.html?shadowops=central','/index.wasm?shadowops=central',
   '/?token=secret','/?shadowops=central%20']){
  const r=await call(HOST+pathname,{},fake);
  assert.equal(r.status,404,pathname);
 }
 const failed=await call(HOST+'/?shadowops=central',{method:'POST'},fake);
 assert.equal(failed.status,404);
 const alternate=await call('https://pawn-action-staging.pages.dev/?shadowops=central',{},fake);
 assert.equal(alternate.status,404);
});

test('public script is exact canonical GET/HEAD, without cookie, ID proof or R2 reads',async()=>{
 const response=await call(HOST+SCRIPT_PATH);
 assert.equal(response.status,200);
 assert.equal(response.headers.get('Content-Type'),'text/javascript; charset=utf-8');
 assert.equal(response.headers.get('Cache-Control'),'no-store, max-age=0');
 const source=await response.text();
 assert.equal(source,SESSION_SCRIPT);
 assert.ok(source.includes(ID+'/api/identity/token'));
 assert.ok(source.includes('/api/pawn-action/session'));
 assert.doesNotMatch(source,/localStorage|sessionStorage|console\.|document\.cookie|\.searchParams|postMessage/);
 const head=await call(HOST+SCRIPT_PATH,{method:'HEAD'});
 assert.equal(head.status,200);assert.equal(await head.text(),'');
 for(const [url,method,expected] of [
  [HOST+SCRIPT_PATH+'?v=1','GET',404],
  ['http://staging.pawnaction.shadowops.dpdns.org'+SCRIPT_PATH,'GET',404],
  ['https://pawn-action-staging.pages.dev'+SCRIPT_PATH,'GET',404],
  [HOST+SCRIPT_PATH,'POST',405],
  [HOST+SCRIPT_PATH,'DELETE',405],
 ]){
  const r=await call(url,{method});
  assert.equal(r.status,expected,url);
 }
 const home=await call(HOST+'/',{method:'HEAD'});
 assert.equal(home.status,401);assert.equal(await home.text(),'');
 const locked=holding.fetch(new Request(HOST+SCRIPT_PATH));
 assert.equal(locked.status,503,'deployed holding shell must not ship auth bootstrap');
});

async function simulate(tokenResponse,exchangeResponse){
 const calls=[],message={textContent:'Comprobando tu sesión…'},visits=[];
 const context={
  document:{querySelector(selector){assert.equal(selector,'[role="status"]');return message;}},
  location:{replace(url){visits.push(url);}},
  AbortSignal:{timeout(ms){assert.equal(ms,8000);return {deadline:true};}},
  fetch:async(url,init)=>{
   calls.push({url,init});
   if(url===ID+'/api/identity/token'){
    if(tokenResponse instanceof Error)throw tokenResponse;
    return tokenResponse;
   }
   if(url==='/api/pawn-action/session'){
    if(exchangeResponse instanceof Error)throw exchangeResponse;
    return exchangeResponse;
   }
   throw Error('Unexpected browser network endpoint '+url);
  },
  JSON,Error
 };
 await vm.runInNewContext(SESSION_SCRIPT,context);
 return {calls,message:message.textContent,visits};
}
test('browser token exchange sends credentials correctly and navigates only on success',async()=>{
 const token='signed.fixture.token';
 const a=await simulate({status:200,ok:true,json:async()=>({token})},{status:200,ok:true});
 assert.deepEqual(a.visits,['/']);
 assert.equal(a.calls.length,2);
 assert.equal(a.calls[0].url,ID+'/api/identity/token');
 assert.equal(a.calls[0].init.method,'POST');
 assert.equal(a.calls[0].init.credentials,'include');
 assert.equal(a.calls[0].init.body,'{}');
 assert.equal(a.calls[1].url,'/api/pawn-action/session');
 assert.equal(a.calls[1].init.credentials,'same-origin');
 assert.equal(a.calls[1].init.body,JSON.stringify({token}));
 assert.equal(a.calls[0].init.cache,'no-store');
 assert.equal(a.calls[1].init.cache,'no-store');
});
test('browser denies unauthenticated, invalid token, IdP outage and failed cookie exchange',async()=>{
 for(const status of [401,403]){
  const x=await simulate({ok:false,status},null);
  assert.equal(x.calls.length,1);
  assert.deepEqual(x.visits,[]);
  assert.match(x.message,/Inicia sesión/);
 }
 for(const first of [
  {ok:false,status:503},
  {ok:true,status:200,json:async()=>({token:''})},
  {ok:true,status:200,json:async()=>({token:'x'.repeat(4000)})},
  {ok:true,status:200,json:async()=>({aud:'football'})},
  new Error('token server down')
 ]){
  const x=await simulate(first,null);
  assert.deepEqual(x.visits,[]);
  assert.match(x.message,/no está disponible/);
  assert.equal(x.calls.length,1);
 }
 const broken=await simulate({status:200,ok:true,json:async()=>({token:'signed.test'})},
  {ok:false,status:401});
 assert.deepEqual(broken.visits,[]);
 assert.equal(broken.calls.length,2);
 assert.match(broken.message,/no está disponible/);
});
