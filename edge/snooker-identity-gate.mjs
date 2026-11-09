// Infra-owned Pages Worker: exact Snooker host, live Identity and no preview aliases.
// Pages edge authority. Only this server checks JWT signatures and live Identity
// freshness. No service proof, signing key or JWT is persisted in browser storage.
export const HOST='staging.snooker.shadowops.dpdns.org';
export const ISSUER='https://id-staging.shadowops.dpdns.org';
export const AUDIENCE='snooker';
const COOKIE='__Host-snooker_staging';
// workerd requires the native global receiver; Node accepts detached fetch.
const publicRequest=(...args)=>globalThis.fetch(...args);
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
class Denied extends Error{constructor(status=401,stage='session'){super('session unavailable');this.status=status;this.stage=stage;}}
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'};
function json(value,status=200,extra={}){return new Response(JSON.stringify(value),{status,headers:{...headers,'Content-Type':'application/json',...extra}});}
function decode(value){
 if(!/^[A-Za-z0-9_-]+$/.test(value))throw new Denied();
 return Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')),x=>x.charCodeAt(0));
}
async function limitedBody(body,max,status){
 const reader=body?.getReader();if(!reader)return '';let bytes=0,text='';const decoder=new TextDecoder('utf-8',{fatal:true});
 try{for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>max){await reader.cancel();throw new Denied(status);}text+=decoder.decode(value,{stream:true});}return text+decoder.decode();}finally{reader.releaseLock();}
}
async function upstream(request,url,init,stage){
 try{const response=await request(url,init);if(!response.ok)throw new Denied(response.status===401?401:503,stage);return response;}
 catch(error){if(error instanceof Denied)throw error;throw new Denied(503,stage);}
}
async function bounded(response,max=32768){
 if(!response.ok)throw new Denied(response.status===401?401:503);
 const text=await limitedBody(response.body,max,503);
 try{return JSON.parse(text);}catch{throw new Denied(503);}
}
export async function verifyIdentityToken(token,{request=publicRequest,now=Math.floor(Date.now()/1000),subtle=crypto.subtle}={}){
 if(typeof token!=='string'||token.length>8192)throw new Denied();
 const parts=token.split('.');if(parts.length!==3)throw new Denied();
 let header,claims;
 try{header=JSON.parse(new TextDecoder().decode(decode(parts[0])));claims=JSON.parse(new TextDecoder().decode(decode(parts[1])));}catch{throw new Denied();}
 if(header.alg!=='EdDSA'||typeof header.kid!=='string'||header.kid.length>128||header.crit||header.jku||header.x5u)throw new Denied();
 if(claims.iss!==ISSUER||claims.aud!==AUDIENCE||!UUID.test(claims.sub)||!Number.isSafeInteger(claims.sv)||claims.sv<1
   ||typeof claims.jti!=='string'||!claims.jti||claims.jti.length>128
   ||![claims.iat,claims.nbf,claims.exp].every(Number.isSafeInteger)||claims.iat>now+5||claims.nbf>now+5
   ||claims.exp<=now||claims.exp<=claims.iat||claims.exp-claims.iat>120||claims.nbf<claims.iat-5)throw new Denied();
 const jwks=await bounded(await upstream(request,ISSUER+'/api/identity/jwks',{headers:{'Accept':'application/json','User-Agent':'ShadowOps-Snooker-Edge/1.0'},redirect:'manual',signal:AbortSignal.timeout(5000)},'identity_keys'));
 if(!Array.isArray(jwks.keys)||jwks.keys.length>20)throw new Denied(503);
 const matches=jwks.keys.filter(key=>key.kid===header.kid&&key.kty==='OKP'&&key.crv==='Ed25519'&&key.use==='sig'&&!key.d);
 if(matches.length!==1)throw new Denied();
 try{
  const key=await subtle.importKey('jwk',matches[0],{name:'Ed25519'},false,['verify']);
  if(!await subtle.verify({name:'Ed25519'},key,decode(parts[2]),new TextEncoder().encode(parts[0]+'.'+parts[1])))throw new Denied();
 }catch{throw new Denied();}
 return claims;
}
export async function authorize(token,env,{request=publicRequest,now=Math.floor(Date.now()/1000),subtle=crypto.subtle}={}){
 const proof=env.SHADOWOPS_SNOOKER_SERVICE_CREDENTIAL;
 if(typeof proof!=='string'||!/^soc1_[A-Za-z0-9_-]{43}$/.test(proof))throw new Denied(503,'edge_configuration');
 const claims=await verifyIdentityToken(token,{request,now,subtle});
 const response=await upstream(request,ISSUER+'/api/identity/freshness',{method:'POST',redirect:'manual',signal:AbortSignal.timeout(5000),
  headers:{'Content-Type':'application/json','Authorization':'Bearer '+proof,'User-Agent':'ShadowOps-Snooker-Edge/1.0'},
  body:JSON.stringify({subject:claims.sub,session_version:claims.sv,token_jti:claims.jti})},'identity_freshness');
 const live=await bounded(response,8192);
 if(live.issuer!==ISSUER||live.audience!==AUDIENCE||live.subject!==claims.sub||live.session_version!==claims.sv||live.token_jti!==claims.jti
  ||live.account_active!==true||live.session_active!==true||live.token_active!==true||!Number.isSafeInteger(live.checked_at)
  ||live.checked_at>now+5||now-live.checked_at>5)throw new Denied();
 return claims;
}

function cookie(request){
 const matches=(request.headers.get('Cookie')||'').split(';').map(x=>x.trim()).filter(x=>x.startsWith(COOKIE+'='));
 if(matches.length!==1)throw new Denied();return matches[0].slice(COOKIE.length+1);
}
const bootstrap=`const status=document.querySelector('[role=status]');
(async()=>{try{
 const response=await fetch('${ISSUER}/api/identity/token',{method:'POST',credentials:'include',cache:'no-store',headers:{'Content-Type':'application/json'},body:'{}',signal:AbortSignal.timeout(8000)});
 if(response.status===401){status.textContent='Entra con tu cuenta de ShadowOps ID para jugar.';return;}
 if(!response.ok)throw Error();const value=await response.json();
 const session=await fetch('/api/snooker/session',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:value.token}),signal:AbortSignal.timeout(8000)});
 if(!session.ok)throw Error();location.replace('/');
}catch{status.textContent='El acceso con ShadowOps ID aún no está disponible. Vuelve a intentarlo en unos minutos.';}})();`;
function login(status=401){
 const body=`<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Snooker · ShadowOps ID</title><style>body{margin:0;background:#08130d;color:#f4e9d1;font:18px system-ui;min-height:100vh;display:grid;place-items:center}main{max-width:34rem;margin:1rem;padding:2rem;border:1px solid #52634c;border-radius:18px}a,button{display:inline-block;padding:14px 18px;background:#d6c18b;color:#132115;border:0;border-radius:9px;font:inherit;text-decoration:none}p{line-height:1.6}small{color:#b8c8ad}a:focus-visible,button:focus-visible{outline:3px solid #9ef4b1;outline-offset:4px}</style><main><small>SNOOKER OF MATTHIAS</small><h1>Tu cuenta ShadowOps ID</h1><p role="status">Comprobando tu sesión…</p><a href="${ISSUER}/login?app=snooker">Entrar con ShadowOps ID</a><p><small>Una mesa 3D protegida mediante ShadowOps ID.</small></p></main><script src="/_shadowops/session.js" defer></script></html>`;
 return new Response(body,{status,headers:{...headers,'Content-Type':'text/html; charset=utf-8',
  'Content-Security-Policy':`default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self' ${ISSUER}; base-uri 'none'; frame-ancestors 'none'; form-action ${ISSUER}`}});
}
export async function handle(request,env,options={}){
 const url=new URL(request.url);
 if(url.hostname!==HOST)return new Response('Not found',{status:404,headers});
 if(url.pathname==='/_shadowops/session.js'&&request.method==='GET')return new Response(bootstrap,{headers:{...headers,'Content-Type':'text/javascript; charset=utf-8'}});
 try{
  if(url.pathname==='/api/snooker/session'&&request.method==='POST'){
   if(url.search||request.headers.get('Origin')!=='https://'+HOST||request.headers.get('Content-Type')!=='application/json')throw new Denied(403);
   const raw=await limitedBody(request.body,9000,413);
   let body;try{body=JSON.parse(raw);}catch{throw new Denied(400);}
   if(!body||Object.keys(body).length!==1||!Object.hasOwn(body,'token'))throw new Denied(400);
   const claims=await authorize(body.token,env,options);
   return json({subject:claims.sub,expires_at:claims.exp,identity:'snooker'},200,{'Set-Cookie':`${COOKIE}=${body.token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${Math.max(0,claims.exp-Math.floor(Date.now()/1000))}`});
  }
  if(url.pathname==='/api/snooker/logout'&&request.method==='POST'){
   if(url.search||request.headers.get('Origin')!=='https://'+HOST)throw new Denied(403);
   return json({signed_out:true},200,{'Set-Cookie':`${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`});
  }
  if(!['GET','HEAD'].includes(request.method))throw new Denied(405);
  const claims=await authorize(cookie(request),env,options);
  if(url.pathname==='/api/snooker/session')return json({subject:claims.sub,expires_at:claims.exp,identity:'snooker'});
  if(url.pathname.startsWith('/api/'))return json({error:'not_found'},404);
  const response=await env.ASSETS.fetch(request);const next=new Response(response.body,response);
  next.headers.set('Cache-Control','no-store');return next;
 }catch(error){
  const status=error instanceof Denied?error.status:503;
  if(url.pathname==='/'||url.pathname==='/index.html')return login(status===401?401:503);
  return json({error:status===401?'authentication_required':'access_unavailable'},status,status===503?{'X-Snooker-Identity-Error':error instanceof Denied?error.stage:'edge_runtime'}:{});
 }
}
export default {fetch:handle};
