// Candidate-only POST /api/pawn-action/session. NOT imported by locked Pages edge.
import {authorize, COOKIE, IdentityDenied} from './identity-gate.mjs';
export const SESSION_PATH='/api/pawn-action/session';
export const ORIGIN='https://staging.pawnaction.shadowops.dpdns.org';
const MAX_BODY=8192;
const H={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store, max-age=0',
 'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY'};
const reply=(value,status,extra={})=>new Response(JSON.stringify(value),{status,headers:{...H,...extra}});
class BadRequest extends Error{constructor(status){super('exchange denied');this.status=status;}}
async function singleToken(body){
 if(!body?.getReader)throw new BadRequest(400);
 const reader=body.getReader(),decoder=new TextDecoder('utf-8',{fatal:true});
 let size=0,data='';
 try{
  for(;;){
   const {done,value}=await reader.read();if(done)break;
   size+=value.byteLength;
   if(size>MAX_BODY){await reader.cancel();throw new BadRequest(413);}
   data+=decoder.decode(value,{stream:true});
  }
  data+=decoder.decode();
 }catch(e){if(e instanceof BadRequest)throw e;throw new BadRequest(400);}
 finally{try{reader.releaseLock();}catch{}}
 // Strict single-field protocol prevents JSON duplicate-key smuggling.
 const matched=/^\{\s*"token"\s*:\s*"([A-Za-z0-9._-]{1,3500})"\s*\}$/.exec(data);
 if(!matched)throw new BadRequest(400);
 return matched[1];
}
export async function handleSessionExchange(request,env,options={}){
 try{
  const url=new URL(request.url);
  if(url.origin!==ORIGIN||url.pathname!==SESSION_PATH||url.port||url.search||url.hash||url.username||url.password)
   return reply({error:'not_found'},404);
  if(request.method!=='POST')return reply({error:'method_not_allowed'},405,{Allow:'POST'});
  if(request.headers.get('Origin')!==ORIGIN||
    (request.headers.has('Sec-Fetch-Site')&&request.headers.get('Sec-Fetch-Site')!=='same-origin'))
   return reply({error:'origin_denied'},403);
  if(request.headers.get('Content-Type')!=='application/json'||
     request.headers.has('Content-Encoding')||request.headers.has('Authorization'))
   return reply({error:'unsupported_request'},415);
  const length=request.headers.get('Content-Length');
  if(length!==null&&(!/^[0-9]+$/.test(length)||Number(length)>MAX_BODY))
   return reply({error:'request_too_large'},413);
  const token=await singleToken(request.body);
  const claims=await authorize(token,env,options);
  const seconds=Math.min(120,claims.exp-Math.floor(Date.now()/1000));
  if(!Number.isSafeInteger(seconds)||seconds<=0)return reply({error:'authentication_required'},401);
  return reply({subject:claims.sub,expires_at:claims.exp},200,{'Set-Cookie':
    COOKIE+'='+token+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='+seconds});
 }catch(e){
  if(e instanceof BadRequest)return reply({error:'invalid_request'},e.status);
  const status=e instanceof IdentityDenied?e.status:503;
  return reply({error:status===401?'authentication_required':'access_unavailable'},status);
 }
}
