// Synthetic-only harness; never included in Pawn Action Pages holding shell.
import {handleSessionExchange} from '../../workers/pawn-action-staging/session-exchange.mjs';
export default {
 async fetch(request,env){
  return handleSessionExchange(request,env,{request:(url,init)=>env.FAKE_IDP.fetch(new Request(url,init))});
 },
};
