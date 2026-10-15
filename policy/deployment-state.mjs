const transitions=Object.freeze({
 pending:['accredited','rejected'],
 accredited:['deploying','rejected'],
 deploying:['verifying','failed'],
 verifying:['healthy','failed'],
 healthy:['promoted','rollback_pending'],
 promoted:['rollback_pending'],
 rollback_pending:['rolling_back','failed'],
 rolling_back:['rolled_back','failed'],
 rejected:[],failed:[],rolled_back:[]
});
export function transitionDeployment(current,next,{actor,releaseDigest}={}) {
 if(!current || typeof current!=='object' || !Object.hasOwn(transitions,current.state)) throw new Error('invalid deployment state');
 if(!transitions[current.state].includes(next)) throw new Error('illegal deployment transition');
 if(typeof actor!=='string'||!/^[a-zA-Z0-9_-]{1,80}$/.test(actor)) throw new Error('missing authenticated actor');
 if(typeof releaseDigest!=='string'||!/^sha256:[a-f0-9]{64}$/.test(releaseDigest)||current.digest!==releaseDigest) throw new Error('release identity mismatch');
 if(!Number.isSafeInteger(current.version)||current.version<0) throw new Error('invalid state version');
 return Object.freeze({state:next,digest:current.digest,version:current.version+1,previousState:current.state,actor});
}
