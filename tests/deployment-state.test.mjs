import test from 'node:test';
import assert from 'node:assert/strict';
import {transitionDeployment} from '../policy/deployment-state.mjs';
const digest='sha256:'+'a'.repeat(64);
const ctx={actor:'workflow-123',releaseDigest:digest};
test('permits staged verification sequence',()=>{
 let state={state:'pending',digest,version:0};
 for(const next of ['accredited','deploying','verifying','healthy']) state=transitionDeployment(state,next,ctx);
 assert.equal(state.version,4);
});
test('denies bypasses, digest swaps and missing actor',()=>{
 const state={state:'pending',digest,version:0};
 assert.throws(()=>transitionDeployment(state,'healthy',ctx));
 assert.throws(()=>transitionDeployment(state,'accredited',{...ctx,releaseDigest:'sha256:'+'b'.repeat(64)}));
 assert.throws(()=>transitionDeployment(state,'accredited',{...ctx,actor:''}));
 assert.throws(()=>transitionDeployment({...state,state:'failed'},'deploying',ctx));
});
