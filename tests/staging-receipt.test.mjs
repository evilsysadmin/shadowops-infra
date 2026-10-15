import test from 'node:test';
import assert from 'node:assert/strict';
import {createStagingReceipt,assertPromotionCandidate} from '../policy/staging-receipt.mjs';
const r={repository:'evilsysadmin/chronicles-of-matthias',service:'chronicles-api',sha:'a'.repeat(40),digest:'sha256:'+'b'.repeat(64),environment:'staging',workflowRunId:17,healthPassed:true,smokePassed:true,deployedAt:'2026-10-15T12:00:00Z'};
test('records only healthy, smoke-tested staging identities',()=>assert.equal(createStagingReceipt(r).digest,r.digest));
test('denies missing tests and altered release',()=>{
 for(const [k,v] of [['healthPassed',false],['smokePassed',false],['environment','production'],['digest','latest'],['workflowRunId',0],['deployedAt','bad'],['command','untrusted']]) assert.throws(()=>createStagingReceipt({...r,[k]:v}),k);
 assert.throws(()=>assertPromotionCandidate(r,{service:r.service,sha:r.sha,digest:'sha256:'+'c'.repeat(64)}));
 assert.equal(assertPromotionCandidate(r,{service:r.service,sha:r.sha,digest:r.digest}).workflowRunId,17);
});
