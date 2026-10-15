import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyRequiredChecks} from '../policy/required-checks.mjs';
const sha='a'.repeat(40);
const run={name:'tests',head_sha:sha,status:'completed',conclusion:'success'};
const mock=data=>async()=>({ok:true,json:async()=>data});
test('requires explicit green checks',async()=>assert.equal((await verifyRequiredChecks({sha,token:'test',requiredContexts:['tests'],fetchImpl:mock({total_count:1,check_runs:[run]})})).sha,sha));
test('fails closed on missing, failed, ambiguous or paginated checks',async()=>{
 for(const data of [{total_count:0,check_runs:[]},{total_count:1,check_runs:[{...run,conclusion:'failure'}]},{total_count:2,check_runs:[run,run]},{total_count:101,check_runs:[run]}]) await assert.rejects(verifyRequiredChecks({sha,token:'test',requiredContexts:['tests'],fetchImpl:mock(data)}));
 await assert.rejects(verifyRequiredChecks({sha,token:'test',requiredContexts:[],fetchImpl:mock({total_count:1,check_runs:[run]})}));
});
