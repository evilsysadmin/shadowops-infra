import test from 'node:test';
import assert from 'node:assert/strict';
import {validateLock,assertFencedOperation} from '../policy/release-lock.mjs';
const now=1000;
const lock={service:'chronicles-api',holder:'workflow-123',leaseUntil:2000,fencingToken:9};
test('accepts live fenced owner',()=>assert.equal(assertFencedOperation(lock,{service:lock.service,holder:lock.holder,fencingToken:9},now).fencingToken,9));
test('rejects stale, foreign, expired or malformed leases',()=>{
 for(const candidate of [{...lock,leaseUntil:now},{...lock,fencingToken:0},{...lock,service:'chess-studio'},{...lock,command:'deploy'}]) assert.throws(()=>validateLock(candidate,now));
 for(const op of [{service:lock.service,holder:lock.holder,fencingToken:8},{service:lock.service,holder:'other',fencingToken:9}]) assert.throws(()=>assertFencedOperation(lock,op,now));
});
