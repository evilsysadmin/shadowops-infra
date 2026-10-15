const SCOPE='chronicles-api';
export function validateLock(lock, nowMs=Date.now()) {
 if(!lock || typeof lock!=='object' || Array.isArray(lock)) throw new Error('invalid lock');
 if(Object.keys(lock).some(k=>!['service','holder','leaseUntil','fencingToken'].includes(k))) throw new Error('unexpected lock field');
 if(lock.service!==SCOPE || typeof lock.holder!=='string' || !/^[a-zA-Z0-9_-]{1,80}$/.test(lock.holder)) throw new Error('invalid lock owner');
 if(!Number.isSafeInteger(lock.fencingToken) || lock.fencingToken<1) throw new Error('invalid fencing token');
 if(!Number.isSafeInteger(lock.leaseUntil) || lock.leaseUntil<=nowMs) throw new Error('expired lock');
 return Object.freeze({...lock});
}
export function assertFencedOperation(lock, operation, nowMs=Date.now()) {
 const valid=validateLock(lock,nowMs);
 if(!operation || operation.service!==valid.service || operation.holder!==valid.holder || operation.fencingToken!==valid.fencingToken) throw new Error('stale or foreign deploy operation');
 return valid;
}
