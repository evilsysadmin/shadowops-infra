import {createStagingReceipt} from './staging-receipt.mjs';
const digest=/^sha256:[a-f0-9]{64}$/;
export function validateLedger(ledger) {
 if(!ledger || typeof ledger!=='object' || Array.isArray(ledger)) throw new Error('invalid ledger');
 if(ledger.schemaVersion!==1 || ledger.service!=='chronicles-api' || !Array.isArray(ledger.history)) throw new Error('unsupported ledger');
 if(ledger.history.length>100 || Object.keys(ledger).some(k=>!['schemaVersion','service','history','activeDigest'].includes(k))) throw new Error('invalid ledger fields');
 const seen=new Set();
 for(const entry of ledger.history) {
  if(!entry || typeof entry!=='object' || !['staging','production'].includes(entry.environment) || !digest.test(entry.digest||'')) throw new Error('invalid release event');
  if(Object.keys(entry).some(k=>!['environment','digest','sha','receipt','deployedAt'].includes(k))) throw new Error('unexpected release event field');
  if(seen.has(entry.environment+':'+entry.deployedAt)) throw new Error('duplicate release event');
  seen.add(entry.environment+':'+entry.deployedAt);
  const receipt=createStagingReceipt(entry.receipt);
  if(receipt.digest!==entry.digest || receipt.sha!==entry.sha) throw new Error('receipt identity mismatch');
  if(typeof entry.deployedAt!=='string' || !Number.isFinite(Date.parse(entry.deployedAt))) throw new Error('invalid deployment time');
 }
 if(ledger.activeDigest!==null && ledger.activeDigest!==undefined && !ledger.history.some(e=>e.environment==='production' && e.digest===ledger.activeDigest)) throw new Error('active digest not in production history');
 return ledger;
}
export function rollbackTarget(ledger) {
 validateLedger(ledger);
 const prod=ledger.history.filter(x=>x.environment==='production');
 const previous=[...prod].reverse().find(x=>x.digest!==ledger.activeDigest);
 if(!previous) throw new Error('no previous accredited production release');
 return Object.freeze({sha:previous.sha,digest:previous.digest,receipt:previous.receipt});
}
