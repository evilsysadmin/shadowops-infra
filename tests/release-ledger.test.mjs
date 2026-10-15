import test from 'node:test';
import assert from 'node:assert/strict';
import {validateLedger,rollbackTarget} from '../policy/release-ledger.mjs';
const receipt={repository:'evilsysadmin/chronicles-of-matthias',service:'chronicles-api',sha:'a'.repeat(40),digest:'sha256:'+'b'.repeat(64),environment:'staging',workflowRunId:17,healthPassed:true,smokePassed:true,deployedAt:'2026-10-15T12:00:00Z'};
const previous={environment:'production',digest:receipt.digest,sha:receipt.sha,receipt,deployedAt:'2026-10-15T13:00:00Z'};
const latestReceipt={...receipt,sha:'c'.repeat(40),digest:'sha256:'+'d'.repeat(64)};
const latest={environment:'production',digest:latestReceipt.digest,sha:latestReceipt.sha,receipt:latestReceipt,deployedAt:'2026-10-15T14:00:00Z'};
const ledger={schemaVersion:1,service:'chronicles-api',history:[previous,latest],activeDigest:latest.digest};
test('rollback selects prior accredited digest',()=>assert.equal(rollbackTarget(ledger).digest,previous.digest));
test('rejects invented active digest and altered evidence',()=>{
 assert.throws(()=>validateLedger({...ledger,activeDigest:'sha256:'+'e'.repeat(64)}));
 assert.throws(()=>validateLedger({...ledger,history:[{...previous,sha:'f'.repeat(40)},latest]}));
 assert.throws(()=>rollbackTarget({...ledger,history:[latest]}));
});
