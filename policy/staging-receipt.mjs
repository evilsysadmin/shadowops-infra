const SHA=/^[a-f0-9]{40}$/;
const DIGEST=/^sha256:[a-f0-9]{64}$/;
export function createStagingReceipt(input) {
 if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('invalid receipt');
 const allowed=['repository','service','sha','digest','environment','workflowRunId','healthPassed','smokePassed','deployedAt'];
 if(Object.keys(input).some(k=>!allowed.includes(k))) throw new Error('unexpected field');
 if(input.repository!=='evilsysadmin/chronicles-of-matthias' || input.service!=='chronicles-api' || input.environment!=='staging') throw new Error('wrong deployment scope');
 if(!SHA.test(input.sha||'') || !DIGEST.test(input.digest||'')) throw new Error('untrusted release identity');
 if(!Number.isSafeInteger(input.workflowRunId)||input.workflowRunId<=0) throw new Error('invalid workflow run');
 if(input.healthPassed!==true || input.smokePassed!==true) throw new Error('staging tests not passed');
 if(typeof input.deployedAt!=='string'||!/^\d{4}-\d{2}-\d{2}T/.test(input.deployedAt)||!Number.isFinite(Date.parse(input.deployedAt))) throw new Error('invalid timestamp');
 return Object.freeze({...input});
}
export function assertPromotionCandidate(receipt, candidate) {
 const r=createStagingReceipt(receipt);
 if(!candidate || candidate.sha!==r.sha || candidate.digest!==r.digest || candidate.service!==r.service) throw new Error('promotion identity mismatch');
 return r;
}
