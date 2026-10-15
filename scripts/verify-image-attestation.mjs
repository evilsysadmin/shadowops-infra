import { spawnSync } from 'node:child_process';
const REPO = 'evilsysadmin/chronicles-of-matthias';
const IMAGE = 'ghcr.io/evilsysadmin/chronicles-api';
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;

export function attestationCommand({sha,digest}) {
  if (!SHA.test(sha || '') || !DIGEST.test(digest || '')) throw new Error('invalid SHA or digest');
  return ['attestation','verify',IMAGE+'@'+digest,'--repo',REPO,'--format','json'];
}
export function verifyImage({sha,digest,runner=spawnSync}) {
  const args=attestationCommand({sha,digest});
  const result=runner('gh',args,{encoding:'utf8',timeout:60000,maxBuffer:2*1024*1024});
  if(result.error || result.status !== 0) throw new Error('attestation verification failed');
  let attestations;
  try { attestations=JSON.parse(result.stdout); } catch {throw new Error('invalid attestation output');}
  if (!Array.isArray(attestations) || !attestations.length) throw new Error('missing verified attestations');
  const valid=attestations.some(entry => {
    const statement=entry?.verificationResult?.statement;
    const predicate=statement?.predicate;
    const subjects=statement?.subject;
    return Array.isArray(subjects) && subjects.some(subject=>subject.digest?.sha256===digest.slice(7))
      && predicate?.buildDefinition?.externalParameters?.workflow?.repository===('https://github.com/'+REPO)
      && predicate?.buildDefinition?.resolvedDependencies?.some(dep=>dep.digest?.gitCommit===sha);
  });
  if(!valid) throw new Error('verified provenance does not match source commit');
  return {sha,digest,verified:true};
}
