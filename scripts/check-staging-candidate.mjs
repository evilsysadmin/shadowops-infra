#!/usr/bin/env node
// Read-only staging admission. No deploy, secret export or registry mutation.
import { pathToFileURL } from 'node:url';
import { evaluateRelease } from '../policy/release-admission.mjs';

const SOURCE = 'evilsysadmin/chronicles-of-matthias';
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;

export function parseCandidateArgs(argv) {
  if (!Array.isArray(argv) || argv.length !== 6) {
    throw new Error('usage: --sha FULL_SHA --digest sha256:HEX --run-id GITHUB_RUN_ID');
  }
  const allowed = new Set(['--sha','--digest','--run-id']);
  const pairs = new Map();
  for (let i=0;i<argv.length;i+=2) {
    if (!allowed.has(argv[i]) || pairs.has(argv[i]) ||
        !argv[i+1] || argv[i+1].startsWith('--')) {
      throw new Error('invalid staging admission argument');
    }
    pairs.set(argv[i],argv[i+1]);
  }
  if (pairs.size !== 3 || !SHA.test(pairs.get('--sha')||'') ||
      !DIGEST.test(pairs.get('--digest')||'') ||
      !/^[1-9][0-9]*$/.test(pairs.get('--run-id')||'')) {
    throw new Error('invalid candidate SHA, digest or source run');
  }
  const runId=Number(pairs.get('--run-id'));
  if (!Number.isSafeInteger(runId)) throw new Error('invalid source run identifier');
  return Object.freeze({
    candidate:Object.freeze({
      repository:SOURCE,
      service:'chronicles-api',
      environment:'staging',
      sha:pairs.get('--sha'),
      digest:pairs.get('--digest'),
    }),
    runId
  });
}

// Fixed source identity: never accept dispatch actorRepository or
// required check names from a remote payload.
export async function inspectCandidate({argv,token,evaluator=evaluateRelease}) {
  if (typeof token!=='string' || !token) throw new Error('GH_TOKEN is required for admission');
  const {candidate,runId}=parseCandidateArgs(argv);
  return evaluator({
    candidate,runId,token,
    context:{event:'repository_dispatch',actorRepository:SOURCE}
  });
}

async function main() {
  try {
    const result=await inspectCandidate({
      argv:process.argv.slice(2),
      token:process.env.GH_TOKEN
    });
    console.log('STAGING_CANDIDATE_ACCREDITED sha='+result.sha+
      ' digest='+result.digest+' source_run='+result.workflowRunId);
  } catch (error) {
    console.error('STAGING_CANDIDATE_BLOCKED: '+error.message);
    process.exitCode=1;
  }
}

if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  await main();
}
