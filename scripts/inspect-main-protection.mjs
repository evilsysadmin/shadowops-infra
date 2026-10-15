#!/usr/bin/env node
// Read-only diagnosis of Chronicles main protection. Does not modify GitHub.
import { pathToFileURL } from 'node:url';

const REPO = 'evilsysadmin/chronicles-of-matthias';
const API = 'https://api.github.com/repos/' + REPO;
export const PR_CHECKS = Object.freeze([
  'repository-contract', 'build-and-test', 'smoke', 'staging-image-policy'
]);

function includesMain(conditions) {
  const included = conditions?.ref_name?.include;
  if (!Array.isArray(included)) return false;
  return included.some(x => ['~DEFAULT_BRANCH', '~ALL', 'refs/heads/main', 'main'].includes(x));
}

export function diagnoseMainProtection(branch, rulesets) {
  const active = (Array.isArray(rulesets) ? rulesets : []).filter(r =>
    r?.target === 'branch' && r?.enforcement === 'active' && includesMain(r?.conditions)
  );
  const missingChecks = PR_CHECKS.filter(name => !active.some(r =>
    (r.rules || []).some(rule => rule.type === 'required_status_checks' &&
      (rule.parameters?.required_status_checks || []).some(check => check.context === name))
  ));
  const types = type => active.some(r => (r.rules || []).some(rule => rule.type === type));
  const blockers = [];
  if (branch?.protected !== true) blockers.push('GitHub reports main.protected=false');
  if (active.length === 0) blockers.push('no active branch ruleset targets main');
  if (!types('pull_request')) blockers.push('pull-request requirement absent');
  if (!types('non_fast_forward')) blockers.push('force-push protection absent');
  if (!types('deletion')) blockers.push('deletion protection absent');
  if (missingChecks.length) blockers.push('missing PR checks: ' + missingChecks.join(', '));
  return Object.freeze({
    verified: blockers.length === 0,
    branchProtected: branch?.protected === true,
    matchingRulesets: active.map(r => r.name),
    missingChecks,
    blockers
  });
}

export async function inspectMain({fetchImpl = fetch, token = ''} = {}) {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28'
  };
  if (token) headers.Authorization = 'Bearer ' + token;
  async function get(path) {
    const response = await fetchImpl(API + path, {headers, redirect:'error'});
    if (!response.ok) throw new Error('GitHub rules inspection failed: HTTP ' + response.status);
    return response.json();
  }
  const branch = await get('/branches/main');
  const listed = await get('/rulesets?includes_parents=true');
  if (!Array.isArray(listed)) throw new Error('invalid rulesets list');
  const detailed = await Promise.all(
    listed.filter(r => r?.target === 'branch' && r?.enforcement === 'active').map(r =>
      get('/rulesets/' + r.id)
    )
  );
  return diagnoseMainProtection(branch, detailed);
}

async function main() {
  try {
    const result = await inspectMain({token:process.env.GH_TOKEN || ''});
    console.log(JSON.stringify(result,null,2));
    if (!result.verified) process.exitCode = 1;
  } catch (error) {
    console.error('CHRONICLES_MAIN_PROTECTION_UNKNOWN: ' + error.message);
    process.exitCode = 1;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
