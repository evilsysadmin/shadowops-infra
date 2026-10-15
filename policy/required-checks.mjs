const REPO = 'evilsysadmin/chronicles-of-matthias';
const SHA = /^[a-f0-9]{40}$/;

export async function verifyRequiredChecks({sha, token, requiredContexts, fetchImpl = fetch}) {
  if (!SHA.test(sha || '') || !token) throw new Error('invalid credentials or SHA');
  if (!Array.isArray(requiredContexts) || !requiredContexts.length || requiredContexts.some(x => typeof x !== 'string' || !x)) throw new Error('explicit required checks needed');
  const url = 'https://api.github.com/repos/' + REPO + '/commits/' + sha + '/check-runs?per_page=100';
  const response = await fetchImpl(url, {headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'},redirect:'error'});
  if (!response.ok) throw new Error('check runs query failed');
  const data = await response.json();
  if (data.total_count > 100) throw new Error('check pagination not verified');
  const runs = data.check_runs;
  if (!Array.isArray(runs)) throw new Error('missing check runs');
  for (const name of requiredContexts) {
    const matches = runs.filter(x => x.name === name && x.head_sha === sha);
    if (matches.length !== 1 || matches[0].status !== 'completed' || matches[0].conclusion !== 'success') throw new Error('required check not accredited: '+name);
  }
  return Object.freeze({sha,requiredContexts:[...requiredContexts]});
}
