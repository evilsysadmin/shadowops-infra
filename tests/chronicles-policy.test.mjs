import test from 'node:test';
import assert from 'node:assert/strict';
import { admitCandidate } from '../policy/chronicles.mjs';
const context = { event: 'repository_dispatch', actorRepository: 'evilsysadmin/chronicles-of-matthias' };
const candidate = { repository: context.actorRepository, service: 'chronicles-api', sha: 'a'.repeat(40), digest: 'sha256:' + 'b'.repeat(64), environment: 'staging' };
test('admission accepts a pinned Chronicles staging candidate', () => assert.deepEqual(admitCandidate(candidate, context), candidate));
test('admission denies untrusted requests', () => {
  for (const [key, value] of [['repository','evilsysadmin/chess-studio'],['service','chess-api'],['sha','main'],['digest','latest'],['environment','production'],['command','echo injected']]) {
    assert.throws(() => admitCandidate({...candidate,[key]:value},context),key);
  }
  assert.throws(() => admitCandidate(candidate,{...context,actorRepository:'evilsysadmin/chess-studio'}));
  assert.throws(() => admitCandidate(candidate,{...context,event:'workflow_dispatch'}));
});
