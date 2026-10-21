import test from 'node:test';
import assert from 'node:assert/strict';
import {WORLDS, RESERVED_WORLDS, isLaunchable, worldById} from '../src/catalog.mjs';

test('Three primary worlds have unique stable IDs and titles', () => {
  assert.deepEqual(WORLDS.map(w => w.id), ['chess', 'chronicles', 'star']);
  assert.equal(new Set(WORLDS.map(w => w.id)).size, WORLDS.length);
  assert.equal(new Set(WORLDS.map(w => w.title)).size, WORLDS.length);
  assert.equal(worldById('unknown'), null);
  assert.ok(RESERVED_WORLDS.includes('Pawn Trailblazer'));
});
test('Only explicitly configured external destinations can launch', () => {
  for (const world of WORLDS) {
    if (!isLaunchable(world)) {
      assert.equal(world.destination, null);
      continue;
    }
    const url = new URL(world.destination);
    assert.equal(url.protocol, 'https:');
    assert.equal(url.hostname.endsWith('.shadowops.dpdns.org'), true);
    assert.equal(world.state, 'external-unverified');
  }
  assert.equal(isLaunchable(worldById('star')), false);
});
