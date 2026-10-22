import test from 'node:test';
import assert from 'node:assert/strict';
import {WORLDS, RESERVED_WORLDS, isLaunchable, worldById, worldsForHost, portalEnvironmentForHost, PORTAL_HOSTS} from '../src/catalog.mjs';

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

test('host routing is exact, not inferred from subdomains or query strings', () => {
  assert.equal(portalEnvironmentForHost('staging.shadowops.dpdns.org'), 'staging');
  assert.equal(portalEnvironmentForHost('shadowops.dpdns.org'), 'production');
  for (const host of ['localhost','127.0.0.1','example.com',
    'shadowops.dpdns.org.evil.example', 'staging.shadowops.dpdns.org.evil.example',
    'staging.chronicles.shadowops.dpdns.org', '']) {
    assert.equal(portalEnvironmentForHost(host), 'preview');
    assert.ok(worldsForHost(host).every(w => !isLaunchable(w) && w.destination === null));
  }
});
test('staging worlds never route to production hosts, including the Star Adventures staging game', () => {
  const worlds = worldsForHost(PORTAL_HOSTS.staging);
  assert.deepEqual(worlds.map(w => w.id), ['chess','chronicles','star']);
  const expected = {
    chess: 'staging.chess-studio.shadowops.dpdns.org',
    chronicles: 'staging.chronicles.shadowops.dpdns.org',
    star: 'staging.staradvs.shadowops.dpdns.org',
  };
  for (const world of worlds) {
    assert.ok(isLaunchable(world));
    assert.equal(new URL(world.destination).hostname,expected[world.id]);
  }
  assert.equal(worldById('star',worlds).destination,'https://staging.staradvs.shadowops.dpdns.org/');
});
test('production links are production-only and do not expose an unreleased Star Adventures', () => {
  const worlds = worldsForHost(PORTAL_HOSTS.production);
  assert.equal(worldById('chess',worlds).destination,'https://chess-studio.shadowops.dpdns.org/');
  assert.equal(worldById('chronicles',worlds).destination,'https://chronicles.shadowops.dpdns.org/');
  assert.equal(worldById('star',worlds).destination,null);
  assert.equal(isLaunchable(worldById('star',worlds)),false);
  assert.ok(Object.isFrozen(worlds));
  assert.ok(worlds.every(Object.isFrozen));
});
