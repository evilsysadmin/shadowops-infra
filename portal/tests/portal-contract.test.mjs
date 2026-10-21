import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');
test('Portal has standalone HTML, language and semantic main', () => {
  assert.match(read('../index.html'), /lang="es"/);
  assert.match(read('../src/main.js'), /el\('main', 'hero'\)/);
});
test('No mutation of DNS/Cloudflare, no dependencies on game asset URLs', () => {
  const manifest = read('../src/catalog.mjs');
  const scene = read('../src/world.js');
  assert.doesNotMatch(scene, /chess-studio\/.+\.(glb|gltf)/);
  assert.doesNotMatch(manifest, /cloudflare.*(token|secret)/i);
});
