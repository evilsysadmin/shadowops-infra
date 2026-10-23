import {test} from 'node:test';
import assert from 'node:assert/strict';
import {toProfileUrl,classifyRenderer,assessGpuSnapshot} from '../scripts/gpu-profile-utils.mjs';

test('local GPU profiler adds opt-in without changing host or path', () => {
  assert.equal(toProfileUrl('http://127.0.0.1:4173/'), 'http://127.0.0.1:4173/?portal_perf=1');
  assert.equal(toProfileUrl('https://staging.shadowops.dpdns.org/?portal_perf=0'),
    'https://staging.shadowops.dpdns.org/?portal_perf=1');
  assert.throws(()=>toProfileUrl('file:///tmp/index.html'),/HTTP/);
  assert.throws(()=>toProfileUrl('https://login:secret@example.org/'),/HTTP/);
});

test('software or absent GPU evidence can never qualify for physical acceptance', () => {
  assert.equal(classifyRenderer('ANGLE (Google, Vulkan SwiftShader Device)'), 'software-suspected');
  assert.equal(classifyRenderer('Mesa llvmpipe (LLVM 19)'), 'software-suspected');
  assert.equal(classifyRenderer('AMD Radeon RX'), 'unverified');
  const available={gpuTimeMs:{status:'available',samples:55,medianMs:3.2,p95Ms:6}};
  assert.equal(assessGpuSnapshot(available,'SwiftShader').state,'not-qualified');
  assert.equal(assessGpuSnapshot({gpuTimeMs:{status:'unsupported',samples:0}},'AMD').state,'not-qualified');
  assert.equal(assessGpuSnapshot(available,'AMD Radeon RX').state,'review-required');
  assert.equal(assessGpuSnapshot(null,null).state,'not-qualified');
});
