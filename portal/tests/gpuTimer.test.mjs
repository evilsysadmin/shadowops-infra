import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createGpuTimer} from '../src/gpuTimer.mjs';

function fakeWebGL2({supportsTimer = true} = {}) {
  const queries = [];
  const deleted = [];
  let active = null;
  let disjoint = false;
  const extension = {TIME_ELAPSED_EXT: 0x88bf, GPU_DISJOINT_EXT: 0x8fbb};
  const gl = {
    QUERY_RESULT_AVAILABLE: 0x8867,
    QUERY_RESULT: 0x8866,
    getExtension(name) {
      assert.equal(name, 'EXT_disjoint_timer_query_webgl2');
      return supportsTimer ? extension : null;
    },
    createQuery() {
      const query = {ready: false, elapsedNs: 0};
      queries.push(query);
      return query;
    },
    beginQuery(target, query) {
      assert.equal(target, extension.TIME_ELAPSED_EXT);
      assert.equal(active, null);
      active = query;
    },
    endQuery(target) {
      assert.equal(target, extension.TIME_ELAPSED_EXT);
      assert.ok(active);
      active = null;
    },
    getQueryParameter(query, key) {
      if (key === gl.QUERY_RESULT_AVAILABLE) return query.ready;
      assert.equal(key, gl.QUERY_RESULT);
      assert.equal(query.ready, true, 'never request GPU elapsed result before availability');
      return query.elapsedNs;
    },
    getParameter(key) {
      assert.equal(key, extension.GPU_DISJOINT_EXT);
      return disjoint;
    },
    deleteQuery(query) { deleted.push(query); },
    isContextLost() { return false; },
  };
  return {gl, queries, deleted, setDisjoint(value) { disjoint = value; }};
}

test('missing GPU timer extension is explicitly unsupported and never allocates', () => {
  const {gl, queries} = fakeWebGL2({supportsTimer: false});
  const timer = createGpuTimer(gl);
  assert.equal(timer.begin(), false);
  timer.poll();
  timer.end();
  const sample = timer.snapshot();
  assert.equal(sample.status, 'unsupported');
  assert.equal(sample.medianMs, null);
  timer.dispose();
  assert.equal(queries.length, 0);
});

test('asynchronous GPU queries never block for an unavailable result; bounds and recycling hold', () => {
  const fake = fakeWebGL2();
  const timer = createGpuTimer(fake.gl, {maxPending: 2, maxSamples: 2});
  assert.equal(timer.begin(), true);
  timer.end();
  timer.poll();
  assert.equal(timer.snapshot().samples, 0);
  assert.equal(timer.begin(), true);
  timer.end();
  assert.equal(timer.begin(), false, 'pending cap prevents runaway GPU queries');
  assert.equal(timer.snapshot().skippedQueries, 1);
  fake.queries[0].elapsedNs = 2_000_000;
  fake.queries[0].ready = true;
  timer.poll();
  assert.equal(timer.snapshot().medianMs, 2);
  assert.equal(timer.snapshot().p95Ms, 2);

  assert.equal(timer.begin(), true);
  timer.end();
  assert.equal(fake.queries.length, 2, 'completed queries reused rather than allocated per frame');
  fake.queries[1].elapsedNs = 4_000_000;
  fake.queries[1].ready = true;
  fake.queries[0].elapsedNs = 6_000_000;
  timer.poll();
  assert.equal(timer.snapshot().samples, 2);
  assert.equal(timer.snapshot().medianMs, 4);
  assert.equal(timer.snapshot().p95Ms, 4);
  timer.dispose();
  assert.equal(fake.deleted.length, 2);
  assert.equal(timer.begin(), false);
});

test('GPU disjoint invalidates previous measurements and destroys outstanding queries', () => {
  const fake = fakeWebGL2();
  const timer = createGpuTimer(fake.gl);
  timer.begin();
  timer.end();
  fake.queries[0].ready = true;
  fake.queries[0].elapsedNs = 3_000_000;
  timer.poll();
  assert.equal(timer.snapshot().samples, 1);
  timer.begin();
  timer.end();
  fake.setDisjoint(true);
  timer.poll();
  const sample = timer.snapshot();
  assert.equal(sample.samples, 0);
  assert.equal(sample.medianMs, null);
  assert.equal(sample.disjointEvents, 1);
  assert.equal(fake.deleted.length, 1);
  fake.setDisjoint(false);
  assert.equal(timer.begin(), true);
  timer.end();
  assert.equal(fake.queries.length, 2);
  timer.dispose();
  assert.equal(fake.deleted.length, 2);
});

test('disposing an active query closes it and does not leave pending resources', () => {
  const fake = fakeWebGL2();
  const timer = createGpuTimer(fake.gl);
  assert.equal(timer.begin(), true);
  timer.dispose();
  timer.dispose();
  assert.equal(fake.deleted.length, 1);
});
