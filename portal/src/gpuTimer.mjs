// Non-blocking, opt-in WebGL2 timer queries. No GPU readback or forced finish().
// The extension is optional (especially under virtualized/headless Chromium).
const roundMs = value => Math.round(value * 1000) / 1000;

function percentile(samples, quantile) {
  if (!samples.length) return null;
  const sorted = [...samples].sort((a, b) => a - b);
  return roundMs(sorted[Math.floor((sorted.length - 1) * quantile)]);
}

export function createGpuTimer(gl, {maxPending = 2, maxSamples = 120} = {}) {
  const extension = typeof gl?.createQuery === 'function' &&
    typeof gl?.beginQuery === 'function' &&
    typeof gl?.endQuery === 'function' &&
    typeof gl?.getQueryParameter === 'function'
    ? gl.getExtension('EXT_disjoint_timer_query_webgl2') : null;

  if (!extension) {
    return {
      poll() {},
      begin() { return false; },
      end() {},
      snapshot() {
        return {status: 'unsupported', samples: 0, medianMs: null, p95Ms: null,
          disjointEvents: 0, skippedQueries: 0};
      },
      dispose() {},
    };
  }

  const pending = [];
  const reusable = [];
  const samples = [];
  let active = null;
  let disposed = false;
  let disjointEvents = 0;
  let skippedQueries = 0;
  let contextLost = false;

  function deleteOutstanding() {
    for (const query of pending.splice(0)) gl.deleteQuery(query);
    for (const query of reusable.splice(0)) gl.deleteQuery(query);
  }

  return {
    poll() {
      if (disposed || contextLost) return;
      if (gl.isContextLost?.()) {
        contextLost = true;
        samples.length = 0;
        deleteOutstanding();
        return;
      }
      if (!pending.length) return;
      // GPU_DISJOINT invalidates all measurements since the preceding poll.
      // Never recycle queries still pending when the GPU has gone disjoint.
      if (gl.getParameter(extension.GPU_DISJOINT_EXT)) {
        disjointEvents++;
        samples.length = 0;
        deleteOutstanding();
        return;
      }
      while (pending.length && gl.getQueryParameter(pending[0], gl.QUERY_RESULT_AVAILABLE)) {
        const query = pending.shift();
        const elapsedNs = gl.getQueryParameter(query, gl.QUERY_RESULT);
        reusable.push(query);
        if (Number.isFinite(elapsedNs) && elapsedNs >= 0) {
          samples.push(elapsedNs / 1e6);
          if (samples.length > maxSamples) samples.shift();
        }
      }
    },
    begin() {
      if (disposed || contextLost || active) return false;
      if (pending.length >= maxPending) {
        skippedQueries++;
        return false;
      }
      const query = reusable.pop() || gl.createQuery();
      if (!query) {
        skippedQueries++;
        return false;
      }
      gl.beginQuery(extension.TIME_ELAPSED_EXT, query);
      active = query;
      return true;
    },
    end() {
      if (!active || disposed) return;
      gl.endQuery(extension.TIME_ELAPSED_EXT);
      pending.push(active);
      active = null;
    },
    snapshot() {
      return {
        status: contextLost ? 'context-lost' : samples.length ? 'available' : 'collecting',
        samples: samples.length,
        medianMs: percentile(samples, .5),
        p95Ms: percentile(samples, .95),
        disjointEvents,
        skippedQueries,
      };
    },
    dispose() {
      if (disposed) return;
      if (active) {
        gl.endQuery(extension.TIME_ELAPSED_EXT);
        gl.deleteQuery(active);
        active = null;
      }
      deleteOutstanding();
      disposed = true;
      samples.length = 0;
    },
  };
}
