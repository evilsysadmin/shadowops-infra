// Small pure helpers shared by the local, user-run GPU profiling CLI and tests.
export function toProfileUrl(address) {
  const url = new URL(address);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error('Expected a credential-free HTTP(S) portal URL');
  }
  url.searchParams.set('portal_perf', '1');
  return url.href;
}

export function classifyRenderer(renderer) {
  const description = typeof renderer === 'string' ? renderer : '';
  return /swiftshader|llvmpipe|softpipe|software raster|mesa offscreen/i.test(description)
    ? 'software-suspected' : 'unverified';
}

export function assessGpuSnapshot(performance, renderer) {
  const gpu = performance?.gpuTimeMs;
  const classification = classifyRenderer(renderer);
  if (classification === 'software-suspected') {
    return {state:'not-qualified',reason:'software renderer suspected'};
  }
  if (gpu?.status !== 'available' || !(gpu.samples > 0)) {
    return {state:'not-qualified',reason:'valid GPU timer queries unavailable'};
  }
  // Measurements are candidates for *manual* hardware acceptance only.
  return {state:'review-required',reason:'verify active physical GPU, driver and sustained frame pacing'};
}
