// Test-only Worker entrypoint for real workerd. Not part of Pages shell.
import privateDelivery from '../../workers/pawn-action-staging/private-delivery.mjs';
export default {
  async fetch(request, env) {
    return privateDelivery.fetch(request, env, {
      request: (url, init) => env.SYNTHETIC_IDENTITY.fetch(new Request(url, init)),
    });
  },
};
