const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const FIELDS = ['repository', 'service', 'sha', 'digest', 'environment'];

export function admitCandidate(payload, context) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('invalid payload');
  if (!context || context.event !== 'repository_dispatch') throw new Error('invalid event');
  if (context.actorRepository !== 'evilsysadmin/chronicles-of-matthias') throw new Error('untrusted origin');
  if (Object.keys(payload).some(key => !FIELDS.includes(key))) throw new Error('unknown field');
  if (payload.repository !== context.actorRepository) throw new Error('source mismatch');
  if (payload.service !== 'chronicles-api') throw new Error('unapproved service');
  if (payload.environment !== 'staging') throw new Error('production not authorized');
  if (!SHA.test(payload.sha || '')) throw new Error('invalid SHA');
  if (!DIGEST.test(payload.digest || '')) throw new Error('invalid digest');
  return Object.freeze({ ...payload });
}
