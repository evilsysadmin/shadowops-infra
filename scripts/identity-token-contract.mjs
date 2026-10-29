// Reference-only Ed25519 token compatibility contract for future ShadowOps Identity.
// No account/session reads or writes; NOT a production authentication middleware.
import { createPublicKey, verify as verifySignature } from 'node:crypto';
import { readFileSync } from 'node:fs';

export class IdentityContractError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'IdentityContractError';
  }
}
const reject = reason => { throw new IdentityContractError(reason); };

export function loadContract(path = new URL('../config/identity/platform-contract.json', import.meta.url)) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function decodePart(value, maxBytes) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > Math.ceil(maxBytes * 4 / 3) + 4) {
    reject('Invalid token encoding or length');
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length > maxBytes || bytes.toString('base64url') !== value) {
    reject('Non-canonical or oversized token part');
  }
  return bytes;
}

function parseObject(bytes) {
  try {
    const value = JSON.parse(bytes.toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) reject('Token section must be object');
    return value;
  } catch (error) {
    if (error instanceof IdentityContractError) throw error;
    reject('Token section is not valid JSON');
  }
}

function selectSigningKey(jwks, kid) {
  if (!jwks || typeof jwks !== 'object' || Array.isArray(jwks) || !Array.isArray(jwks.keys) || jwks.keys.length < 1 || jwks.keys.length > 20) {
    reject('Invalid JWKS');
  }
  const seen = new Set();
  let matching;
  for (const key of jwks.keys) {
    if (!key || typeof key !== 'object' || Array.isArray(key) || typeof key.kid !== 'string' || !key.kid || seen.has(key.kid)) {
      reject('Invalid or duplicate key identifier');
    }
    seen.add(key.kid);
    if (key.d !== undefined || key.kty !== 'OKP' || key.crv !== 'Ed25519' || key.alg !== 'EdDSA' || key.use !== 'sig') {
      reject('Invalid Ed25519 signing JWK');
    }
    if (typeof key.x !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(key.x) || decodePart(key.x, 32).length !== 32) {
      reject('Invalid public signing key');
    }
    if (key.kid === kid) matching = key;
  }
  if (!matching) reject('Unknown signing key');
  return matching;
}

export function verifyTokenContract({ token, jwks, environment, audience, nowSeconds, contract = loadContract() }) {
  if (!contract || contract.status !== 'design-only-not-deployed') reject('Unexpected contract state');
  const env = contract.environments?.[environment];
  if (!env || !['staging', 'production'].includes(environment)) reject('Unknown identity environment');
  if (!env.consumers?.some(entry => entry.audience === audience)) reject('Unknown product audience');
  if (typeof token !== 'string' || token.length > 16_384) reject('Oversized or missing token');
  const parts = token.split('.');
  if (parts.length !== 3) reject('Malformed signed token');

  const header = parseObject(decodePart(parts[0], 1024));
  const claims = parseObject(decodePart(parts[1], 8192));
  const sig = decodePart(parts[2], 64);
  if (sig.length !== 64 || header.alg !== 'EdDSA' || header.typ !== 'JWT' || typeof header.kid !== 'string' || !header.kid) {
    reject('Unsupported signed token header');
  }
  const key = selectSigningKey(jwks, header.kid);
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: key.x },
      format: 'jwk',
    });
  } catch {
    reject('Cannot load public signing key');
  }
  const signedPart = Buffer.from(parts[0] + '.' + parts[1]);
  if (!verifySignature(null, signedPart, publicKey, sig)) reject('Invalid signature');

  if (claims.iss !== env.issuer) reject('Wrong identity environment/issuer');
  if (claims.aud !== audience) reject('Wrong product audience');
  if (typeof claims.sub !== 'string' || !claims.sub.trim() || claims.sub.length > 128) reject('Invalid subject');
  const now = nowSeconds;
  if (!Number.isSafeInteger(now) || now <= 0) reject('Invalid trusted clock');
  const { iat, nbf, exp } = claims;
  if (![iat, nbf, exp].every(v => Number.isSafeInteger(v) && v > 0)) reject('Missing or invalid JWT timestamps');
  if (exp <= iat || exp - iat > contract.token_target.ttl_seconds) reject('Invalid JWT validity interval');
  // Allow 30s for clocks being slightly ahead, but never accept expired tokens.
  if (iat > now + 30 || nbf > now + 30 || exp <= now) reject('Token outside validity window');
  return Object.freeze({
    issuer: claims.iss, audience: claims.aud, subject: claims.sub,
    expiresAt: exp, environment,
  });
}

// A valid identity token alone MUST NOT authorize an application or enable CKA labs.
// Even an otherwise-valid CKA token cannot activate a preview-only consumer.
export function assertConsumerActivated({ contract = loadContract(), environment, audience }) {
  const consumer = contract.environments?.[environment]?.consumers?.find(item => item.audience === audience);
  if (!consumer || consumer.status !== 'active-after-security-accreditation') {
    reject('Consumer is not accredited for authenticated access');
  }
  return true;
}
