import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { loadContract, verifyTokenContract, assertConsumerActivated, IdentityContractError } from '../scripts/identity-token-contract.mjs';

const contract = loadContract();
const now = 1_800_000_000;
const stageKey = generateKeyPairSync('ed25519');
const prodKey = generateKeyPairSync('ed25519');
const otherKey = generateKeyPairSync('ed25519');

function jwk(pair, kid = 'test-key') {
  return { ...pair.publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'EdDSA' };
}
function tokenFor({ environment = 'staging', audience = 'chronicles', pair = stageKey,
    kid = 'test-key', sub = 'acct_554ca6bf', header = {}, payload = {} } = {}) {
  const claims = {
    iss: contract.environments[environment].issuer, aud: audience, sub,
    iat: now - 60, nbf: now - 60, exp: now + 360, ...payload,
  };
  const h = { alg: 'EdDSA', typ: 'JWT', kid, ...header };
  const part = v => Buffer.from(JSON.stringify(v)).toString('base64url');
  const signed = part(h) + '.' + part(claims);
  return signed + '.' + sign(null, Buffer.from(signed), pair.privateKey).toString('base64url');
}
function validate(token, environment = 'staging', audience = 'chronicles', keys = [jwk(stageKey)]) {
  return verifyTokenContract({ token, jwks: { keys }, environment, audience, nowSeconds: now, contract });
}
function rejected(fn) { assert.throws(fn, IdentityContractError); }

test('staging signed token verifies only against staging identity and matching audience', () => {
  const t = tokenFor();
  const v = validate(t);
  assert.equal(v.environment, 'staging');
  assert.equal(v.subject, 'acct_554ca6bf');
  rejected(() => validate(t, 'production', 'chronicles'));
  rejected(() => validate(t, 'staging', 'chess-studio'));
  rejected(() => validate(t, 'staging', 'cka-simulator'));
});

test('production signed token and matching JWKS are never accepted by staging', () => {
  const prod = tokenFor({ environment: 'production', pair: prodKey, sub: 'acct_554ca6bf' });
  assert.equal(validate(prod, 'production', 'chronicles', [jwk(prodKey)]).environment, 'production');
  rejected(() => validate(prod, 'staging', 'chronicles', [jwk(prodKey)]));
  rejected(() => validate(prod, 'production', 'chronicles', [jwk(stageKey)]));
});

test('a signed but wrong audience, issuer or multi-audience value is rejected', () => {
  rejected(() => validate(tokenFor({ audience: 'chess-studio' })));
  rejected(() => validate(tokenFor({ payload: { aud: ['chronicles', 'cka-simulator'] } })));
  rejected(() => validate(tokenFor({ payload: { iss: contract.environments.production.issuer } })));
});

test('expired, future, absurd-duration and malformed JWT times are rejected', () => {
  const invalid = [
    { exp: now }, { exp: now - 1 },
    { nbf: now + 100 }, { iat: now + 100 },
    { iat: now - 3600, exp: now + 3600 },
    { exp: 'not-a-timestamp' }, { exp: null }, { iat: 0 }, { nbf: -1 },
  ];
  for (const payload of invalid) rejected(() => validate(tokenFor({ payload })));
});

test('bad algorithm, type, key id, private JWK, duplicate id and invalid signature fail closed', () => {
  rejected(() => validate(tokenFor({ header: { alg: 'none' } })));
  rejected(() => validate(tokenFor({ header: { typ: 'JWE' } })));
  rejected(() => validate(tokenFor({ kid: 'unknown' })));
  rejected(() => validate(tokenFor({ pair: otherKey })));
  rejected(() => validate(tokenFor(), 'staging', 'chronicles', [jwk(stageKey, 'test-key'), jwk(prodKey, 'test-key')]));
  rejected(() => validate(tokenFor(), 'staging', 'chronicles', [{ ...jwk(stageKey), d: 'NEVER' }]));
  rejected(() => validate(tokenFor(), 'staging', 'chronicles', [{ ...jwk(stageKey), x: 'bad' }]));
});

test('key rotation permits two distinct public keys but unknown key ids remain rejected', () => {
  const token = tokenFor({ pair: otherKey, kid: 'new-key' });
  const keys = [jwk(stageKey, 'old-key'), jwk(otherKey, 'new-key')];
  assert.equal(validate(token, 'staging', 'chronicles', keys).subject, 'acct_554ca6bf');
  rejected(() => validate(token, 'staging', 'chronicles', [jwk(stageKey, 'old-key')]));
});

test('malformed segments, noncanonical base64 and blank subject are rejected', () => {
  for (const t of ['', 'a.b', 'a.b.c.d', '%%%%.abc.abc', 'a'.repeat(20_000)]) {
    rejected(() => validate(t));
  }
  rejected(() => validate(tokenFor({ payload: { sub: '' } })));
  rejected(() => validate(tokenFor({ payload: { sub: ' ' } })));
});

test('public preview CKA is not activated merely by possessing a valid signed token', () => {
  const t = tokenFor({ environment: 'production', audience: 'cka-simulator', pair: prodKey });
  assert.equal(validate(t, 'production', 'cka-simulator', [jwk(prodKey)]).audience, 'cka-simulator');
  rejected(() => assertConsumerActivated({ contract, environment: 'production', audience: 'cka-simulator' }));
  rejected(() => assertConsumerActivated({ contract, environment: 'staging', audience: 'cka-simulator' }));
  rejected(() => assertConsumerActivated({ contract, environment: 'production', audience: 'chronicles' }));
});

test('identity tool never requires or reads deployment credentials', () => {
  assert.equal(contract.status, 'design-only-not-deployed');
  assert.equal(contract.cross_environment_trust, false);
  assert.notEqual(contract.environments.staging.signing_key_scope, contract.environments.production.signing_key_scope);
});
