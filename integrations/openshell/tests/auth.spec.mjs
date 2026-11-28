import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { ExtensionTokenVerifier, publicKeyFromPem, publicKeysFromJwks } from '../src/auth.mjs';
import { AUDIENCE, claims, clock, GATEWAY_ID, gatewayKeys, mintToken, T0 } from './helpers.mjs';

const { privateKey, publicKey } = gatewayKeys();
const other = gatewayKeys();
const jwkOf = (key, kid) => ({ ...key.export({ format: 'jwk' }), kid, use: 'sig', alg: 'EdDSA' });

function verifier(options = {}) {
  return new ExtensionTokenVerifier({ gatewayId: GATEWAY_ID, audience: AUDIENCE, keys: [{ kid: null, key: publicKey }], now: () => T0, ...options });
}
const bearer = (token) => [`Bearer ${token}`];

test('a token from the gateway passes and its claims come back', async () => {
  const result = await verifier().verify(bearer(mintToken(privateKey, claims())));
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.claims.caller_kind, 'supervisor');
  assert.equal(result.claims.sandbox_id, 'sbx-a');
  const gatewayCall = await verifier().verify(bearer(mintToken(privateKey, claims({ caller_kind: 'gateway', sandbox_id: undefined }))));
  assert.equal(gatewayCall.ok, true, gatewayCall.reason);
});

test('a missing, repeated or malformed authorization value is refused', async () => {
  const v = verifier();
  assert.match((await v.verify([])).reason, /no bearer token/);
  assert.match((await v.verify(undefined)).reason, /no bearer token/);
  const token = mintToken(privateKey, claims());
  assert.match((await v.verify([`Bearer ${token}`, `Bearer ${token}`])).reason, /more than one/);
  assert.match((await v.verify([`Basic ${token}`])).reason, /not "Bearer <JWT>"/);
  assert.match((await v.verify(['Bearer abc'])).reason, /not "Bearer <JWT>"/);
  assert.match((await v.verify([`Bearer ${'a'.repeat(9000)}.b.c`])).reason, /too long/);
});

test('the type and algorithm are pinned, and critical headers are refused', async () => {
  const v = verifier();
  assert.match((await v.verify(bearer(mintToken(privateKey, claims(), { typ: 'JWT' })))).reason, /type is not openshell-ext\+jwt/);
  assert.match((await v.verify(bearer(mintToken(privateKey, claims(), { alg: 'none' })))).reason, /algorithm is not EdDSA/);
  assert.match((await v.verify(bearer(mintToken(privateKey, claims(), { alg: 'HS256' })))).reason, /algorithm is not EdDSA/);
  assert.match((await v.verify(bearer(mintToken(privateKey, claims(), { crit: ['exp'] })))).reason, /critical header/);
});

test('a token signed by any other key, or altered after signing, is refused', async () => {
  const v = verifier();
  assert.match((await v.verify(bearer(mintToken(other.privateKey, claims())))).reason, /signature does not verify/);
  const [header, , signature] = mintToken(privateKey, claims()).split('.');
  const forged = Buffer.from(JSON.stringify(claims({ sandbox_id: 'sbx-b' }))).toString('base64url');
  assert.match((await v.verify(bearer(`${header}.${forged}.${signature}`))).reason, /signature does not verify/);
});

test('expiry, not-before and issued-at are checked with the clock allowance', async () => {
  const now = clock();
  const v = verifier({ now, clockSkewSec: 30 });
  const nowSec = T0 / 1000;
  assert.equal((await v.verify(bearer(mintToken(privateKey, claims({ exp: nowSec - 10 }))))).ok, true, 'within the allowance');
  assert.match((await v.verify(bearer(mintToken(privateKey, claims({ exp: nowSec - 31 }))))).reason, /expired/);
  assert.match((await v.verify(bearer(mintToken(privateKey, claims({ exp: undefined }))))).reason, /no expiry/);
  assert.match((await v.verify(bearer(mintToken(privateKey, claims({ nbf: nowSec + 60 }))))).reason, /not valid yet/);
  assert.match((await v.verify(bearer(mintToken(privateKey, claims({ iat: nowSec + 60 }))))).reason, /issued in the future/);
});

test('the audience must be exact, the issuer the configured gateway, and the caller a gateway or a supervisor with a sandbox', async () => {
  const v = verifier();
  assert.match((await v.verify(bearer(mintToken(privateKey, claims({ aud: `${AUDIENCE}-other` }))))).reason, /audience/);
  assert.equal((await v.verify(bearer(mintToken(privateKey, claims({ aud: ['x', AUDIENCE] }))))).ok, true);
  assert.match((await v.verify(bearer(mintToken(privateKey, claims({ iss: 'openshell-gateway:other' }))))).reason, /issuer/);
  assert.match((await v.verify(bearer(mintToken(privateKey, claims({ iss: 'https://gateway.example' }))))).reason, /issuer/);
  assert.match((await v.verify(bearer(mintToken(privateKey, claims({ caller_kind: 'sandbox' }))))).reason, /caller_kind/);
  assert.match((await v.verify(bearer(mintToken(privateKey, claims({ sandbox_id: '' }))))).reason, /no sandbox_id/);
});

test('a repeated jti is accepted: OpenShell reuses a token until it rotates', async () => {
  const v = verifier();
  const token = mintToken(privateKey, claims());
  assert.equal((await v.verify(bearer(token))).ok, true);
  assert.equal((await v.verify(bearer(token))).ok, true);
});

test('JWKS keys are chosen by kid; keys of other types are skipped', () => {
  const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const keys = publicKeysFromJwks({ keys: [{ ...ec.publicKey.export({ format: 'jwk' }), kid: 'ec' }, jwkOf(publicKey, 'k1'), { ...jwkOf(other.publicKey, 'enc'), use: 'enc' }] });
  assert.deepEqual(keys.map((entry) => entry.kid), ['k1']);
  assert.throws(() => publicKeysFromJwks({ keys: [{ ...ec.publicKey.export({ format: 'jwk' }) }] }), /no Ed25519 signing key/);
  assert.throws(() => publicKeysFromJwks({}), /"keys" list/);
  assert.throws(() => publicKeyFromPem(ec.publicKey.export({ type: 'spki', format: 'pem' })), /Ed25519/);
  assert.equal(publicKeyFromPem(publicKey.export({ type: 'spki', format: 'pem' })).asymmetricKeyType, 'ed25519');
});

test('a token naming another kid is checked with that key only', async () => {
  const v = verifier({ keys: publicKeysFromJwks({ keys: [jwkOf(publicKey, 'k1'), jwkOf(other.publicKey, 'k2')] }) });
  assert.equal((await v.verify(bearer(mintToken(other.privateKey, claims(), { kid: 'k2' })))).ok, true);
  assert.match((await v.verify(bearer(mintToken(other.privateKey, claims(), { kid: 'k1' })))).reason, /signature/);
});

test('an unknown kid re-reads the gateway discovery document, at most once a minute', async () => {
  const now = clock();
  let fetches = 0;
  let jwks = { keys: [jwkOf(publicKey, 'k1')] };
  const fetchJson = async (url) => {
    fetches += 1;
    if (url === 'https://gateway.example/.well-known/openid-configuration') return { jwks_uri: 'https://gateway.example/jwks' };
    if (url === 'https://gateway.example/jwks') return jwks;
    throw new Error(`unexpected ${url}`);
  };
  const v = await new ExtensionTokenVerifier({ gatewayId: GATEWAY_ID, audience: AUDIENCE, discoveryUrl: 'https://gateway.example/.well-known/openid-configuration', now, fetchJson }).init();
  assert.equal(fetches, 2, 'discovery and JWKS at start');
  assert.equal((await v.verify(bearer(mintToken(privateKey, claims(), { kid: 'k1' })))).ok, true);

  // The gateway rotates to k2. Within a minute of the last read the gate does not fetch again.
  jwks = { keys: [jwkOf(other.publicKey, 'k2')] };
  now.advance(30_000);
  assert.match((await v.verify(bearer(mintToken(other.privateKey, claims({}, now()), { kid: 'k2' })))).reason, /signature/);
  assert.equal(fetches, 2);
  now.advance(31_000);
  assert.equal((await v.verify(bearer(mintToken(other.privateKey, claims({}, now()), { kid: 'k2' })))).ok, true);
  assert.equal(fetches, 4);
  // A known kid with a bad signature never triggers a fetch.
  now.advance(120_000);
  assert.match((await v.verify(bearer(mintToken(privateKey, claims({}, now()), { kid: 'k2' })))).reason, /signature/);
  assert.equal(fetches, 4);
});

test('discovery must stay on https, and a start with no usable key fails', async () => {
  const plainJwks = async (url) => (url.endsWith('openid-configuration') ? { jwks_uri: 'http://gateway.example/jwks' } : { keys: [] });
  await assert.rejects(
    new ExtensionTokenVerifier({ gatewayId: GATEWAY_ID, audience: AUDIENCE, discoveryUrl: 'https://gateway.example/.well-known/openid-configuration', fetchJson: plainJwks }).init(),
    /jwks_uri is not https/,
  );
  assert.throws(() => new ExtensionTokenVerifier({ gatewayId: GATEWAY_ID, audience: AUDIENCE }), /public key, a JWKS or a discovery URL/);
  assert.throws(() => new ExtensionTokenVerifier({ audience: AUDIENCE, keys: [{ kid: null, key: publicKey }] }), /gateway_id/);
});
