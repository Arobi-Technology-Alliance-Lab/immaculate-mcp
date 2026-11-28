/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Checks the bearer token OpenShell sends with every call to a supervisor middleware when its gateway has JWT signing
 * configured (OpenShell docs, "Authenticating Extensions"):
 *   - header: typ "openshell-ext+jwt" and alg "EdDSA", pinned here and never read from the token;
 *   - an Ed25519 signature by the gateway's key: a public key (PEM) or JWKS the operator configured, and optionally the
 *     gateway's discovery document over TLS, re-read when a token names a key the gate does not know;
 *   - expiry, not-before and issued-at, with a small clock allowance;
 *   - the exact audience, the issuer "openshell-gateway:<gateway_id>", and caller_kind "gateway" or "supervisor", with
 *     sandbox_id set for a supervisor.
 * A repeated jti is accepted: OpenShell reuses a token until it rotates.
 */

import crypto from 'node:crypto';
import https from 'node:https';

export const TOKEN_TYPE = 'openshell-ext+jwt';
const MAX_TOKEN_BYTES = 8192;
const MAX_DOCUMENT_BYTES = 1024 * 1024;
const REFRESH_INTERVAL_MS = 60_000;
const FETCH_TIMEOUT_MS = 5000;
const BEARER = /^Bearer ([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/i;

/** An Ed25519 public key from PEM (SPKI). */
export function publicKeyFromPem(pem) {
  const key = crypto.createPublicKey(pem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('The gateway signing key is an Ed25519 public key.');
  return key;
}

/** The Ed25519 signing keys of a JWKS, as [{ kid, key }]. Keys of other types are skipped; none usable is an error. */
export function publicKeysFromJwks(jwks) {
  if (!jwks || typeof jwks !== 'object' || !Array.isArray(jwks.keys)) throw new Error('A JWKS is an object with a "keys" list.');
  const keys = [];
  for (const jwk of jwks.keys) {
    if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') continue;
    if (jwk.use !== undefined && jwk.use !== 'sig') continue;
    if (jwk.alg !== undefined && jwk.alg !== 'EdDSA' && jwk.alg !== 'Ed25519') continue;
    const key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
    keys.push({ kid: typeof jwk.kid === 'string' ? jwk.kid : null, key });
  }
  if (keys.length === 0) throw new Error('The JWKS has no Ed25519 signing key.');
  return keys;
}

function decodeJson(segment, what) {
  let value;
  try {
    value = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    throw new Error(`the token ${what} is not base64url JSON`);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`the token ${what} is not a JSON object`);
  return value;
}

/** GET a JSON document over HTTPS only, with a timeout and a size limit. */
export function fetchJsonOverTls(url, { ca } = {}) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      reject(new Error(`"${url}" is not a URL`));
      return;
    }
    if (parsed.protocol !== 'https:') {
      reject(new Error(`"${url}" is not https: keys are read over TLS only`));
      return;
    }
    const request = https.get(parsed, { ca, timeout: FETCH_TIMEOUT_MS, headers: { accept: 'application/json' } }, (response) => {
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`${url} answered ${response.statusCode}`));
        return;
      }
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_DOCUMENT_BYTES) {
          request.destroy(new Error(`${url} sent more than ${MAX_DOCUMENT_BYTES} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch {
          reject(new Error(`${url} did not send JSON`));
        }
      });
      response.on('error', reject);
    });
    request.on('timeout', () => request.destroy(new Error(`${url} did not answer within ${FETCH_TIMEOUT_MS} ms`)));
    request.on('error', reject);
  });
}

export class ExtensionTokenVerifier {
  /**
   * @param {object} options
   * @param {string} options.gatewayId     the gateway's id; the issuer must be "openshell-gateway:<gatewayId>"
   * @param {string} options.audience      the registration's exact audience
   * @param {{kid: string|null, key: crypto.KeyObject}[]} [options.keys]  keys the operator configured
   * @param {string} [options.discoveryUrl] https URL of the gateway's /.well-known/openid-configuration
   * @param {string|Buffer} [options.ca]   CA certificate for the discovery fetch (platform roots when omitted)
   * @param {number} [options.clockSkewSec] allowance for exp, nbf and iat (default 30)
   * @param {() => number} [options.now]   clock in milliseconds, for tests
   * @param {(url: string, opts: object) => Promise<any>} [options.fetchJson]  for tests
   */
  constructor({ gatewayId, audience, keys = [], discoveryUrl = null, ca = undefined, clockSkewSec = 30, now = () => Date.now(), fetchJson = fetchJsonOverTls }) {
    if (typeof gatewayId !== 'string' || !gatewayId) throw new Error('auth.gateway_id is required.');
    if (typeof audience !== 'string' || !audience) throw new Error('auth.audience is required.');
    if (keys.length === 0 && !discoveryUrl) throw new Error('auth needs a public key, a JWKS or a discovery URL.');
    this.issuer = `openshell-gateway:${gatewayId}`;
    this.audience = audience;
    this.staticKeys = keys;
    this.discoveredKeys = [];
    this.discoveryUrl = discoveryUrl;
    this.ca = ca;
    this.clockSkewSec = clockSkewSec;
    this.now = now;
    this.fetchJson = fetchJson;
    this.lastRefresh = -Infinity;
    this.refreshing = null;
  }

  /** Reads the discovery document once at start when one is configured. Throws when no key is usable then. */
  async init() {
    if (this.discoveryUrl) {
      const error = await this.refresh();
      if (error && this.staticKeys.length === 0) throw new Error(`no gateway signing key: ${error.message}`);
    }
    return this;
  }

  keys() {
    return [...this.staticKeys, ...this.discoveredKeys];
  }

  /** Re-reads the discovery document and its JWKS. Resolves to null, or to the error (old keys stay in use). */
  refresh() {
    if (!this.discoveryUrl) return Promise.resolve(new Error('no discovery URL is configured'));
    if (!this.refreshing) {
      this.lastRefresh = this.now();
      // finally runs after this assignment even when the load fails at once, so a later refresh is never blocked.
      this.refreshing = this.loadDiscoveredKeys().finally(() => {
        this.refreshing = null;
      });
    }
    return this.refreshing;
  }

  async loadDiscoveredKeys() {
    try {
      const config = await this.fetchJson(this.discoveryUrl, { ca: this.ca });
      if (!config || typeof config.jwks_uri !== 'string') throw new Error('the discovery document has no jwks_uri');
      if (new URL(config.jwks_uri).protocol !== 'https:') throw new Error('the jwks_uri is not https');
      this.discoveredKeys = publicKeysFromJwks(await this.fetchJson(config.jwks_uri, { ca: this.ca }));
      return null;
    } catch (error) {
      return error;
    }
  }

  candidates(kid) {
    return this.keys().filter((entry) => kid === undefined || entry.kid === null || entry.kid === kid);
  }

  /**
   * Checks the authorization metadata of one call. Resolves to { ok: true, claims } or { ok: false, reason }.
   * @param {string[]} values every value of the call's "authorization" metadata
   */
  async verify(values) {
    try {
      if (!Array.isArray(values) || values.length === 0) throw new Error('the call carries no bearer token');
      if (values.length > 1) throw new Error('the call carries more than one authorization value');
      if (typeof values[0] !== 'string') throw new Error('the authorization value is not text');
      if (values[0].length > MAX_TOKEN_BYTES) throw new Error('the bearer token is too long');
      const match = BEARER.exec(values[0]);
      if (!match) throw new Error('the authorization value is not "Bearer <JWT>"');
      const [, headerPart, claimsPart, signaturePart] = match;
      const header = decodeJson(headerPart, 'header');
      if (header.typ !== TOKEN_TYPE) throw new Error(`the token type is not ${TOKEN_TYPE}`);
      if (header.alg !== 'EdDSA') throw new Error('the token algorithm is not EdDSA');
      if (header.crit !== undefined) throw new Error('the token has critical header parameters the gate does not support');
      if (header.kid !== undefined && typeof header.kid !== 'string') throw new Error('the token key id is not a string');
      const claims = decodeJson(claimsPart, 'claims');

      const signingInput = Buffer.from(`${headerPart}.${claimsPart}`, 'ascii');
      const signature = Buffer.from(signaturePart, 'base64url');
      const signedBy = (entries) => entries.some(({ key }) => {
        try {
          return crypto.verify(null, signingInput, key, signature);
        } catch {
          return false;
        }
      });
      let verified = signedBy(this.candidates(header.kid));
      const unknownKid = header.kid === undefined || !this.keys().some((entry) => entry.kid === header.kid);
      if (!verified && unknownKid && this.discoveryUrl && this.now() - this.lastRefresh >= REFRESH_INTERVAL_MS) {
        await this.refresh();
        verified = signedBy(this.candidates(header.kid));
      }
      if (!verified) throw new Error('the token signature does not verify with the gateway signing key');

      const nowSec = this.now() / 1000;
      if (!Number.isFinite(claims.exp)) throw new Error('the token has no expiry');
      if (nowSec > claims.exp + this.clockSkewSec) throw new Error('the token has expired');
      if (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || nowSec + this.clockSkewSec < claims.nbf)) {
        throw new Error('the token is not valid yet');
      }
      if (claims.iat !== undefined && (!Number.isFinite(claims.iat) || claims.iat > nowSec + this.clockSkewSec)) {
        throw new Error('the token was issued in the future');
      }
      const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      if (!audiences.includes(this.audience)) throw new Error('the token audience is not this registration');
      if (claims.iss !== this.issuer) throw new Error('the token issuer is not the configured gateway');
      if (claims.caller_kind !== 'gateway' && claims.caller_kind !== 'supervisor') {
        throw new Error('the token caller_kind is neither gateway nor supervisor');
      }
      if (claims.caller_kind === 'supervisor' && (typeof claims.sandbox_id !== 'string' || !claims.sandbox_id)) {
        throw new Error('a supervisor token names no sandbox_id');
      }
      return { ok: true, claims };
    } catch (error) {
      return { ok: false, reason: error.message };
    }
  }
}
