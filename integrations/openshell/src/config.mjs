/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * The operator's file (gate.json): where the gate listens, how OpenShell's calls are authenticated, where sealed records
 * go, and the grants: who allowed which sandboxes to do what, until when. A sandbox policy's `config` says what each
 * request is; only a grant here makes it allowed.
 *
 * Two transport modes, the same two an OpenShell registration offers:
 *   - TLS with token checks (the default): `tls` and `auth` are both required;
 *   - `allow_insecure_transport: true`: plaintext, for local development only. OpenShell sends no token then, so `auth`
 *     is refused in this mode rather than silently never checked.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';

import { publicKeyFromPem, publicKeysFromJwks } from './auth.mjs';

export const DEFAULT_ROTATE_AFTER_RECORDS = 50_000;
const CONFIG_KEYS = new Set(['listen', 'allow_insecure_transport', 'tls', 'auth', 'records_dir', 'rotate_after_records', 'grants']);
const TLS_KEYS = new Set(['cert_path', 'key_path']);
const AUTH_KEYS = new Set(['gateway_id', 'audience', 'public_key_path', 'jwks_path', 'openid_configuration_url', 'tls_ca_cert_path', 'clock_skew_sec']);
const GRANT_KEYS = new Set(['route_id', 'granted_by', 'sandboxes', 'actions', 'ttl_hours', 'expires_at']);
const LISTEN = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):(\d{1,5})$/;
const ROUTE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const ACTION_PATTERN = /^(?:\*|[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?:\.\*)?)$/;
const SANDBOX_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/;
const MAX_GRANTS = 1024;

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

function onlyKeys(object, allowed, where) {
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) throw new Error(`${where} has an unknown field "${key}".`);
  }
}

function text(value, where, max = 256) {
  if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error(`${where} is a non-empty string of at most ${max} characters.`);
  return value;
}

function readFile(baseDir, file, where) {
  const resolved = path.resolve(baseDir, text(file, where, 4096));
  try {
    return readFileSync(resolved);
  } catch (error) {
    throw new Error(`${where} (${resolved}) cannot be read: ${error.message}`);
  }
}

function parseGrant(grant, index, nowMs) {
  const where = `grants[${index}]`;
  if (!isPlainObject(grant)) throw new Error(`${where} is an object.`);
  onlyKeys(grant, GRANT_KEYS, where);
  const routeId = grant.route_id === undefined ? 'openshell' : grant.route_id;
  if (typeof routeId !== 'string' || !ROUTE_ID.test(routeId)) throw new Error(`${where}.route_id is 1-128 characters of letters, digits, ".", "_", ":" or "-".`);
  const grantedBy = text(grant.granted_by, `${where}.granted_by`);
  if (!Array.isArray(grant.sandboxes) || grant.sandboxes.length === 0) throw new Error(`${where}.sandboxes is a non-empty list of sandbox ids, or ["*"].`);
  const sandboxes = grant.sandboxes.map((id, i) => {
    if (id === '*' || (typeof id === 'string' && SANDBOX_ID.test(id))) return id;
    throw new Error(`${where}.sandboxes[${i}] is a sandbox id (as OpenShell reports sandbox_id) or "*".`);
  });
  if (sandboxes.includes('*') && sandboxes.length > 1) throw new Error(`${where}.sandboxes is either ["*"] or a list of ids, not both.`);
  if (new Set(sandboxes).size !== sandboxes.length) throw new Error(`${where}.sandboxes names a sandbox twice.`);
  if (!Array.isArray(grant.actions) || grant.actions.length === 0) throw new Error(`${where}.actions is a non-empty list.`);
  const actions = grant.actions.map((action, i) => {
    if (typeof action === 'string' && ACTION_PATTERN.test(action)) return action;
    throw new Error(`${where}.actions[${i}] is an action, a prefix ending in ".*", or "*".`);
  });
  const hasTtl = grant.ttl_hours !== undefined;
  const hasExpiry = grant.expires_at !== undefined;
  if (hasTtl === hasExpiry) throw new Error(`${where} sets exactly one of ttl_hours and expires_at.`);
  let expiresMs;
  if (hasTtl) {
    if (typeof grant.ttl_hours !== 'number' || !(grant.ttl_hours > 0) || grant.ttl_hours > 8760) {
      throw new Error(`${where}.ttl_hours is a number of hours, more than 0 and at most 8760.`);
    }
    expiresMs = nowMs + grant.ttl_hours * 3_600_000;
  } else {
    expiresMs = typeof grant.expires_at === 'string' ? Date.parse(grant.expires_at) : NaN;
    if (Number.isNaN(expiresMs)) throw new Error(`${where}.expires_at is an ISO 8601 time.`);
    if (expiresMs <= nowMs) throw new Error(`${where}.expires_at (${grant.expires_at}) has already passed.`);
  }
  return { route_id: routeId, granted_by: grantedBy, sandboxes, actions, expires_at: new Date(expiresMs).toISOString() };
}

/**
 * Checks the operator's file and reads the files it names. Throws an Error naming the field at fault.
 * @param {object} raw          the parsed JSON
 * @param {object} options
 * @param {string} options.baseDir  relative paths are read from here (the config file's folder)
 * @param {number} [options.nowMs]  the clock, for ttl_hours and expires_at
 */
export function parseGateConfig(raw, { baseDir, nowMs = Date.now() }) {
  if (!isPlainObject(raw)) throw new Error('The gate config is a JSON object.');
  onlyKeys(raw, CONFIG_KEYS, 'The gate config');

  const listen = raw.listen === undefined ? '127.0.0.1:50051' : raw.listen;
  const listenMatch = typeof listen === 'string' ? LISTEN.exec(listen) : null;
  if (!listenMatch || Number(listenMatch[2]) > 65535) throw new Error('listen is "host:port", such as "0.0.0.0:50051" or "[::]:50051".');

  if (raw.allow_insecure_transport !== undefined && typeof raw.allow_insecure_transport !== 'boolean') {
    throw new Error('allow_insecure_transport is true or false.');
  }
  const insecure = raw.allow_insecure_transport === true;
  let tls = null;
  let auth = null;
  if (insecure) {
    if (raw.tls !== undefined) throw new Error('tls is not used with allow_insecure_transport: remove one of them.');
    if (raw.auth !== undefined) {
      throw new Error('auth cannot be checked with allow_insecure_transport: OpenShell sends no token to a plaintext registration.');
    }
  } else {
    if (!isPlainObject(raw.tls)) throw new Error('tls { cert_path, key_path } is required (or allow_insecure_transport: true, for local development only).');
    onlyKeys(raw.tls, TLS_KEYS, 'tls');
    tls = { cert: readFile(baseDir, raw.tls.cert_path, 'tls.cert_path'), key: readFile(baseDir, raw.tls.key_path, 'tls.key_path') };
    if (!isPlainObject(raw.auth)) throw new Error('auth is required with TLS: { gateway_id, audience, and public_key_path, jwks_path or openid_configuration_url }.');
    onlyKeys(raw.auth, AUTH_KEYS, 'auth');
    const keys = [];
    if (raw.auth.public_key_path !== undefined) {
      try {
        keys.push({ kid: null, key: publicKeyFromPem(readFile(baseDir, raw.auth.public_key_path, 'auth.public_key_path')) });
      } catch (error) {
        throw new Error(`auth.public_key_path: ${error.message}`);
      }
    }
    if (raw.auth.jwks_path !== undefined) {
      try {
        keys.push(...publicKeysFromJwks(JSON.parse(readFile(baseDir, raw.auth.jwks_path, 'auth.jwks_path').toString('utf8'))));
      } catch (error) {
        throw new Error(`auth.jwks_path: ${error.message}`);
      }
    }
    let discoveryUrl = null;
    if (raw.auth.openid_configuration_url !== undefined) {
      discoveryUrl = text(raw.auth.openid_configuration_url, 'auth.openid_configuration_url', 2048);
      let protocol;
      try {
        protocol = new URL(discoveryUrl).protocol;
      } catch {
        protocol = null;
      }
      if (protocol !== 'https:') throw new Error('auth.openid_configuration_url is an https URL.');
    }
    if (keys.length === 0 && !discoveryUrl) {
      throw new Error('auth needs the gateway signing key: public_key_path, jwks_path or openid_configuration_url.');
    }
    const clockSkewSec = raw.auth.clock_skew_sec === undefined ? 30 : raw.auth.clock_skew_sec;
    if (!Number.isInteger(clockSkewSec) || clockSkewSec < 0 || clockSkewSec > 300) throw new Error('auth.clock_skew_sec is a whole number of seconds from 0 to 300.');
    auth = {
      gatewayId: text(raw.auth.gateway_id, 'auth.gateway_id'),
      audience: text(raw.auth.audience, 'auth.audience', 1024),
      keys,
      discoveryUrl,
      ca: raw.auth.tls_ca_cert_path === undefined ? undefined : readFile(baseDir, raw.auth.tls_ca_cert_path, 'auth.tls_ca_cert_path'),
      clockSkewSec,
    };
  }

  if (!Array.isArray(raw.grants) || raw.grants.length === 0) throw new Error('grants is a non-empty list: without a grant every request is denied.');
  if (raw.grants.length > MAX_GRANTS) throw new Error(`grants has at most ${MAX_GRANTS} entries.`);
  const grants = raw.grants.map((grant, index) => parseGrant(grant, index, nowMs));
  const seen = new Map();
  for (const [index, grant] of grants.entries()) {
    for (const sandbox of grant.sandboxes) {
      if (seen.has(sandbox)) {
        throw new Error(`grants[${index}] and grants[${seen.get(sandbox)}] both cover sandbox "${sandbox}": one grant per sandbox, so a decision has one source.`);
      }
      seen.set(sandbox, index);
    }
  }
  const sealedGrants = grants.reduce((sum, grant) => sum + grant.sandboxes.length, 0);

  const rotateAfter = raw.rotate_after_records === undefined ? DEFAULT_ROTATE_AFTER_RECORDS : raw.rotate_after_records;
  if (!Number.isInteger(rotateAfter) || rotateAfter < sealedGrants + 2 || rotateAfter > 10_000_000) {
    throw new Error(`rotate_after_records is a whole number from ${sealedGrants + 2} (the sealed grants plus one decision) to 10000000.`);
  }
  const recordsDir = path.resolve(baseDir, raw.records_dir === undefined ? 'records' : text(raw.records_dir, 'records_dir', 4096));

  return { listen, insecure, tls, auth, recordsDir, rotateAfterRecords: rotateAfter, grants };
}

/** Reads and checks a gate config file; relative paths in it are read from its folder. */
export function loadGateConfig(file, options = {}) {
  const resolved = path.resolve(file);
  let raw;
  try {
    raw = JSON.parse(readFileSync(resolved, 'utf8'));
  } catch (error) {
    throw new Error(`${resolved} is not readable JSON: ${error.message}`);
  }
  return parseGateConfig(raw, { baseDir: path.dirname(resolved), ...options });
}
