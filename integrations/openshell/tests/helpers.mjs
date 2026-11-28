/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Shared test fixtures: a policy, grants, a gate on a temporary folder, an in-process gRPC server and clients, and
 * gateway tokens signed with a key made for the test run (no key material is stored in the repository).
 */

import crypto from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import grpc from '@grpc/grpc-js';

import { ImmaculateGate } from '../src/gate.mjs';
import { createGateServer, loadProtocol } from '../src/server.mjs';
import { jsonToStruct } from '../src/struct.mjs';

export const T0 = Date.parse('2026-11-28T00:00:00.000Z');

export const POLICY = {
  rules: [
    { id: 'crm-read', methods: ['GET'], hosts: ['api.crm.example'], paths: ['/v1/contacts/*'], action: 'crm.read.contacts', tier: 'low' },
    { id: 'crm-write', methods: ['POST', 'PATCH'], hosts: ['api.crm.example'], paths: ['/v1/contacts/*'], action: 'crm.write.contacts', tier: 'medium' },
    { id: 'refunds', methods: ['POST'], hosts: ['api.payments.example'], paths: ['/v1/refunds'], action: 'payments.refund', tier: 'critical' },
    { id: 'mail', methods: ['POST'], hosts: ['*.mail.example'], paths: ['/send'], action: 'mail.send', tier: 'high' },
  ],
  unmatched: 'deny',
};

/** Any sandbox may read contacts, send mail and ask for refunds (which are critical, so they are held). */
export function grants({ expiresAt = '2026-11-29T00:00:00.000Z', sandboxes = ['*'], actions = ['crm.read.*', 'payments.refund', 'mail.send'] } = {}) {
  return [{ route_id: 'openshell', granted_by: 'ops@example.test', sandboxes, actions, expires_at: expiresAt }];
}

export function tempDir() {
  return mkdtempSync(path.join(os.tmpdir(), 'immaculate-openshell-'));
}

export function removeDir(dir) {
  rmSync(dir, { recursive: true, force: true });
}

/** A clock the test moves. */
export function clock(start = T0) {
  let now = start;
  const fn = () => now;
  fn.advance = (ms) => {
    now += ms;
  };
  return fn;
}

export function makeGate({ dir, now = clock(), grantList = grants(), rotateAfterRecords = 50_000, log } = {}) {
  return new ImmaculateGate({ grants: grantList, recordsDir: dir, rotateAfterRecords, now, log }).start();
}

/** Every record of every file in a records folder, by file name. */
export function readRecords(dir) {
  const out = {};
  for (const name of readdirSync(dir).sort()) {
    out[name] = readFileSync(path.join(dir, name), 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
  }
  return out;
}

export const TARGET = { scheme: 'https', host: 'api.crm.example', port: 443, method: 'GET', path: '/v1/contacts/7', query: 'fields=name' };
export const CONTEXT = {
  request_id: 'req-1',
  sandbox_id: 'sbx-a',
  sandbox: 'demo',
  workspace: 'research',
  originating_process: { binary: '/usr/bin/python3', pid: 0, ancestors: ['/bin/sh'] },
};

export const GATEWAY = {
  protocol_version: { major: 1, minor: 0 },
  implementation_name: 'openshell/gateway',
  implementation_version: '0.1.0',
  supported_capabilities: ['openshell.supervisor-middleware.contract', 'openshell.supervisor-middleware.http-hooks'],
  required_capabilities: ['openshell.supervisor-middleware.contract'],
};

/** A request-hook preflight event as OpenShell sends it; config: null leaves the config out. */
export function preflight({ target = {}, context = {}, phase = 'SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS', config = POLICY } = {}) {
  return {
    preflight: {
      request: { target: { ...TARGET, ...target }, headers: [{ name: 'accept', value: 'application/json' }] },
      phase,
      context: { ...CONTEXT, ...context },
      middleware_name: 'immaculate',
      ...(config === null ? {} : { config: jsonToStruct(config) }),
      permitted_body_modes: [],
      limits: {},
    },
  };
}

/** Starts the gate's gRPC server on a free local port (plaintext, for tests). */
export async function startServer({ gate, verifier = null, log } = {}) {
  const server = createGateServer({ gate, verifier, log });
  const port = await new Promise((resolve, reject) => {
    server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, bound) => (error ? reject(error) : resolve(bound)));
  });
  const proto = loadProtocol();
  const address = `127.0.0.1:${port}`;
  const middleware = new proto.SupervisorMiddleware(address, grpc.credentials.createInsecure());
  const hooks = new proto.HttpHooks(address, grpc.credentials.createInsecure());
  return {
    port,
    middleware,
    hooks,
    async close() {
      middleware.close();
      hooks.close();
      await new Promise((resolve) => server.tryShutdown(resolve));
    },
  };
}

export function bearer(token) {
  const metadata = new grpc.Metadata();
  if (token) metadata.set('authorization', `Bearer ${token}`);
  return metadata;
}

export function unary(client, method, request, metadata = new grpc.Metadata()) {
  return new Promise((resolve, reject) => {
    client[method](request, metadata, (error, response) => (error ? reject(error) : resolve(response)));
  });
}

/** Runs one request-hook stream: writes the events, ends, and resolves to every result (or rejects with the status). */
export function hookStream(hooks, events, metadata = new grpc.Metadata(), method = 'EvaluateHttpRequestHook') {
  return new Promise((resolve, reject) => {
    const call = hooks[method](metadata);
    const results = [];
    call.on('data', (result) => results.push(result));
    call.on('error', reject);
    call.on('end', () => resolve(results));
    for (const event of events) call.write(event);
    call.end();
  });
}

/** An Ed25519 key pair standing in for the gateway's signing key. */
export function gatewayKeys() {
  return crypto.generateKeyPairSync('ed25519');
}

/** A gateway token: header and claims as OpenShell issues them, signed with the given key. */
export function mintToken(privateKey, claims, header = {}) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${encode({ typ: 'openshell-ext+jwt', alg: 'EdDSA', ...header })}.${encode(claims)}`;
  return `${input}.${crypto.sign(null, Buffer.from(input), privateKey).toString('base64url')}`;
}

export const GATEWAY_ID = 'gw-test';
export const AUDIENCE = 'urn:openshell:extension:middleware:immaculate';

export function claims(overrides = {}, nowMs = T0) {
  const iat = Math.floor(nowMs / 1000);
  return { iss: `openshell-gateway:${GATEWAY_ID}`, aud: AUDIENCE, iat, exp: iat + 300, jti: 'j-1', caller_kind: 'supervisor', sandbox_id: 'sbx-a', ...overrides };
}
