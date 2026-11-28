import assert from 'node:assert/strict';
import test from 'node:test';

import grpc from '@grpc/grpc-js';

import { ExtensionTokenVerifier } from '../src/auth.mjs';
import { CONTRACT_CAPABILITY, gatewayMetadataProblem, HTTP_HOOKS_CAPABILITY, IMPLEMENTATION_NAME, VERSION } from '../src/server.mjs';
import { jsonToStruct } from '../src/struct.mjs';
import {
  AUDIENCE, bearer, claims, clock, GATEWAY, GATEWAY_ID, gatewayKeys, hookStream, makeGate, mintToken, POLICY, preflight,
  removeDir, startServer, T0, tempDir, unary,
} from './helpers.mjs';

async function withServer({ verifier = null } = {}, fn) {
  const dir = tempDir();
  const gate = makeGate({ dir, now: clock(T0) });
  const server = await startServer({ gate, verifier });
  try {
    await fn(server, gate);
  } finally {
    await server.close();
    gate.close();
    removeDir(dir);
  }
}

const expectStatus = async (promise, code) => {
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, code, `${error.code}: ${error.details}`);
    return true;
  });
};

test('Describe: one request binding at PRE_CREDENTIALS with no body, requiring HTTP hooks', () => withServer({}, async ({ middleware }) => {
  const manifest = await unary(middleware, 'Describe', { gateway: GATEWAY });
  assert.equal(manifest.name, IMPLEMENTATION_NAME);
  assert.deepEqual(manifest.bindings, [{
    operation: 'SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST',
    phase: 'SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS',
    max_payload_bytes: '0',
  }]);
  assert.deepEqual(manifest.extension.protocol_version, { major: 1, minor: 0 });
  assert.equal(manifest.extension.implementation_version, VERSION);
  assert.deepEqual(manifest.extension.supported_capabilities, [CONTRACT_CAPABILITY, HTTP_HOOKS_CAPABILITY]);
  assert.deepEqual(manifest.extension.required_capabilities, [CONTRACT_CAPABILITY, HTTP_HOOKS_CAPABILITY]);
  assert.equal(manifest.expected_audience ?? '', '');
}));

test('Describe refuses a gateway without metadata, without HTTP hooks, or on another major version', () => withServer({}, async ({ middleware }) => {
  await expectStatus(unary(middleware, 'Describe', {}), grpc.status.FAILED_PRECONDITION);
  const noHooks = { ...GATEWAY, supported_capabilities: [CONTRACT_CAPABILITY] };
  await expectStatus(unary(middleware, 'Describe', { gateway: noHooks }), grpc.status.FAILED_PRECONDITION);
  await expectStatus(unary(middleware, 'Describe', { gateway: { ...GATEWAY, protocol_version: { major: 2, minor: 0 } } }), grpc.status.FAILED_PRECONDITION);
}));

test('gateway metadata checks match OpenShell negotiation', () => {
  const extension = { supported_capabilities: [CONTRACT_CAPABILITY, HTTP_HOOKS_CAPABILITY], required_capabilities: [CONTRACT_CAPABILITY, HTTP_HOOKS_CAPABILITY] };
  assert.equal(gatewayMetadataProblem(GATEWAY, extension), null);
  assert.equal(gatewayMetadataProblem({ ...GATEWAY, protocol_version: { major: 1, minor: 3 } }, extension), null, 'a newer minor version is compatible');
  assert.match(gatewayMetadataProblem({ ...GATEWAY, required_capabilities: ['openshell.supervisor-middleware.future'] }, extension), /requires capabilities this middleware does not support/);
  assert.match(gatewayMetadataProblem({ ...GATEWAY, supported_capabilities: ['Bad Capability'] }, extension), /lowercase namespaced/);
  assert.match(gatewayMetadataProblem({ ...GATEWAY, supported_capabilities: [CONTRACT_CAPABILITY, CONTRACT_CAPABILITY] }, extension), /twice/);
  assert.match(gatewayMetadataProblem({ ...GATEWAY, protocol_version: undefined }, extension), /no protocol_version/);
});

test('ValidateConfig accepts the policy and explains a refusal', () => withServer({}, async ({ middleware }) => {
  assert.deepEqual(await unary(middleware, 'ValidateConfig', { config: jsonToStruct(POLICY), middleware_name: 'immaculate' }), { valid: true, reason: '' });
  const bad = await unary(middleware, 'ValidateConfig', { config: jsonToStruct({ rules: [{ id: 'a', hosts: ['x.example'], action: 'a', tier: 'urgent' }] }) });
  assert.equal(bad.valid, false);
  assert.match(bad.reason, /tier is one of/);
  const missing = await unary(middleware, 'ValidateConfig', { middleware_name: 'immaculate' });
  assert.equal(missing.valid, false);
}));

test('a granted request continues without its body, with the record in the diagnostics metadata', () => withServer({}, async ({ hooks }) => {
  const results = await hookStream(hooks, [preflight()]);
  assert.equal(results.length, 1);
  const [result] = results;
  assert.equal(result.result, 'preflight_result');
  assert.equal(result.preflight_result.decision, 'continue_without_body');
  assert.equal(result.preflight_result.diagnostics.metadata.immaculate_verdict, 'continue');
  assert.match(result.preflight_result.diagnostics.metadata.immaculate_record, /^[0-9a-f]{64}$/);
}));

test('a denied or held request gets deny with a valid reason code', () => withServer({}, async ({ hooks }) => {
  const [outOfScope] = await hookStream(hooks, [preflight({ target: { method: 'PATCH' } })]);
  assert.equal(outOfScope.result, 'deny');
  assert.equal(outOfScope.deny.diagnostics.reason_code, 'immaculate_action_out_of_scope');
  const [held] = await hookStream(hooks, [preflight({ target: { method: 'POST', host: 'api.payments.example', path: '/v1/refunds' } })]);
  assert.equal(held.deny.diagnostics.reason_code, 'immaculate_critical_requires_fresh_auth');
  for (const code of [outOfScope.deny.diagnostics.reason_code, held.deny.diagnostics.reason_code]) assert.match(code, /^[a-z][a-z0-9_]{0,63}$/);
}));

test('an invalid policy config or another phase is denied, not allowed', () => withServer({}, async ({ hooks }) => {
  const [badConfig] = await hookStream(hooks, [preflight({ config: { rules: 'all' } })]);
  assert.equal(badConfig.deny.diagnostics.reason_code, 'immaculate_config_invalid');
  const [noConfig] = await hookStream(hooks, [preflight({ config: null })]);
  assert.equal(noConfig.deny.diagnostics.reason_code, 'immaculate_config_invalid');
  const [phase] = await hookStream(hooks, [preflight({ phase: 'SUPERVISOR_MIDDLEWARE_PHASE_PRE_RETURN' })]);
  assert.equal(phase.deny.diagnostics.reason_code, 'immaculate_unsupported_phase');
}));

test('a stream that does not start with a preflight fails the exchange', () => withServer({}, async ({ hooks }) => {
  await expectStatus(hookStream(hooks, [{ begin: {} }]), grpc.status.FAILED_PRECONDITION);
}));

test('a session_end after the decision needs no answer', () => withServer({}, async ({ hooks }) => {
  const results = await hookStream(hooks, [preflight(), { session_end: { reason: 'MIDDLEWARE_SESSION_END_REASON_STAGE_SKIPPED' } }]);
  assert.equal(results.length, 1);
  assert.equal(results[0].result, 'preflight_result');
}));

test('the response hook, the legacy request RPC and WebSocket sessions are unimplemented', () => withServer({}, async ({ hooks, middleware }) => {
  await expectStatus(hookStream(hooks, [{}], new grpc.Metadata(), 'EvaluateHttpResponseHook'), grpc.status.UNIMPLEMENTED);
  await expectStatus(unary(middleware, 'EvaluateHttpRequest', {}), grpc.status.UNIMPLEMENTED);
  await expectStatus(hookStream(middleware, [{}], new grpc.Metadata(), 'EvaluateWebSocketSession'), grpc.status.UNIMPLEMENTED);
}));

test('with token checks: calls need the gateway token, and the request sandbox must be the token sandbox', async () => {
  const { privateKey, publicKey } = gatewayKeys();
  const verifier = new ExtensionTokenVerifier({ gatewayId: GATEWAY_ID, audience: AUDIENCE, keys: [{ kid: null, key: publicKey }], now: () => T0 });
  await withServer({ verifier }, async ({ middleware, hooks }) => {
    const gatewayToken = mintToken(privateKey, claims({ caller_kind: 'gateway', sandbox_id: undefined }));
    const supervisorToken = mintToken(privateKey, claims());

    await expectStatus(unary(middleware, 'Describe', { gateway: GATEWAY }), grpc.status.UNAUTHENTICATED);
    const manifest = await unary(middleware, 'Describe', { gateway: GATEWAY }, bearer(gatewayToken));
    assert.equal(manifest.expected_audience, AUDIENCE);
    await expectStatus(unary(middleware, 'ValidateConfig', { config: jsonToStruct(POLICY) }), grpc.status.UNAUTHENTICATED);
    assert.equal((await unary(middleware, 'ValidateConfig', { config: jsonToStruct(POLICY) }, bearer(gatewayToken))).valid, true);

    await expectStatus(hookStream(hooks, [preflight()]), grpc.status.UNAUTHENTICATED);
    const [allowed] = await hookStream(hooks, [preflight()], bearer(supervisorToken));
    assert.equal(allowed.result, 'preflight_result');
    const [otherSandbox] = await hookStream(hooks, [preflight({ context: { sandbox_id: 'sbx-b' } })], bearer(supervisorToken));
    assert.equal(otherSandbox.deny.diagnostics.reason_code, 'immaculate_sandbox_mismatch');
    const [fromGateway] = await hookStream(hooks, [preflight()], bearer(gatewayToken));
    assert.equal(fromGateway.deny.diagnostics.reason_code, 'immaculate_caller_not_supervisor');
    const expired = mintToken(privateKey, claims({ exp: T0 / 1000 - 3600 }));
    await expectStatus(hookStream(hooks, [preflight()], bearer(expired)), grpc.status.UNAUTHENTICATED);
    const forged = mintToken(gatewayKeys().privateKey, claims());
    await expectStatus(hookStream(hooks, [preflight()], bearer(forged)), grpc.status.UNAUTHENTICATED);
  });
});
