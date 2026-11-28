import assert from 'node:assert/strict';
import { closeSync, openSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { LocalImmaculateEngine, sha256Hex } from '../../../src/engine.mjs';
import { DECISION_RECORD, gateReasonCode } from '../src/gate.mjs';
import { validatePolicyConfig } from '../src/policy.mjs';
import { clock, CONTEXT, grants, makeGate, POLICY, readRecords, removeDir, TARGET, tempDir } from './helpers.mjs';

const policy = validatePolicyConfig(POLICY).policy;
const verifyFile = (records) => new LocalImmaculateEngine().verifyChain({ records, expected_signer_kid: records[0].signer_kid });

function withGate(options, fn) {
  const dir = tempDir();
  const gate = makeGate({ dir, ...options });
  try {
    return fn(gate, dir);
  } finally {
    gate.close();
    removeDir(dir);
  }
}

test('a request in scope continues, and its two records are on disk before the answer', () => withGate({}, (gate, dir) => {
  const decision = gate.decide({ target: TARGET, context: CONTEXT, policy, caller: null });
  assert.equal(decision.verdict, 'continue');
  assert.equal(decision.reason_code, '');
  assert.equal(decision.metadata.immaculate_action, 'crm.read.contacts');
  assert.equal(decision.metadata.immaculate_engine_decision, 'GRANTED');

  const files = readRecords(dir);
  const [records] = Object.values(files);
  assert.equal(Object.keys(files).length, 1);
  assert.deepEqual(records.map((record) => record.record_type), ['ROUTE_GRANT', 'AUTHORIZATION', DECISION_RECORD]);
  const verified = verifyFile(records);
  assert.equal(verified.valid, true, verified.reason);

  const [, authorization, gateRecord] = records;
  assert.equal(authorization.payload.decision, 'GRANTED');
  assert.equal(authorization.payload.principal, 'openshell-sandbox:sbx-a');
  assert.equal(gateRecord.payload.authorization_record, authorization.record_hash);
  assert.equal(gateRecord.record_hash, decision.metadata.immaculate_record);
  assert.equal(gateRecord.payload.rule, 'crm-read');
  assert.equal(gateRecord.payload.process_binary, '/usr/bin/python3');
}));

test('the sealed record keeps digests of the path and query, never the text', () => withGate({}, (gate, dir) => {
  gate.decide({ target: { ...TARGET, path: '/v1/contacts/7', query: 'token=hunter2' }, context: CONTEXT, policy, caller: null });
  const text = JSON.stringify(readRecords(dir));
  assert.equal(text.includes('hunter2'), false);
  assert.equal(text.includes('/v1/contacts/7'), false);
  const gateRecord = Object.values(readRecords(dir))[0].at(-1);
  assert.equal(gateRecord.payload.path_sha256, sha256Hex('/v1/contacts/7'));
  assert.equal(gateRecord.payload.query_sha256, sha256Hex('token=hunter2'));
}));

test('an action outside the grant is denied with the engine reason code', () => withGate({}, (gate) => {
  const decision = gate.decide({ target: { ...TARGET, method: 'PATCH' }, context: CONTEXT, policy, caller: null });
  assert.equal(decision.verdict, 'deny');
  assert.equal(decision.reason_code, 'immaculate_action_out_of_scope');
  assert.equal(decision.metadata.immaculate_engine_decision, 'DENIED');
}));

test('a critical action is held: the engine escalates it and the gate denies it', () => withGate({}, (gate, dir) => {
  const decision = gate.decide({ target: { ...TARGET, method: 'POST', host: 'api.payments.example', path: '/v1/refunds' }, context: CONTEXT, policy, caller: null });
  assert.equal(decision.verdict, 'deny');
  assert.equal(decision.reason_code, 'immaculate_critical_requires_fresh_auth');
  assert.equal(decision.metadata.immaculate_engine_decision, 'ESCALATED');
  const gateRecord = Object.values(readRecords(dir))[0].at(-1);
  assert.equal(gateRecord.payload.engine_decision, 'ESCALATED');
  assert.equal(gateRecord.payload.verdict, 'deny');
}));

test('a high-tier action in scope continues: no authentication age is known for a sandbox request', () => withGate({}, (gate) => {
  const decision = gate.decide({ target: { ...TARGET, method: 'POST', host: 'eu.mail.example', path: '/send' }, context: CONTEXT, policy, caller: null });
  assert.equal(decision.verdict, 'continue');
  assert.equal(decision.metadata.immaculate_tier, 'high');
}));

test('a sandbox no grant covers is denied; a named sandbox uses its own grant before the "*" grant', () => {
  const list = [
    { route_id: 'named', granted_by: 'ops@example.test', sandboxes: ['sbx-b'], actions: ['crm.write.*'], expires_at: '2026-11-29T00:00:00.000Z' },
  ];
  withGate({ grantList: list }, (gate) => {
    assert.equal(gate.decide({ target: TARGET, context: CONTEXT, policy, caller: null }).reason_code, 'immaculate_no_grant');
    const write = gate.decide({ target: { ...TARGET, method: 'POST' }, context: { ...CONTEXT, sandbox_id: 'sbx-b' }, policy, caller: null });
    assert.equal(write.verdict, 'continue');
  });
  withGate({ grantList: [...list, ...grants()] }, (gate) => {
    // sbx-b's own grant has no crm.read, so the "*" grant is not consulted for it.
    assert.equal(gate.decide({ target: TARGET, context: { ...CONTEXT, sandbox_id: 'sbx-b' }, policy, caller: null }).reason_code, 'immaculate_action_out_of_scope');
    assert.equal(gate.decide({ target: TARGET, context: CONTEXT, policy, caller: null }).verdict, 'continue');
  });
});

test('after a grant expires, its sandboxes are denied', () => {
  const now = clock();
  withGate({ now, grantList: grants({ expiresAt: '2026-11-28T01:00:00.000Z' }) }, (gate) => {
    assert.equal(gate.decide({ target: TARGET, context: CONTEXT, policy, caller: null }).verdict, 'continue');
    now.advance(2 * 3_600_000);
    assert.equal(gate.decide({ target: TARGET, context: CONTEXT, policy, caller: null }).reason_code, 'immaculate_grant_expired');
  });
});

test('the caller token must be a supervisor for the same sandbox as the request', () => withGate({}, (gate, dir) => {
  const mismatch = gate.decide({ target: TARGET, context: CONTEXT, policy, caller: { caller_kind: 'supervisor', sandbox_id: 'sbx-b' } });
  assert.equal(mismatch.reason_code, 'immaculate_sandbox_mismatch');
  const gatewayCaller = gate.decide({ target: TARGET, context: CONTEXT, policy, caller: { caller_kind: 'gateway' } });
  assert.equal(gatewayCaller.reason_code, 'immaculate_caller_not_supervisor');
  const ok = gate.decide({ target: TARGET, context: CONTEXT, policy, caller: { caller_kind: 'supervisor', sandbox_id: 'sbx-a' } });
  assert.equal(ok.verdict, 'continue');
  const records = Object.values(readRecords(dir))[0];
  assert.deepEqual(records.filter((record) => record.record_type === DECISION_RECORD).map((record) => record.payload.caller_kind), ['supervisor', 'gateway', 'supervisor']);
}));

test('no sandbox_id, an unmatched request and a server refusal are denied, and each is sealed', () => withGate({}, (gate, dir) => {
  assert.equal(gate.decide({ target: TARGET, context: { ...CONTEXT, sandbox_id: '' }, policy, caller: null }).reason_code, 'immaculate_no_sandbox_id');
  assert.equal(gate.decide({ target: { ...TARGET, host: 'elsewhere.example' }, context: CONTEXT, policy, caller: null }).reason_code, 'immaculate_unmatched_request');
  const refusal = gate.decide({ target: TARGET, context: CONTEXT, policy: null, caller: null, refusal: { reason_code: 'immaculate_config_invalid', reason: 'config.rules is a list.' } });
  assert.equal(refusal.reason_code, 'immaculate_config_invalid');
  assert.equal(refusal.reason, 'config.rules is a list.');
  const decisions = Object.values(readRecords(dir))[0].filter((record) => record.record_type === DECISION_RECORD);
  assert.deepEqual(decisions.map((record) => record.payload.reason_code), ['immaculate_no_sandbox_id', 'immaculate_unmatched_request', 'immaculate_config_invalid']);
  assert.ok(decisions.every((record) => record.payload.authorization_record === null));
}));

test('runs rotate: a new key and file, the grants re-sealed with the same expiry, and every file verifies', () => withGate({ rotateAfterRecords: 7 }, (gate, dir) => {
  const kids = new Set();
  for (let i = 0; i < 6; i += 1) {
    kids.add(gate.signerKid);
    assert.equal(gate.decide({ target: TARGET, context: CONTEXT, policy, caller: null }).verdict, 'continue');
  }
  const files = readRecords(dir);
  assert.equal(Object.keys(files).length, 3, Object.keys(files).join(', '));
  assert.ok(kids.size >= 2);
  for (const [name, records] of Object.entries(files)) {
    const verified = verifyFile(records);
    assert.equal(verified.valid, true, `${name}: ${verified.reason}`);
    assert.equal(records[0].record_type, 'ROUTE_GRANT');
    assert.equal(records[0].payload.expires_at, '2026-11-29T00:00:00.000Z');
  }
}));

test('when records cannot be written the gate denies, retries a new run at most every 5 s, and recovers', () => {
  const now = clock();
  const logs = [];
  withGate({ now, log: (level, message) => logs.push(`${level}: ${message}`) }, (gate, dir) => {
    const decide = () => gate.decide({ target: TARGET, context: CONTEXT, policy, caller: null });
    // Writes start failing, as on a failed disk: the records file's descriptor is swapped for a read-only one.
    const recordsFd = gate.run.fd;
    writeFileSync(path.join(dir, 'read-only.txt'), '');
    gate.run.fd = openSync(path.join(dir, 'read-only.txt'), 'r');
    const denied = decide();
    assert.equal(denied.verdict, 'deny');
    assert.equal(denied.reason_code, 'immaculate_record_write_failed');
    assert.ok(logs.some((line) => line.startsWith('error: sealed records could not be written')));

    // A new run cannot start either: its folder sits under a file.
    const recordsDir = gate.recordsDir;
    writeFileSync(path.join(dir, 'blocker'), '');
    gate.recordsDir = path.join(dir, 'blocker', 'records');
    assert.equal(decide().reason_code, 'immaculate_record_write_failed');
    assert.ok(logs.some((line) => line.startsWith('error: could not start a new run')));
    const attempts = logs.filter((line) => line.startsWith('error: could not start a new run')).length;
    assert.equal(decide().reason_code, 'immaculate_record_write_failed');
    assert.equal(logs.filter((line) => line.startsWith('error: could not start a new run')).length, attempts, 'no new attempt within 5 s');

    gate.recordsDir = recordsDir;
    now.advance(5000);
    assert.equal(decide().verdict, 'continue');
    assert.equal(readdirSync(dir).filter((name) => name.endsWith('.jsonl')).length, 2);
    assert.ok(logs.some((line) => line.startsWith('info: new run of the gate')));
    closeSync(recordsFd);
  });
});

test('reason codes are "immaculate_" and the engine code, within OpenShell\'s format', () => {
  assert.equal(gateReasonCode('GRANT_REVOKED'), 'immaculate_grant_revoked');
  assert.equal(gateReasonCode(undefined), 'immaculate_denied');
  assert.equal(gateReasonCode('BAD CODE!'), 'immaculate_denied');
  assert.equal(gateReasonCode('X'.repeat(80)), 'immaculate_denied');
});
