/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Partly-run actions in the local engine: the six acceptance tests, then the rules around them.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { LocalImmaculateEngine } from '../src/engine.mjs';

const T0 = Date.parse('2026-11-24T12:00:00.000Z');
const digest = (c) => c.repeat(64);

function setup() {
  const clock = { t: T0 };
  const engine = new LocalImmaculateEngine({ now: () => clock.t });
  const grant = engine.routeGrant({
    route_id: 'ops', scope: { actions: ['deploy.*', 'mail.*', 'revert.*'] }, granted_by: 'ops-lead', delegated_to: 'deploy-agent',
  }).route_grant;
  const authorize = (extra = {}) => engine.authorize({
    route_grant: grant, action: 'deploy.release', consequence_tier: 'medium', principal: 'deploy-agent', ...extra,
  });
  const start = (authorization, extra = {}) => engine.beginEffect({
    authorization_record_hash: authorization.record.record_hash,
    steps: ['upload', 'switch', 'purge-cache'],
    postcondition: 'site-a serves release 42',
    reversal: { class: 'COMPENSABLE', compensation: 'restore the previous deploy' },
    deadline_sec: 600,
    idempotency_key: 'deploy-42-attempt',
    ...extra,
  });
  return { clock, engine, grant, authorize, start };
}

test('1. an executor stopped between steps leaves an effect that reads IN_DOUBT after its deadline, with no call from it', () => {
  const { clock, engine, authorize, start } = setup();
  const auth = authorize({ effect_key: 'deploy:site-a', reversal_class: 'COMPENSABLE' });
  assert.equal(auth.decision, 'GRANTED');
  const begun = start(auth);
  assert.equal(begun.status, 'STARTED');
  const id = begun.effect.effect_id;
  engine.recordEffectStep({ effect_id: id, step: 'upload', status: 'ok', evidence_digest: digest('a') });
  // The executor stops here. Before the deadline the effect is open and still running.
  assert.equal(engine.listOpenEffects().open[0].state, 'STARTED');
  clock.t += 601_000;
  // Anyone's call finds it IN_DOUBT; the executor said nothing.
  const listed = engine.listOpenEffects();
  assert.equal(listed.open_count, 1);
  const [open] = listed.open;
  assert.equal(open.effect_id, id);
  assert.equal(open.state, 'IN_DOUBT');
  assert.equal(open.cleanup_owner, 'ops-lead', 'the grant issuer owns the cleanup by default');
  assert.deepEqual(open.receipts.map((r) => [r.step, r.status]), [['upload', 'ok']]);
  assert.equal(open.age_sec, 601);
  // The transition is sealed once.
  assert.equal(engine.chain.filter((r) => r.record_type === 'EFFECT_IN_DOUBT').length, 1);
  engine.listOpenEffects();
  assert.equal(engine.chain.filter((r) => r.record_type === 'EFFECT_IN_DOUBT').length, 1);
});

test('2. authorizing again on that effect key is DENIED, and the denial names the open effect', () => {
  const { clock, engine, authorize, start } = setup();
  const id = start(authorize({ effect_key: 'deploy:site-a' })).effect.effect_id;
  clock.t += 601_000;
  const again = authorize({ effect_key: 'deploy:site-a' });
  assert.equal(again.decision, 'DENIED');
  assert.equal(again.reason_code, 'EFFECT_OPEN');
  assert.equal(again.open_effect_id, id);
  assert.equal(again.record.payload.open_effect_id, id, 'the denial is sealed with the open effect');
  // Another key is unaffected.
  assert.equal(authorize({ effect_key: 'deploy:site-b' }).decision, 'GRANTED');
});

test('3. a compensation whose read-back shows the first state makes the effect COMPENSATED, and the chain verifies offline', () => {
  const { clock, engine, grant, authorize, start } = setup();
  const original = start(authorize({ effect_key: 'deploy:site-a' })).effect.effect_id;
  engine.recordEffectStep({ effect_id: original, step: 'upload', status: 'ok' });
  clock.t += 601_000;
  assert.equal(engine.listOpenEffects().open[0].state, 'IN_DOUBT');
  // The compensation is authorized on its own, as the one authorization the open effect admits on its key.
  const compAuth = engine.authorize({
    route_grant: grant, action: 'revert.deploy', consequence_tier: 'medium', principal: 'ops-lead',
    effect_key: 'deploy:site-a', compensates_effect_id: original,
  });
  assert.equal(compAuth.decision, 'GRANTED');
  const comp = engine.compensateEffect({
    effect_id: original,
    authorization_record_hash: compAuth.record.record_hash,
    steps: ['restore-previous'],
    postcondition: 'site-a serves release 41, as before the effect',
    reversal: { class: 'COMPENSABLE', compensation: 'deploy release 42 again' },
    deadline_sec: 300,
    idempotency_key: 'revert-42-to-41',
  });
  assert.equal(comp.status, 'STARTED');
  assert.equal(comp.effect.compensates, original);
  engine.recordEffectStep({ effect_id: comp.effect.effect_id, step: 'restore-previous', status: 'ok' });
  const closed = engine.closeEffect({
    effect_id: comp.effect.effect_id,
    read_back: { postcondition_met: true, downstream_changed: true, evidence_digest: digest('b') },
  });
  assert.equal(closed.outcome, 'COMMITTED');
  assert.equal(closed.compensated.effect_id, original);
  assert.equal(closed.compensated.state, 'COMPENSATED');
  assert.equal(engine.listOpenEffects().open_count, 0);
  const verified = engine.verifyChain({ records: engine.chain, expected_signer_kid: engine.signerKid });
  assert.equal(verified.valid, true, verified.reason);
  const types = engine.chain.map((r) => r.record_type);
  for (const type of ['EFFECT_STARTED', 'EFFECT_STEP', 'EFFECT_IN_DOUBT', 'EFFECT_CLOSED', 'EFFECT_COMPENSATED']) {
    assert.ok(types.includes(type), `${type} is sealed`);
  }
});

test('4. an IRREVERSIBLE effect with no prior human approval is DENIED at authorization', () => {
  const { clock, engine, grant } = setup();
  const mail = (extra) => engine.authorize({
    route_grant: grant, action: 'mail.send', consequence_tier: 'high', principal: 'deploy-agent',
    effect_key: 'mail:release-notes', reversal_class: 'IRREVERSIBLE', ...extra,
  });
  for (const human_approval of [undefined, {}, { approver: 'ops-lead', auth_method: 'webauthn' },
    { approver: 'ops-lead', auth_method: 'webauthn', approved_at: new Date(T0 - 16 * 60_000).toISOString() }]) {
    const denied = mail({ human_approval });
    assert.equal(denied.decision, 'DENIED', JSON.stringify(human_approval));
    assert.equal(denied.reason_code, 'IRREVERSIBLE_NEEDS_HUMAN_APPROVAL');
  }
  const approved = mail({ human_approval: { approver: 'ops-lead', auth_method: 'webauthn', approved_at: new Date(clock.t - 60_000).toISOString() } });
  assert.equal(approved.decision, 'GRANTED');
  assert.equal(approved.record.payload.human_approval.approver, 'ops-lead');
  // An irreversible effect is accepted by a person, never compensated.
  const begun = engine.beginEffect({
    authorization_record_hash: approved.record.record_hash, steps: ['send'], postcondition: 'the notes reached the list',
    reversal: { class: 'IRREVERSIBLE' }, deadline_sec: 60, idempotency_key: 'release-notes-42',
  });
  assert.equal(begun.status, 'STARTED');
  clock.t += 61_000;
  const refused = engine.compensateEffect({ effect_id: begun.effect.effect_id, authorization_record_hash: approved.record.record_hash, steps: ['x'], postcondition: 'x', reversal: { class: 'IRREVERSIBLE' }, deadline_sec: 60, idempotency_key: 'undo-mail-1' });
  assert.equal(refused.reason_code, 'EFFECT_IRREVERSIBLE');
  const accepted = engine.acceptEffect({ effect_id: begun.effect.effect_id, accepted_by: 'ops-lead', auth_method: 'webauthn', auth_freshness_sec: 30, reason: 'the mail went out; nothing to undo' });
  assert.equal(accepted.status, 'ACCEPTED');
});

test('5. a retry with the same idempotency key does not apply the effect twice', () => {
  const { engine, authorize, start } = setup();
  const auth = authorize({ effect_key: 'deploy:site-a' });
  const first = start(auth);
  const startedBefore = engine.chain.filter((r) => r.record_type === 'EFFECT_STARTED').length;
  const retry = start(auth);
  assert.equal(retry.status, 'REPLAYED');
  assert.equal(retry.effect.effect_id, first.effect.effect_id);
  assert.equal(engine.chain.filter((r) => r.record_type === 'EFFECT_STARTED').length, startedBefore, 'no second start is sealed');
  // A retried step that already landed is not recorded twice either.
  engine.recordEffectStep({ effect_id: first.effect.effect_id, step: 'upload', status: 'ok' });
  const again = engine.recordEffectStep({ effect_id: first.effect.effect_id, step: 'upload', status: 'ok' });
  assert.equal(again.reason_code, 'STEP_ALREADY_RECORDED');
  // While the first is still running, a new authorization on its key is fenced, so a second start cannot rest on one.
  const second = authorize({ effect_key: 'deploy:site-a' });
  assert.equal(second.decision, 'DENIED');
  assert.equal(second.reason_code, 'EFFECT_OPEN');
  assert.equal(second.open_effect_id, first.effect.effect_id);
  // And a start from an authorization that named no key is fenced at the start.
  const unkeyed = authorize();
  const fenced = start(unkeyed, { effect_key: 'deploy:site-a', idempotency_key: 'deploy-42-second' });
  assert.equal(fenced.reason_code, 'EFFECT_OPEN');
  assert.equal(fenced.open_effect_id, first.effect.effect_id);
});

test('6. steps that exit 0 and change nothing close as ABORTED, never COMMITTED', () => {
  const { engine, authorize, start } = setup();
  const id = start(authorize({ effect_key: 'deploy:site-a' })).effect.effect_id;
  for (const step of ['upload', 'switch', 'purge-cache']) engine.recordEffectStep({ effect_id: id, step, status: 'ok' });
  const closed = engine.closeEffect({ effect_id: id, read_back: { postcondition_met: false, downstream_changed: false, detail: 'site-a still serves release 41' } });
  assert.equal(closed.outcome, 'ABORTED');
  assert.match(closed.why, /nothing changed downstream/);
  assert.equal(closed.record.payload.outcome, 'ABORTED');
});

test('a close is checked: no read-back is never COMMITTED, and a changed but unfinished downstream is PARTIAL', () => {
  const { engine, authorize, start } = setup();
  const quiet = start(authorize({ effect_key: 'deploy:q' })).effect.effect_id;
  assert.equal(engine.closeEffect({ effect_id: quiet }).outcome, 'ABORTED', 'no ok step and no read-back');
  const half = start(authorize({ effect_key: 'deploy:h' }), { idempotency_key: 'deploy-h-1' }).effect.effect_id;
  engine.recordEffectStep({ effect_id: half, step: 'upload', status: 'ok' });
  assert.equal(engine.closeEffect({ effect_id: half }).outcome, 'PARTIAL', 'an ok step without a read-back');
  const changed = start(authorize({ effect_key: 'deploy:c' }), { idempotency_key: 'deploy-c-1' }).effect.effect_id;
  engine.recordEffectStep({ effect_id: changed, step: 'upload', status: 'ok' });
  assert.equal(engine.closeEffect({ effect_id: changed, read_back: { postcondition_met: false, downstream_changed: true } }).outcome, 'PARTIAL');
  const missing = start(authorize({ effect_key: 'deploy:m' }), { idempotency_key: 'deploy-m-1' }).effect.effect_id;
  engine.recordEffectStep({ effect_id: missing, step: 'upload', status: 'ok' });
  const m = engine.closeEffect({ effect_id: missing, read_back: { postcondition_met: true, downstream_changed: true } });
  assert.equal(m.outcome, 'PARTIAL', 'the postcondition without every step receipt');
  const done = start(authorize({ effect_key: 'deploy:d' }), { idempotency_key: 'deploy-d-1' }).effect.effect_id;
  for (const step of ['upload', 'switch', 'purge-cache']) engine.recordEffectStep({ effect_id: done, step, status: 'ok' });
  assert.equal(engine.closeEffect({ effect_id: done, read_back: { postcondition_met: true, downstream_changed: true } }).outcome, 'COMMITTED');
  // PARTIAL stays open until a compensation or a person closes it; COMMITTED and ABORTED do not.
  assert.deepEqual(engine.listOpenEffects().open.map((e) => e.state).sort(), ['PARTIAL', 'PARTIAL', 'PARTIAL']);
});

test('the start is refused without what detection, ownership and reversal need', () => {
  const { engine, authorize, start } = setup();
  const auth = authorize({ effect_key: 'deploy:site-a' });
  assert.throws(() => start(auth, { deadline_sec: 0 }), /deadline_sec/);
  assert.throws(() => start(auth, { reversal: { class: 'COMPENSABLE' } }), /compensating action/);
  assert.throws(() => start(auth, { reversal: { class: 'REVERSIBLE' } }), /inverse/);
  assert.throws(() => start(auth, { steps: [] }), /steps/);
  assert.throws(() => start(auth, { postcondition: '' }), /postcondition/);
  assert.equal(start({ record: { record_hash: digest('c') } }).reason_code, 'AUTHORIZATION_UNKNOWN');
  const denied = engine.authorize({ route_grant: { grant_hash: 'x', signature_b64: 'y' }, action: 'deploy.x', consequence_tier: 'low', principal: 'p', effect_key: 'deploy:z' });
  assert.equal(start(denied).reason_code, 'AUTHORIZATION_UNKNOWN', 'only a GRANTED authorization starts an effect');
  const used = start(auth);
  assert.equal(used.status, 'STARTED');
  assert.equal(start(auth, { idempotency_key: 'another-key-1' }).reason_code, 'AUTHORIZATION_ALREADY_USED');
  assert.equal(authorize({ effect_key: 'not a key!' }).reason_code, 'EFFECT_KEY_INVALID');
});
