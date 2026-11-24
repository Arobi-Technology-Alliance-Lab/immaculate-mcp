/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Partly-run actions in the local engine: the six acceptance tests, then one test per rule of the lifecycle
 * (IN_DOUBT unless proven, a close bound to its attempt, attempt fencing, no new work under a stopped grant, the
 * clock's deadlines, bounded recovery, the evidence chain, IRREVERSIBLE held at authorization) and ACCEPTED.
 */

import crypto from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, LocalImmaculateEngine, sha256Hex } from '../src/engine.mjs';

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
  // The binding a write carries: the effect, its attempt and the lease a start or a claim returned.
  const as = (holder) => ({ effect_id: holder.effect.effect_id, attempt: holder.effect.attempt, lease_token: holder.lease.token });
  const step = (holder, name, status = 'ok') => engine.recordEffectStep({ ...as(holder), step: name, status });
  const readBack = (over = {}) => ({
    postcondition_met: false, downstream_changed: false, observed_at: new Date(clock.t).toISOString(), evidence_digest: digest('e'), ...over,
  });
  const close = (holder, read_back) => engine.closeEffect({ ...as(holder), ...(read_back ? { read_back } : {}) });
  const claim = (holder) => engine.claimEffect({ effect_id: holder.effect.effect_id, attempt: holder.effect.attempt });
  const accept = (holder, extra = {}) => engine.acceptEffect({
    effect_id: holder.effect.effect_id, attempt: holder.effect.attempt, accepted_by: 'ops-lead', auth_method: 'webauthn',
    auth_freshness_sec: 30, reason: 'checked by hand', ...extra,
  });
  return { clock, engine, grant, authorize, start, as, step, readBack, close, claim, accept };
}

const types = (engine, type) => engine.chain.filter((r) => r.record_type === type);

test('1. an executor stopped between steps leaves an effect that reads IN_DOUBT after its deadline, with no call from it', () => {
  const { clock, engine, authorize, start, step } = setup();
  const auth = authorize({ effect_key: 'deploy:site-a', reversal_class: 'COMPENSABLE' });
  assert.equal(auth.decision, 'GRANTED');
  const begun = start(auth);
  assert.equal(begun.status, 'STARTED');
  assert.equal(begun.effect.attempt, 1);
  assert.equal(begun.lease.generation, 1);
  assert.equal(begun.lease.until, begun.effect.deadline_at, 'the lease ends at the deadline');
  const id = begun.effect.effect_id;
  step(begun, 'upload');
  // The executor stops here. Before the deadline the effect is open and still running.
  assert.equal(engine.listOpenEffects().open[0].state, 'STARTED');
  clock.t += 601_000;
  // Anyone's call finds it IN_DOUBT; the executor said nothing.
  const listed = engine.listOpenEffects();
  assert.equal(listed.open_count, 1);
  const [open] = listed.open;
  assert.equal(open.effect_id, id);
  assert.equal(open.state, 'IN_DOUBT');
  assert.equal(open.in_doubt_cause, 'DEADLINE_PASSED');
  assert.equal(open.cleanup_owner, 'ops-lead', 'the grant issuer owns the cleanup by default');
  assert.deepEqual(open.receipts.map((r) => [r.step, r.status]), [['upload', 'ok']]);
  assert.equal(open.age_sec, 601);
  assert.equal(open.lease.live, false, 'its lease ended with the deadline');
  // The transition is sealed once.
  assert.equal(types(engine, 'EFFECT_IN_DOUBT').length, 1);
  engine.listOpenEffects();
  assert.equal(types(engine, 'EFFECT_IN_DOUBT').length, 1);
});

test('2. authorizing again on that effect key is DENIED, and the denial names the open effect', () => {
  const { clock, authorize, start } = setup();
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

test('3. a compensation whose read-back shows the first state makes the effect COMPENSATED, and the chain verifies offline (and refuses tampering)', () => {
  const { clock, engine, grant, authorize, start, step, readBack, close } = setup();
  const original = start(authorize({ effect_key: 'deploy:site-a' }));
  const originalId = original.effect.effect_id;
  step(original, 'upload');
  clock.t += 601_000;
  assert.equal(engine.listOpenEffects().open[0].state, 'IN_DOUBT');
  // The compensation is authorized on its own, as the one authorization the open effect admits on its key.
  const compAuth = engine.authorize({
    route_grant: grant, action: 'revert.deploy', consequence_tier: 'medium', principal: 'ops-lead',
    effect_key: 'deploy:site-a', compensates_effect_id: originalId,
  });
  assert.equal(compAuth.decision, 'GRANTED');
  const comp = engine.compensateEffect({
    effect_id: originalId,
    authorization_record_hash: compAuth.record.record_hash,
    steps: ['restore-previous'],
    postcondition: 'site-a serves release 41, as before the effect',
    reversal: { class: 'COMPENSABLE', compensation: 'deploy release 42 again' },
    deadline_sec: 300,
    idempotency_key: 'revert-42-to-41',
  });
  assert.equal(comp.status, 'STARTED');
  assert.equal(comp.effect.compensates, originalId);
  assert.equal(comp.effect.attempt, 1, 'the first compensation of that effect');
  assert.notEqual(comp.lease.token, original.lease.token, 'its own lease');
  step(comp, 'restore-previous');
  const closed = close(comp, readBack({ postcondition_met: true, downstream_changed: true, evidence_digest: digest('b') }));
  assert.equal(closed.outcome, 'COMMITTED');
  assert.equal(closed.compensated.effect_id, originalId);
  assert.equal(closed.compensated.state, 'COMPENSATED');
  assert.equal(engine.listOpenEffects().open_count, 0);
  for (const type of ['EFFECT_STARTED', 'EFFECT_STEP', 'EFFECT_IN_DOUBT', 'EFFECT_CLOSED', 'EFFECT_COMPENSATED']) {
    assert.ok(types(engine, type).length > 0, `${type} is sealed`);
  }

  // Offline: a verifier holding none of this engine's state checks the chain against the signer it trusts.
  const offline = new LocalImmaculateEngine();
  const check = (records) => offline.verifyChain({ records, expected_signer_kid: engine.signerKid });
  const verified = check(engine.chain);
  assert.equal(verified.valid, true, verified.reason);
  assert.equal(verified.checked_count, engine.chain.length);

  // Tampered copies are refused at the record where they break.
  const records = structuredClone(engine.chain);
  const at = records.findIndex((r) => r.record_type === 'EFFECT_CLOSED');
  const gap = check([...records.slice(0, at), ...records.slice(at + 1)]);
  assert.deepEqual([gap.valid, gap.first_broken_index], [false, at], 'a record removed');
  assert.match(gap.reason, /missing, repeated or out of order/);
  const swapped = [...records];
  [swapped[at - 1], swapped[at]] = [swapped[at], swapped[at - 1]];
  const reordered = check(swapped);
  assert.deepEqual([reordered.valid, reordered.first_broken_index], [false, at - 1], 'two records swapped');
  // A fork: a second record on the same predecessor, validly signed by the same key, says ABORTED instead.
  const body = { ...records[at], payload: { ...records[at].payload, outcome: 'ABORTED' } };
  const forkBody = { seq: body.seq, record_type: body.record_type, prev_hash: body.prev_hash, timestamp: body.timestamp, payload: body.payload };
  const forkHash = sha256Hex(canonicalJson(forkBody));
  const fork = {
    ...forkBody, record_hash: forkHash, signer_kid: engine.signerKid, public_key_pem: engine.publicKeyPem,
    signature_b64: crypto.sign(null, Buffer.from(forkHash, 'utf8'), engine.privateKey).toString('base64'),
  };
  assert.equal(check([...records.slice(0, at), fork]).valid, true, 'the fork alone is a well-formed chain of its own');
  const forked = check([...records.slice(0, at + 1), fork, ...records.slice(at + 1)]);
  assert.deepEqual([forked.valid, forked.first_broken_index], [false, at + 1], 'both branches shown');
  const edited = structuredClone(records);
  edited[at].payload.outcome = 'ABORTED';
  const tampered = check(edited);
  assert.deepEqual([tampered.valid, tampered.first_broken_index], [false, at], 'a sealed outcome edited');
  assert.match(tampered.reason, /Digest mismatch/);
});

test('4. an IRREVERSIBLE effect with no prior human approval is DENIED at authorization, and a held authorization starts nothing', () => {
  const { clock, engine, grant, accept } = setup();
  const mail = (extra) => engine.authorize({
    route_grant: grant, action: 'mail.send', consequence_tier: 'high', principal: 'deploy-agent',
    effect_key: 'mail:release-notes', reversal_class: 'IRREVERSIBLE', ...extra,
  });
  const sendMail = (authorization, idempotency_key) => engine.beginEffect({
    authorization_record_hash: authorization.record.record_hash, steps: ['send'], postcondition: 'the notes reached the list',
    reversal: { class: 'IRREVERSIBLE' }, deadline_sec: 60, idempotency_key,
  });
  const held = [undefined, {}, { approver: 'ops-lead', auth_method: 'webauthn' },
    { approver: 'ops-lead', auth_method: 'webauthn', approved_at: new Date(T0 - 16 * 60_000).toISOString() }];
  for (const [i, human_approval] of held.entries()) {
    const denied = mail({ human_approval });
    assert.equal(denied.decision, 'DENIED', JSON.stringify(human_approval));
    assert.equal(denied.reason_code, 'IRREVERSIBLE_NEEDS_HUMAN_APPROVAL');
    // Held at authorization: nothing can start from it, and no STARTED record exists.
    assert.equal(sendMail(denied, `release-notes-held-${i}`).reason_code, 'AUTHORIZATION_UNKNOWN');
  }
  assert.equal(types(engine, 'EFFECT_STARTED').length, 0, 'a held authorize leaves no STARTED record');
  const approved = mail({ human_approval: { approver: 'ops-lead', auth_method: 'webauthn', approved_at: new Date(clock.t - 60_000).toISOString() } });
  assert.equal(approved.decision, 'GRANTED');
  assert.equal(approved.record.payload.human_approval.approver, 'ops-lead');
  const begun = sendMail(approved, 'release-notes-42');
  assert.equal(begun.status, 'STARTED');
  clock.t += 61_000;
  // An irreversible effect is accepted by a person, never compensated.
  const refused = engine.compensateEffect({ effect_id: begun.effect.effect_id, authorization_record_hash: approved.record.record_hash, steps: ['x'], postcondition: 'x', reversal: { class: 'IRREVERSIBLE' }, deadline_sec: 60, idempotency_key: 'undo-mail-1' });
  assert.equal(refused.reason_code, 'EFFECT_IRREVERSIBLE');
  const accepted = accept(begun, { reason: 'the mail went out; nothing to undo' });
  assert.equal(accepted.status, 'ACCEPTED');
  assert.equal(accepted.effect.accepted_from, 'IN_DOUBT');
});

test('5. a retry with the same idempotency key does not apply the effect twice', () => {
  const { engine, authorize, start, step } = setup();
  const auth = authorize({ effect_key: 'deploy:site-a' });
  const first = start(auth);
  const startedBefore = types(engine, 'EFFECT_STARTED').length;
  const retry = start(auth);
  assert.equal(retry.status, 'REPLAYED');
  assert.equal(retry.effect.effect_id, first.effect.effect_id);
  assert.equal(retry.lease, undefined, 'a replay carries no lease: one holder at a time');
  assert.equal(types(engine, 'EFFECT_STARTED').length, startedBefore, 'no second start is sealed');
  // A retried step that already landed is not recorded twice either.
  step(first, 'upload');
  assert.equal(step(first, 'upload').reason_code, 'STEP_ALREADY_RECORDED');
  // While the first is still running, a new authorization on its key is fenced, so a second start cannot rest on one.
  const second = authorize({ effect_key: 'deploy:site-a' });
  assert.equal(second.decision, 'DENIED');
  assert.equal(second.reason_code, 'EFFECT_OPEN');
  assert.equal(second.open_effect_id, first.effect.effect_id);
  // And a start from an authorization that named no key is fenced at the start.
  const fenced = start(authorize(), { effect_key: 'deploy:site-a', idempotency_key: 'deploy-42-second' });
  assert.equal(fenced.reason_code, 'EFFECT_OPEN');
  assert.equal(fenced.open_effect_id, first.effect.effect_id);
  // The idempotency key is sealed only as its sha256.
  assert.ok(!JSON.stringify(engine.chain).includes('deploy-42-attempt'));
  assert.equal(types(engine, 'EFFECT_STARTED')[0].payload.idempotency_key_sha256, sha256Hex('deploy-42-attempt'));
});

test('6. steps that exit 0 and change nothing are IN_DOUBT until the attempt is fenced, and ABORTED (never COMMITTED) after', () => {
  const { clock, authorize, start, step, readBack, close, claim } = setup();
  const begun = start(authorize({ effect_key: 'deploy:site-a' }));
  for (const name of ['upload', 'switch', 'purge-cache']) step(begun, name);

  // Before the fence. The read-back shows nothing changed, but this attempt can still be used until its deadline: a
  // call that timed out may land after the read, and a retry would apply the effect twice.
  const unfenced = close(begun, readBack({ detail: 'site-a still serves release 41' }));
  assert.equal(unfenced.outcome, 'IN_DOUBT');
  assert.equal(unfenced.record.record_type, 'EFFECT_IN_DOUBT');
  assert.equal(unfenced.record.payload.cause, 'NOTHING_SEEN_UNFENCED');
  assert.equal(unfenced.effect.state, 'IN_DOUBT', 'open and owned, not ABORTED and never COMMITTED');
  assert.equal(authorize({ effect_key: 'deploy:site-a' }).reason_code, 'EFFECT_OPEN', 'its key stays fenced');
  const reconciler = claim(begun);
  assert.equal(reconciler.status, 'CLAIMED');
  assert.deepEqual([reconciler.lease.purpose, reconciler.lease.generation], ['RECONCILE', 2]);
  const tooSoon = close(reconciler, readBack({ fence: { kind: 'EXPIRED_UNUSED' } }));
  assert.equal(tooSoon.reason_code, 'FENCE_NOT_IN_FORCE', 'it cannot claim expiry before the deadline');

  // After the fence. Past the deadline the attempt can no longer be used; a read-back taken before the deadline still
  // does not count, and one taken after it closes the effect ABORTED.
  clock.t += 601_000;
  const stale = close(reconciler, readBack({ observed_at: new Date(T0 + 590_000).toISOString(), fence: { kind: 'EXPIRED_UNUSED' } }));
  assert.equal(stale.reason_code, 'FENCE_NOT_IN_FORCE');
  const aborted = close(reconciler, readBack({ fence: { kind: 'EXPIRED_UNUSED' } }));
  assert.equal(aborted.outcome, 'ABORTED');
  assert.match(aborted.why, /after the deadline/);
  assert.deepEqual(aborted.record.payload.read_back.fence, { kind: 'EXPIRED_UNUSED' });
  assert.equal(authorize({ effect_key: 'deploy:site-a' }).decision, 'GRANTED', 'and only now is the key free');
});

test('rule 1. "nothing seen" is IN_DOUBT, never ABORTED; a fence goes only with a read-back that shows nothing changed', () => {
  const { authorize, start, step, readBack, close } = setup();
  const quiet = start(authorize({ effect_key: 'deploy:q' }), { idempotency_key: 'deploy-q-1' });
  const none = close(quiet);
  assert.equal(none.outcome, 'IN_DOUBT', 'no step and no read-back is not proof of nothing');
  assert.equal(none.record.payload.cause, 'CLOSED_WITHOUT_READ_BACK');
  const half = start(authorize({ effect_key: 'deploy:h' }), { idempotency_key: 'deploy-h-1' });
  step(half, 'upload');
  assert.equal(close(half).outcome, 'IN_DOUBT', 'an exit status is not a read-back');

  // The downstream's own receipt that it took this attempt and will never apply it fences it at once.
  const refusedDownstream = start(authorize({ effect_key: 'deploy:r' }), { idempotency_key: 'deploy-r-1' });
  for (const name of ['upload', 'switch', 'purge-cache']) step(refusedDownstream, name);
  assert.throws(() => close(refusedDownstream, readBack({ fence: { kind: 'CONSUMED_NOT_RELEASED' } })), /receipt_digest/);
  assert.throws(() => close(refusedDownstream, readBack({ downstream_changed: true, fence: { kind: 'EXPIRED_UNUSED' } })), /only with a read-back that shows nothing changed/);
  assert.throws(() => close(refusedDownstream, readBack({ fence: { kind: 'TRUST_ME' } })), /fence.kind/);
  const consumed = close(refusedDownstream, readBack({ fence: { kind: 'CONSUMED_NOT_RELEASED', receipt_digest: digest('d') } }));
  assert.equal(consumed.outcome, 'ABORTED');
  assert.deepEqual(consumed.record.payload.read_back.fence, { kind: 'CONSUMED_NOT_RELEASED', receipt_digest: digest('d') });

  // What a read-back shows decides the rest.
  const changed = start(authorize({ effect_key: 'deploy:c' }), { idempotency_key: 'deploy-c-1' });
  step(changed, 'upload');
  assert.equal(close(changed, readBack({ downstream_changed: true })).outcome, 'PARTIAL');
  const missing = start(authorize({ effect_key: 'deploy:m' }), { idempotency_key: 'deploy-m-1' });
  step(missing, 'upload');
  assert.equal(close(missing, readBack({ postcondition_met: true, downstream_changed: true })).outcome, 'PARTIAL', 'the postcondition without every step receipt');
  const done = start(authorize({ effect_key: 'deploy:d' }), { idempotency_key: 'deploy-d-1' });
  for (const name of ['upload', 'switch', 'purge-cache']) step(done, name);
  assert.equal(close(done, readBack({ postcondition_met: true, downstream_changed: true })).outcome, 'COMMITTED');
});

test('rule 2. a close binds to its attempt: the attempt number, and a read-back taken after the start, not ahead, not stale, with a digest', () => {
  const { clock, engine, authorize, start, step, readBack, as } = setup();
  const begun = start(authorize({ effect_key: 'deploy:site-a' }));
  for (const name of ['upload', 'switch', 'purge-cache']) step(begun, name);
  clock.t += 60_000;
  const closeWith = (read_back, binding = {}) => engine.closeEffect({ ...as(begun), ...binding, read_back });
  const shows = { postcondition_met: true, downstream_changed: true };
  assert.equal(closeWith(readBack(shows), { attempt: 2 }).reason_code, 'ATTEMPT_MISMATCH');
  for (const observed_at of [new Date(T0 - 1_000).toISOString(), new Date(clock.t + 1_000).toISOString()]) {
    assert.equal(closeWith(readBack({ ...shows, observed_at })).reason_code, 'READ_BACK_BINDING_INVALID', observed_at);
  }
  const old = new Date(clock.t).toISOString();
  clock.t += 5 * 60_000 + 1;
  assert.equal(closeWith(readBack({ ...shows, observed_at: old })).reason_code, 'READ_BACK_BINDING_INVALID', 'more than 5 minutes old');
  assert.throws(() => closeWith({ ...shows, observed_at: new Date(clock.t).toISOString() }), /evidence_digest/);
  assert.throws(() => closeWith({ ...shows, evidence_digest: digest('e') }), /observed_at/);
  const committed = closeWith(readBack(shows));
  assert.equal(committed.outcome, 'COMMITTED');
  const sealed = committed.record.payload;
  assert.equal(sealed.attempt, 1);
  assert.equal(sealed.lease_generation, 1);
  assert.equal(sealed.plan_digest, types(engine, 'EFFECT_STARTED')[0].payload.plan_digest, 'the close names the plan the start fixed');
  assert.equal(sealed.read_back.observed_at, new Date(clock.t).toISOString());
  assert.equal(sealed.read_back.evidence_digest, digest('e'));
  assert.equal(closeWith(readBack(shows)).reason_code, 'EFFECT_CLOSED');
});

test('rule 3. attempt fencing: nothing the first attempt holds changes the retry, and its read-back cannot settle it', () => {
  const { clock, engine, authorize, start, step, readBack, close, claim } = setup();
  const first = start(authorize({ effect_key: 'deploy:site-a' }));
  step(first, 'upload');
  const firstReadAt = new Date(clock.t).toISOString();
  // The downstream refused attempt 1 for good, so it is fenced and ABORTED.
  assert.equal(close(first, readBack({ fence: { kind: 'CONSUMED_NOT_RELEASED', receipt_digest: digest('d') } })).outcome, 'ABORTED');
  clock.t += 5_000;
  // The same idempotency key now starts attempt 2, under an authorization of its own, with its own lease.
  const retry = start(authorize({ effect_key: 'deploy:site-a' }));
  assert.equal(retry.status, 'STARTED');
  assert.equal(retry.effect.attempt, 2);
  assert.notEqual(retry.effect.effect_id, first.effect.effect_id);
  const retryId = retry.effect.effect_id;
  // Attempt 1's lease writes to neither attempt.
  assert.equal(step(first, 'switch').reason_code, 'LEASE_STALE');
  const firstLease = first.lease.token;
  assert.equal(engine.recordEffectStep({ effect_id: retryId, attempt: 1, lease_token: firstLease, step: 'upload', status: 'ok' }).reason_code, 'ATTEMPT_MISMATCH');
  assert.equal(engine.recordEffectStep({ effect_id: retryId, attempt: 2, lease_token: firstLease, step: 'upload', status: 'ok' }).reason_code, 'LEASE_STALE');
  for (const name of ['upload', 'switch', 'purge-cache']) step(retry, name);
  // Attempt 1's read-back, however good, cannot settle attempt 2: it was taken before attempt 2 started.
  const shows = { postcondition_met: true, downstream_changed: true };
  assert.equal(close(retry, readBack({ ...shows, observed_at: firstReadAt })).reason_code, 'READ_BACK_BINDING_INVALID');
  assert.equal(engine.closeEffect({ effect_id: retryId, attempt: 1, lease_token: retry.lease.token, read_back: readBack(shows) }).reason_code, 'ATTEMPT_MISMATCH');
  assert.deepEqual(engine.chain.filter((r) => r.payload.effect_id === retryId).map((r) => r.record_type),
    ['EFFECT_STARTED', 'EFFECT_STEP', 'EFFECT_STEP', 'EFFECT_STEP'], 'nothing from attempt 1 landed on attempt 2');
  // Its own lease and its own read-back do.
  assert.equal(close(retry, readBack(shows)).outcome, 'COMMITTED');

  // A claim replaces a lapsed lease: the earlier holder's writes are refused from then on.
  const other = start(authorize({ effect_key: 'deploy:site-b' }), { idempotency_key: 'deploy-b-1' });
  clock.t += 601_000;
  assert.equal(step(other, 'upload').reason_code, 'LEASE_EXPIRED');
  const reconciler = claim(other);
  assert.equal(reconciler.lease.generation, 2);
  assert.equal(close(other, readBack({ fence: { kind: 'EXPIRED_UNUSED' } })).reason_code, 'LEASE_STALE');
  assert.equal(step(reconciler, 'upload').reason_code, 'LEASE_PURPOSE', 'a reconciler reads back; it records no steps');
  assert.equal(claim(other).reason_code, 'EFFECT_LEASED', 'one holder at a time');
  assert.equal(close(reconciler, readBack({ fence: { kind: 'EXPIRED_UNUSED' } })).outcome, 'ABORTED');
});

test('rule 4. no new work under a stopped grant: a revoked or expired grant starts no effect and no compensation, and in-flight work is still observed', () => {
  const { clock, engine, grant, authorize, start, step, readBack, close, claim } = setup();
  const original = start(authorize({ effect_key: 'deploy:site-a' }));
  step(original, 'upload');
  const inFlight = start(authorize({ effect_key: 'deploy:site-c' }), { idempotency_key: 'deploy-c-1', deadline_sec: 3_600 });
  const spare = authorize({ effect_key: 'deploy:site-b' });
  clock.t += 601_000;
  const compAuth = engine.authorize({
    route_grant: grant, action: 'revert.deploy', consequence_tier: 'medium', principal: 'ops-lead',
    effect_key: 'deploy:site-a', compensates_effect_id: original.effect.effect_id,
  });
  assert.equal(compAuth.decision, 'GRANTED');
  assert.equal(engine.revokeGrant({ route_grant: grant, reason: 'operator stop' }).status, 'REVOKED');
  // No compensation starts under the stopped grant, even from an authorization made before the stop...
  const comp = engine.compensateEffect({
    effect_id: original.effect.effect_id, authorization_record_hash: compAuth.record.record_hash, steps: ['restore-previous'],
    postcondition: 'site-a serves release 41', reversal: { class: 'COMPENSABLE', compensation: 'deploy 42 again' }, deadline_sec: 300,
    idempotency_key: 'revert-42-to-41',
  });
  assert.equal(comp.reason_code, 'GRANT_REVOKED');
  // ...no new effect starts either, and the grant authorizes nothing more.
  assert.equal(start(spare, { idempotency_key: 'deploy-b-1' }).reason_code, 'GRANT_REVOKED');
  assert.equal(authorize({ effect_key: 'deploy:site-d' }).reason_code, 'GRANT_REVOKED');
  assert.equal(types(engine, 'EFFECT_STARTED').length, 2, 'nothing started after the stop');
  // Observation goes on: the effect in flight takes its receipts and its close, and the IN_DOUBT one is read back.
  for (const name of ['upload', 'switch', 'purge-cache']) assert.equal(step(inFlight, name).status, 'RECORDED');
  assert.equal(close(inFlight, readBack({ postcondition_met: true, downstream_changed: true })).outcome, 'COMMITTED');
  const reconciler = claim(original);
  assert.equal(reconciler.status, 'CLAIMED');
  assert.equal(close(reconciler, readBack({ downstream_changed: true })).outcome, 'PARTIAL');

  // An expired grant stops new work the same way.
  const shortGrant = engine.routeGrant({
    route_id: 'short', scope: { actions: ['deploy.*'] }, granted_by: 'ops-lead', delegated_to: 'deploy-agent',
    expires_at: new Date(clock.t + 60_000).toISOString(),
  }).route_grant;
  const early = engine.authorize({ route_grant: shortGrant, action: 'deploy.release', consequence_tier: 'medium', principal: 'deploy-agent', effect_key: 'deploy:site-e' });
  assert.equal(early.decision, 'GRANTED');
  clock.t += 61_000;
  assert.equal(start(early, { idempotency_key: 'deploy-e-1' }).reason_code, 'GRANT_EXPIRED');
});

test('rule 5. deadlines are the clock\'s: the timer marks a quiet effect IN_DOUBT with no call, and an expired start records nothing more', async () => {
  const { clock, engine, authorize, start, step, readBack, close } = setup();
  const begun = start(authorize({ effect_key: 'deploy:site-a' }), { deadline_sec: 1 });
  step(begun, 'upload');
  engine.effects.takeUnreturned();
  const timer = engine.effects.startSweepTimer(5);
  try {
    clock.t += 1_000;
    await new Promise((resolve) => setTimeout(resolve, 60));
  } finally {
    clearInterval(timer);
  }
  // Nobody called the engine: the timer swept it, sealed that once, and holds the record for the next result.
  const last = engine.chain[engine.chain.length - 1];
  assert.equal(last.record_type, 'EFFECT_IN_DOUBT');
  assert.equal(last.payload.cause, 'DEADLINE_PASSED');
  assert.equal(types(engine, 'EFFECT_IN_DOUBT').length, 1);
  assert.deepEqual(engine.effects.takeUnreturned().map((r) => r.record_hash), [last.record_hash]);
  // The quiet holder's lease ended with the deadline: no step and no close lands under the old attempt.
  assert.equal(step(begun, 'switch').reason_code, 'LEASE_EXPIRED');
  assert.equal(close(begun, readBack({ postcondition_met: true, downstream_changed: true })).reason_code, 'LEASE_EXPIRED');
  assert.equal(types(engine, 'EFFECT_STEP').length, 1);
});

test('rule 6. recovery is bounded: an unsettled compensation is IN_DOUBT and blocks the next, three compensations at most, five claims at most', () => {
  const { clock, engine, grant, authorize, start, step, readBack, close, claim, accept } = setup();
  const original = start(authorize({ effect_key: 'deploy:site-a' }));
  const originalId = original.effect.effect_id;
  step(original, 'upload');
  // A compensation starts only once the effect can no longer land: here, after its deadline.
  const compensateOnce = (idempotency_key) => {
    const auth = engine.authorize({
      route_grant: grant, action: 'revert.deploy', consequence_tier: 'medium', principal: 'ops-lead',
      effect_key: 'deploy:site-a', compensates_effect_id: originalId,
    });
    if (auth.decision !== 'GRANTED') return auth;
    return engine.compensateEffect({
      effect_id: originalId, authorization_record_hash: auth.record.record_hash, steps: ['restore-previous'],
      postcondition: 'site-a serves release 41', reversal: { class: 'COMPENSABLE', compensation: 'deploy 42 again' },
      deadline_sec: 60, idempotency_key,
    });
  };
  assert.equal(close(original).outcome, 'IN_DOUBT');
  assert.equal(compensateOnce('revert-0').reason_code, 'ATTEMPT_NOT_FENCED', 'switch and purge-cache may still be in flight');
  clock.t += 601_000;
  const c1 = compensateOnce('revert-1');
  assert.deepEqual([c1.status, c1.effect.attempt], ['STARTED', 1]);
  // Its executor goes quiet: it is IN_DOUBT by its own deadline, like any effect, and nothing retries it in a loop.
  clock.t += 61_000;
  assert.equal(engine.listOpenEffects().open.find((e) => e.effect_id === c1.effect.effect_id).state, 'IN_DOUBT');
  const blocked = compensateOnce('revert-2');
  assert.deepEqual([blocked.reason_code, blocked.open_effect_id], ['EFFECT_OPEN', c1.effect.effect_id], 'no second compensation while the first is unsettled');
  assert.equal(claim(original).reason_code, 'COMPENSATION_OPEN');
  assert.equal(accept(original).reason_code, 'COMPENSATION_OPEN');
  const c1Reconciler = claim(c1);
  assert.equal(close(c1Reconciler, readBack({ fence: { kind: 'EXPIRED_UNUSED' } })).outcome, 'ABORTED');
  for (const [key, attempt] of [['revert-2', 2], ['revert-3', 3]]) {
    const next = compensateOnce(key);
    assert.deepEqual([next.status, next.effect.attempt], ['STARTED', attempt]);
    assert.equal(close(next, readBack({ fence: { kind: 'CONSUMED_NOT_RELEASED', receipt_digest: digest('d') } })).outcome, 'ABORTED');
  }
  assert.equal(compensateOnce('revert-4').reason_code, 'ATTEMPT_LIMIT', 'three compensations, then a person decides');
  assert.equal(engine.listOpenEffects().open.find((e) => e.effect_id === originalId).state, 'IN_DOUBT');
  assert.equal(accept(original).status, 'ACCEPTED');

  // Reconciliation is bounded too: five claims that do not settle it, then a person decides.
  const quiet = start(authorize({ effect_key: 'deploy:site-b' }), { idempotency_key: 'deploy-b-1' });
  clock.t += 601_000;
  for (let i = 0; i < 5; i += 1) {
    const reconciler = claim(quiet);
    assert.equal(reconciler.status, 'CLAIMED', `claim ${i + 1}`);
    assert.equal(close(reconciler, readBack()).outcome, 'IN_DOUBT', 'nothing seen, no fence given');
  }
  assert.equal(claim(quiet).reason_code, 'CLAIM_LIMIT');

  // Retries of one effect are capped the same way: three attempts under one idempotency key.
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const tryIt = start(authorize({ effect_key: 'deploy:site-c' }), { idempotency_key: 'deploy-c-1' });
    assert.equal(tryIt.effect.attempt, attempt);
    close(tryIt, readBack({ fence: { kind: 'CONSUMED_NOT_RELEASED', receipt_digest: digest('d') } }));
  }
  assert.equal(start(authorize({ effect_key: 'deploy:site-c' }), { idempotency_key: 'deploy-c-1' }).reason_code, 'ATTEMPT_LIMIT');
});

test('rule 7. the evidence chain holds plain data numbered from 1: the verifier refuses code, a renumbering and a gap, and nothing else is sealed', () => {
  const { engine, authorize } = setup();
  authorize();
  const offline = new LocalImmaculateEngine();
  const check = (records) => offline.verifyChain({ records, expected_signer_kid: engine.signerKid });
  assert.equal(check(engine.chain).valid, true);
  const withCode = structuredClone(engine.chain);
  withCode[1].payload.note = () => 'run me';
  assert.deepEqual([check(withCode).valid, check(withCode).first_broken_index], [false, 1]);
  assert.match(check(withCode).reason, /not plain data/);
  const withGetter = structuredClone(engine.chain);
  Object.defineProperty(withGetter[0].payload, 'route_id', { get: () => 'ops', enumerable: true });
  assert.match(check(withGetter).reason, /getter/);
  const renumbered = structuredClone(engine.chain);
  renumbered[0].seq = 2;
  assert.match(check(renumbered).reason, /expected 1/);
  assert.equal(check(engine.chain.slice(1)).first_broken_index, 0, 'a chain starts at seq 1');
  // The engine seals plain data only.
  const before = engine.chain.length;
  assert.throws(() => authorize({ transaction: { category: 'refund', amount: 5, when: new Date(T0) } }), /Only plain data is sealed/);
  assert.equal(engine.chain.length, before);
});

test('ACCEPTED is the human-review exit: it closes the obligation, not the outcome, and not the fence', () => {
  const { clock, authorize, start, step, close, claim, accept, engine } = setup();
  const begun = start(authorize({ effect_key: 'deploy:site-a' }));
  step(begun, 'upload');
  // The executor closes with no proof, before its deadline: switch and purge-cache may still be in flight.
  assert.equal(close(begun).outcome, 'IN_DOUBT');
  assert.throws(() => accept(begun, { auth_freshness_sec: 301 }), /auth_freshness_sec/);
  assert.equal(accept(begun, { attempt: 2 }).reason_code, 'ATTEMPT_MISMATCH');
  const accepted = accept(begun, { reason: 'we will check site-a by hand' });
  assert.equal(accepted.status, 'ACCEPTED');
  assert.equal(accepted.effect.accepted_from, 'IN_DOUBT');
  assert.match(accepted.why, /outcome is still unknown/);
  assert.equal(accepted.record.payload.prior_state, 'IN_DOUBT');
  assert.equal(accepted.key_fenced_until, begun.effect.deadline_at);
  // The obligation is closed: it is no longer listed as open. The outcome is not: it never reads COMMITTED.
  assert.equal(engine.listOpenEffects().open_count, 0);
  assert.notEqual(accepted.effect.state, 'COMMITTED');
  // The fence stays until the attempt can no longer land.
  const early = authorize({ effect_key: 'deploy:site-a' });
  assert.deepEqual([early.reason_code, early.open_effect_id], ['EFFECT_OPEN', begun.effect.effect_id]);
  assert.match(early.reason, /ACCEPTED as it stood/);
  clock.t += 601_000;
  assert.equal(authorize({ effect_key: 'deploy:site-a' }).decision, 'GRANTED');
  // Nothing is accepted while it runs or while a lease is live.
  const other = start(authorize({ effect_key: 'deploy:site-b' }), { idempotency_key: 'deploy-b-1' });
  assert.equal(accept(other).reason_code, 'NOTHING_TO_ACCEPT');
  clock.t += 601_000;
  claim(other);
  assert.equal(accept(other).reason_code, 'EFFECT_LEASED');
});

test('the start is refused without what detection, ownership and reversal need, and a compensation\'s authorization starts only that compensation', () => {
  const { clock, engine, grant, authorize, start, step } = setup();
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
  assert.equal(authorize({ effect_key: 'deploy:zz', compensates_effect_id: 'ef_0000000000000000' }).reason_code, 'COMPENSATES_UNKNOWN');
  // An authorization made for a compensation starts nothing else.
  for (const name of ['upload', 'switch', 'purge-cache']) step(used, name);
  clock.t += 601_000;
  const compAuth = engine.authorize({
    route_grant: grant, action: 'revert.deploy', consequence_tier: 'medium', principal: 'ops-lead',
    effect_key: 'deploy:site-a', compensates_effect_id: used.effect.effect_id,
  });
  assert.equal(compAuth.decision, 'GRANTED');
  assert.equal(start(compAuth, { idempotency_key: 'deploy-42-other' }).reason_code, 'AUTHORIZATION_MISMATCH');
});
