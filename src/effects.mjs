/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Partly-run actions in the local engine: an authorized effect gets a checked life, sealed in the engine's hash chain.
 *
 *   AUTHORIZED -> STARTED -> (step receipts) -> COMMITTED | ABORTED | PARTIAL, or IN_DOUBT
 *                    |                                                      |
 *                    +-- deadline passes, no close -> IN_DOUBT              +--> COMPENSATED | ACCEPTED
 *
 * IN_DOUBT is the default. An effect leaves it only on evidence bound to its attempt:
 * - COMMITTED: a read-back taken after the start shows the declared postcondition, and every step has an ok receipt.
 * - PARTIAL: a read-back shows the downstream changed without reaching the postcondition (or reached it without every
 *   step's receipt).
 * - ABORTED: a read-back shows nothing changed AND a fence shows the attempt can no longer land: its deadline has
 *   passed and the read-back was taken after it (EXPIRED_UNUSED), or the downstream's receipt says it took the attempt
 *   and will never apply it (CONSUMED_NOT_RELEASED). "Nothing seen" without a fence stays IN_DOUBT: a call that timed
 *   out may still land after the read, and a retry would then apply the effect twice.
 *
 * Each start is one attempt with one lease (a token and a generation). Step receipts and closes carry the attempt
 * number and the lease token; a write from an older attempt, an expired lease or a replaced lease is refused, never
 * merged. The lease ends at the deadline by the clock: the sweep runs on every call and on a timer, with no call
 * needed from a holder that went quiet. An IN_DOUBT effect is reconciled under a new lease (arobi_claim_effect).
 * Retries and compensations are attempts of their own, numbered and capped, and start only under a grant that is
 * neither revoked nor expired. A compensation starts only once the effect it undoes can no longer land.
 *
 * ACCEPTED is the human-review exit: a person closes the obligation of an IN_DOUBT or PARTIAL effect. It never
 * changes the outcome (an accepted IN_DOUBT effect is still unknown) and never lifts the fence: the key stays fenced
 * while the accepted attempt can still land.
 *
 * Local engine only: the read-backs, fences and human approvals are what the caller reports. The engine checks that
 * they were reported, that they are bound to this attempt and agree with what the start declared, and seals them; it
 * does not observe the downstream system itself.
 */

import crypto from 'node:crypto';

export const REVERSAL_CLASSES = Object.freeze(['REVERSIBLE', 'COMPENSABLE', 'IRREVERSIBLE']);
export const OPEN_STATES = Object.freeze(['STARTED', 'IN_DOUBT', 'PARTIAL']);
export const FENCE_KINDS = Object.freeze(['EXPIRED_UNUSED', 'CONSUMED_NOT_RELEASED']);
const HEX_64 = /^[0-9a-f]{64}$/;
const EFFECT_KEY = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,199}$/;
const MAX_STEPS = 32;
const MAX_DEADLINE_SEC = 7 * 24 * 60 * 60;
/** How recent a human approval of an IRREVERSIBLE effect must be, by the engine's clock. */
const APPROVAL_MAX_AGE_MS = 15 * 60 * 1000;
/** How old a read-back may be when it closes an effect. */
export const READ_BACK_MAX_AGE_MS = 5 * 60 * 1000;
/** How long a reconciliation lease lasts. */
export const RECONCILE_LEASE_MS = 15 * 60 * 1000;
/** Attempts of one effect (retries after a fenced ABORTED) and compensations of one effect, each. */
export const MAX_ATTEMPTS = 3;
/** Reconciliation claims of one effect; after these a person decides (accept or compensate). */
export const MAX_RECONCILE_CLAIMS = 5;

const text = (value, max) => typeof value === 'string' && value.trim().length > 0 && value.length <= max;
const iso = (ms) => new Date(ms).toISOString();
const sha256 = (value) => crypto.createHash('sha256').update(value, 'utf8').digest('hex');

function sameToken(given, held) {
  if (typeof given !== 'string' || typeof held !== 'string' || given.length !== held.length) return false;
  return crypto.timingSafeEqual(Buffer.from(given, 'utf8'), Buffer.from(held, 'utf8'));
}

export class EffectLedger {
  /**
   * seal(type, payload) appends a record to the engine's chain; now() is the engine's clock in milliseconds;
   * digest(value) is the SHA-256 of a value's canonical JSON; grantStopped(info) says why the grant behind an
   * authorization can start nothing more (revoked or expired), or null.
   */
  constructor({ seal, now, digest, grantStopped }) {
    this.seal = seal;
    this.now = now;
    this.digest = digest;
    this.grantStopped = grantStopped;
    this.effects = new Map();
    // GRANTED authorizations this run sealed, by record hash: what a start may rest on.
    this.authorizations = new Map();
    // Records the sweep sealed that no tool result has carried yet; the server hands them out with the next result.
    this.unreturned = [];
  }

  /**
   * Marks every started effect whose deadline has passed IN_DOUBT, once, and seals that. Runs on every effect call
   * and on the server's timer: a holder that went quiet loses its lease by the clock, without calling anything.
   */
  sweep() {
    const nowMs = this.now();
    for (const effect of this.effects.values()) {
      if (effect.state !== 'STARTED' || Date.parse(effect.deadline_at) > nowMs) continue;
      this.unreturned.push(this.markInDoubt(effect, 'DEADLINE_PASSED'));
    }
  }

  /** The sweep's records since the last call, oldest first, so a client's copy of the chain has no gap. */
  takeUnreturned() {
    const records = this.unreturned;
    this.unreturned = [];
    return records;
  }

  /** Runs the sweep every intervalMs. The timer does not keep the process alive. */
  startSweepTimer(intervalMs) {
    const timer = setInterval(() => {
      try {
        this.sweep();
      } catch (err) {
        process.stderr.write(`immaculate-mcp: the overdue-effect sweep failed: ${err instanceof Error ? err.message : String(err)}\n`);
      }
    }, intervalMs);
    timer.unref?.();
    return timer;
  }

  /**
   * Whether this attempt could still land downstream: before its deadline, while a step has no ok receipt. An
   * ABORTED attempt was fenced and never can.
   */
  mayStillLand(effect) {
    if (effect.state === 'ABORTED' || this.now() >= Date.parse(effect.deadline_at)) return false;
    const ok = new Set(effect.receipts.filter((r) => r.status === 'ok').map((r) => r.step));
    return effect.steps.some((s) => !ok.has(s));
  }

  /**
   * The effect that fences a key against another start: one still open, or one ACCEPTED as it stood whose attempt can
   * still land (accepting closes the obligation, not the fence). The compensated effect itself does not count.
   */
  blockingOn(effectKey, exceptId) {
    return [...this.effects.values()].find((e) => e.effect_key === effectKey && e.effect_id !== exceptId
      && (OPEN_STATES.includes(e.state) || (e.state === 'ACCEPTED' && this.mayStillLand(e)))) ?? null;
  }

  blockingReason(effect, effectKey) {
    return effect.state === 'ACCEPTED'
      ? `Effect ${effect.effect_id} on ${effectKey} was ACCEPTED as it stood, but its attempt can still land until ${effect.deadline_at}; another effect on this key waits until then.`
      : `Effect ${effect.effect_id} on ${effectKey} is ${effect.state}; it must be closed, compensated or accepted before another effect on this key starts.`;
  }

  openCompensationOf(effectId) {
    return [...this.effects.values()].find((e) => e.compensates === effectId && OPEN_STATES.includes(e.state)) ?? null;
  }

  liveLease(effect) {
    return effect.lease && this.now() < effect.lease.until_ms ? effect.lease : null;
  }

  markInDoubt(effect, cause, extra = {}) {
    effect.state = 'IN_DOUBT';
    effect.in_doubt_at = iso(this.now());
    effect.in_doubt_cause = cause;
    return this.seal('EFFECT_IN_DOUBT', {
      effect_id: effect.effect_id,
      effect_key: effect.effect_key,
      attempt: effect.attempt,
      cause,
      deadline_at: effect.deadline_at,
      cleanup_owner: effect.cleanup_owner,
      receipts: effect.receipts.map((r) => ({ step: r.step, status: r.status })),
      ...extra,
    });
  }

  /**
   * The checks an authorization that declares an effect must pass, beyond the grant's own: no other open effect on
   * its key, a compensation that names an effect on that key, and a fresh named human approval for an IRREVERSIBLE
   * one. Null when they pass.
   */
  authorizationGate({ effect_key, reversal_class, human_approval, compensates_effect_id }) {
    this.sweep();
    if (effect_key !== undefined) {
      if (!text(effect_key, 200) || !EFFECT_KEY.test(effect_key)) {
        return { reason_code: 'EFFECT_KEY_INVALID', reason: 'effect_key must be 1-200 characters: letters, digits and . _ : / @ -.' };
      }
      // The one authorization an open effect admits on its key is the one for its own compensation, and only while
      // no other effect on the key (an earlier compensation, say) is open.
      const blocking = this.blockingOn(effect_key, compensates_effect_id);
      if (blocking) {
        return { reason_code: 'EFFECT_OPEN', reason: this.blockingReason(blocking, effect_key), open_effect_id: blocking.effect_id };
      }
    }
    if (compensates_effect_id !== undefined) {
      const target = typeof compensates_effect_id === 'string' ? this.effects.get(compensates_effect_id) : undefined;
      if (!target || (effect_key !== undefined && target.effect_key !== effect_key)) {
        return { reason_code: 'COMPENSATES_UNKNOWN', reason: 'compensates_effect_id must name an effect this server started in this run, on the same effect_key.' };
      }
    }
    if (reversal_class !== undefined && !REVERSAL_CLASSES.includes(reversal_class)) {
      return { reason_code: 'REVERSAL_CLASS_INVALID', reason: `reversal_class must be one of ${REVERSAL_CLASSES.join(', ')}.` };
    }
    if (reversal_class === 'IRREVERSIBLE') {
      const approval = human_approval;
      const approvedMs = approval && typeof approval.approved_at === 'string' ? Date.parse(approval.approved_at) : Number.NaN;
      const fresh = Number.isFinite(approvedMs) && approvedMs <= this.now() && this.now() - approvedMs <= APPROVAL_MAX_AGE_MS;
      if (!approval || !text(approval.approver, 200) || !text(approval.auth_method, 100) || !fresh) {
        return {
          reason_code: 'IRREVERSIBLE_NEEDS_HUMAN_APPROVAL',
          reason: 'An IRREVERSIBLE effect needs human_approval { approver, auth_method, approved_at within the last 15 minutes } at authorization; it cannot be undone, so a person decides before it starts.',
        };
      }
    }
    return null;
  }

  rememberAuthorization(recordHash, info) {
    this.authorizations.set(recordHash, { ...info, used_by: null });
  }

  /**
   * Checks that a write names this effect's attempt and the lease it holds now. A write from an older attempt, under
   * a lease that was replaced or has expired, or under the wrong kind of lease, is refused. Null when it is bound.
   */
  checkLease(effect, attempt, leaseToken, purpose) {
    if (!Number.isInteger(attempt)) throw new Error("attempt (the effect's attempt number, from its start) is required.");
    if (typeof leaseToken !== 'string' || leaseToken.length === 0) throw new Error('lease_token (from the start or the claim) is required.');
    if (attempt !== effect.attempt) {
      return this.refuse('ATTEMPT_MISMATCH', `Effect ${effect.effect_id} is attempt ${effect.attempt}; a write for attempt ${attempt} is refused, never merged.`);
    }
    const lease = effect.lease;
    if (!lease || !sameToken(leaseToken, lease.token)) {
      return this.refuse('LEASE_STALE', `That lease token is not the one effect ${effect.effect_id} holds now${lease ? '' : ' (it holds none; claim it to reconcile)'}; a stale holder's writes are refused.`);
    }
    if (this.now() >= lease.until_ms) {
      return this.refuse('LEASE_EXPIRED', `The lease of effect ${effect.effect_id} ended at ${lease.until}; nothing more is written under it. An IN_DOUBT effect is reconciled under a new lease from arobi_claim_effect.`);
    }
    if (purpose && lease.purpose !== purpose) {
      return this.refuse('LEASE_PURPOSE', 'A reconciliation lease reads the outcome back; it records no steps.');
    }
    return null;
  }

  begin(args, { compensates } = {}) {
    if (!args || typeof args !== 'object') throw new Error('Arguments object is required.');
    this.sweep();
    const {
      authorization_record_hash, effect_key, steps, postcondition, reversal, deadline_sec, cleanup_owner, idempotency_key,
    } = args;
    if (!HEX_64.test(String(authorization_record_hash ?? ''))) {
      throw new Error('authorization_record_hash must be the record_hash of a GRANTED AUTHORIZATION this server sealed.');
    }
    if (!text(idempotency_key, 200) || idempotency_key.length < 8) throw new Error('idempotency_key (8-200 characters) is required.');
    const auth = this.authorizations.get(authorization_record_hash);
    const original = compensates ? this.effects.get(compensates) : undefined;
    const key = original ? original.effect_key : (effect_key ?? auth?.effect_key);

    // A retry with the same idempotency key on the same key replays the start: it is never applied twice. Only when
    // the latest attempt was ABORTED (fenced: it can never land) does the same key start a new attempt.
    const lineage = [...this.effects.values()].filter((e) => e.effect_key === key && e.idempotency_key === idempotency_key
      && (e.compensates ?? null) === (compensates ?? null));
    const latest = lineage[lineage.length - 1];
    if (latest && latest.state !== 'ABORTED') {
      // The replay carries no lease: whoever holds the start's lease keeps it, one holder at a time.
      return { status: 'REPLAYED', effect: this.view(latest), mode: 'local' };
    }

    if (!auth) {
      return this.refuse('AUTHORIZATION_UNKNOWN', 'authorization_record_hash names no GRANTED AUTHORIZATION this server sealed in this run.');
    }
    if (auth.used_by) {
      return this.refuse('AUTHORIZATION_ALREADY_USED', `That authorization already started effect ${auth.used_by}; authorize again for a new effect.`);
    }
    if ((auth.compensates_effect_id ?? null) !== (compensates ?? null)) {
      return this.refuse('AUTHORIZATION_MISMATCH', compensates
        ? `A compensation starts from an authorization made for it: authorize with compensates_effect_id ${compensates}.`
        : `That authorization is for the compensation of ${auth.compensates_effect_id}; start it with arobi_compensate.`);
    }
    // No new work under a grant that was revoked or has expired (a revocation is this engine's stop).
    const stopped = this.grantStopped(auth);
    if (stopped) return this.refuse(stopped.reason_code, stopped.reason);
    if (!text(key, 200) || !EFFECT_KEY.test(key)) throw new Error('effect_key (on the start or its authorization) is required.');
    if (auth.effect_key !== undefined && auth.effect_key !== key) {
      return this.refuse('EFFECT_KEY_MISMATCH', `The authorization is for ${auth.effect_key}, not ${key}.`);
    }
    if (!Array.isArray(steps) || steps.length === 0 || steps.length > MAX_STEPS || !steps.every((s) => text(s, 100))
      || new Set(steps).size !== steps.length) {
      throw new Error(`steps must be 1-${MAX_STEPS} distinct step names.`);
    }
    if (!text(postcondition, 500)) throw new Error('postcondition (what the read-back must show, up to 500 characters) is required.');
    if (!reversal || typeof reversal !== 'object' || !REVERSAL_CLASSES.includes(reversal.class)) {
      throw new Error(`reversal.class must be one of ${REVERSAL_CLASSES.join(', ')}.`);
    }
    if (reversal.class === 'REVERSIBLE' && !text(reversal.inverse, 500)) throw new Error('A REVERSIBLE effect names its inverse operation in reversal.inverse.');
    if (reversal.class === 'COMPENSABLE' && !text(reversal.compensation, 500)) throw new Error('A COMPENSABLE effect names its compensating action in reversal.compensation.');
    if (auth.reversal_class !== undefined && auth.reversal_class !== reversal.class) {
      return this.refuse('REVERSAL_CLASS_MISMATCH', `The authorization declared ${auth.reversal_class}, not ${reversal.class}.`);
    }
    if (reversal.class === 'IRREVERSIBLE' && auth.reversal_class !== 'IRREVERSIBLE') {
      return this.refuse('IRREVERSIBLE_NEEDS_HUMAN_APPROVAL', 'An IRREVERSIBLE effect starts only from an authorization that declared reversal_class IRREVERSIBLE with a human approval.');
    }
    if (!(Number.isInteger(deadline_sec) && deadline_sec >= 1 && deadline_sec <= MAX_DEADLINE_SEC)) {
      throw new Error(`deadline_sec must be a whole number of seconds from 1 to ${MAX_DEADLINE_SEC}.`);
    }
    // Attempts are numbered by the engine: a retry counts the attempts of its lineage, a compensation counts every
    // compensation of the effect it undoes. Both are capped, so recovery is bounded rather than a loop.
    const attempt = compensates
      ? [...this.effects.values()].filter((e) => e.compensates === compensates).length + 1
      : lineage.length + 1;
    if (attempt > MAX_ATTEMPTS) {
      return this.refuse('ATTEMPT_LIMIT', compensates
        ? `Effect ${compensates} has had ${MAX_ATTEMPTS} compensation attempts; a person decides now (arobi_accept_effect).`
        : `This effect has had ${MAX_ATTEMPTS} attempts under this idempotency key; a person decides whether to try again under a new one.`);
    }
    const blocking = this.blockingOn(key, compensates);
    if (blocking) {
      return { ...this.refuse('EFFECT_OPEN', this.blockingReason(blocking, key)), open_effect_id: blocking.effect_id };
    }
    const owner = cleanup_owner === undefined ? auth.granted_by : cleanup_owner;
    if (!text(owner, 200)) throw new Error('cleanup_owner must name who cleans up if the effect is left part-done.');

    const nowMs = this.now();
    const effect_id = `ef_${crypto.randomBytes(8).toString('hex')}`;
    const plan = {
      effect_id,
      effect_key: key,
      attempt,
      steps: [...steps],
      postcondition,
      reversal: { class: reversal.class, ...(reversal.inverse ? { inverse: reversal.inverse } : {}), ...(reversal.compensation ? { compensation: reversal.compensation } : {}) },
      deadline_at: iso(nowMs + deadline_sec * 1000),
      cleanup_owner: owner,
      ...(compensates ? { compensates } : {}),
    };
    // The plan is fixed, and its digest sealed, before anything runs; every close names it.
    const plan_digest = this.digest(plan);
    const lease = { token: crypto.randomBytes(16).toString('hex'), generation: 1, purpose: 'EXECUTE', holder: 'executor', until: plan.deadline_at, until_ms: nowMs + deadline_sec * 1000 };
    const record = this.seal('EFFECT_STARTED', {
      ...plan,
      plan_digest,
      authorization_record_hash,
      started_at: iso(nowMs),
      idempotency_key_sha256: sha256(idempotency_key),
      lease_generation: lease.generation,
    });
    const effect = {
      ...plan,
      state: 'STARTED',
      plan_digest,
      authorization_record_hash,
      started_at: iso(nowMs),
      idempotency_key,
      receipts: [],
      lease,
      last_generation: lease.generation,
      claims: 0,
      started_record_hash: record.record_hash,
    };
    auth.used_by = effect_id;
    this.effects.set(effect_id, effect);
    return { status: 'STARTED', effect: this.view(effect), lease: this.leaseView(lease, true), mode: 'local', record };
  }

  recordStep(args) {
    if (!args || typeof args !== 'object') throw new Error('Arguments object is required.');
    this.sweep();
    const { effect_id, attempt, lease_token, step, status, evidence_digest, detail } = args;
    const effect = this.effects.get(effect_id);
    if (!effect) throw new Error('effect_id must name an effect this server started in this run.');
    const unbound = this.checkLease(effect, attempt, lease_token, 'EXECUTE');
    if (unbound) return unbound;
    if (effect.state !== 'STARTED') {
      return this.refuse('EFFECT_NOT_RUNNING', `Effect ${effect_id} is ${effect.state}; it takes no more step receipts.`);
    }
    if (!effect.steps.includes(step)) throw new Error(`step must be one of the declared steps: ${effect.steps.join(', ')}.`);
    if (!['ok', 'failed'].includes(status)) throw new Error("status must be 'ok' or 'failed'.");
    if (evidence_digest !== undefined && !HEX_64.test(String(evidence_digest))) throw new Error('evidence_digest must be a sha256 hex digest.');
    if (detail !== undefined && !text(detail, 300)) throw new Error('detail must be up to 300 characters.');
    if (effect.receipts.some((r) => r.step === step && r.status === 'ok')) {
      return this.refuse('STEP_ALREADY_RECORDED', `Step ${step} of ${effect_id} already has an ok receipt; it is not recorded twice.`);
    }
    const record = this.seal('EFFECT_STEP', {
      effect_id, effect_key: effect.effect_key, attempt: effect.attempt, lease_generation: effect.lease.generation, step, status,
      ...(evidence_digest ? { evidence_digest } : {}),
      ...(detail ? { detail } : {}),
    });
    effect.receipts.push({ step, status, record_hash: record.record_hash });
    return { status: 'RECORDED', effect: this.view(effect), mode: 'local', record };
  }

  /**
   * Settles an attempt on its read-back. Without a read-back, or on a read-back that shows nothing changed but no
   * fence, the effect is IN_DOUBT: open, still owned, its key still fenced.
   */
  close(args) {
    if (!args || typeof args !== 'object') throw new Error('Arguments object is required.');
    this.sweep();
    const { effect_id, attempt, lease_token, read_back } = args;
    const effect = this.effects.get(effect_id);
    if (!effect) throw new Error('effect_id must name an effect this server started in this run.');
    if (!['STARTED', 'IN_DOUBT'].includes(effect.state)) {
      return this.refuse('EFFECT_CLOSED', `Effect ${effect_id} is already ${effect.state}.`);
    }
    const unbound = this.checkLease(effect, attempt, lease_token, null);
    if (unbound) return unbound;
    const leaseGeneration = effect.lease.generation;
    const nowMs = this.now();

    if (read_back === undefined) {
      if (effect.state === 'IN_DOUBT') {
        return this.refuse('READ_BACK_REQUIRED', `Effect ${effect_id} is already IN_DOUBT; only a read-back changes that.`);
      }
      effect.lease = null;
      const record = this.markInDoubt(effect, 'CLOSED_WITHOUT_READ_BACK', { lease_generation: leaseGeneration });
      return {
        status: 'IN_DOUBT', outcome: 'IN_DOUBT',
        why: 'closed without a read-back of the downstream state, so what landed is unknown: it stays IN_DOUBT, open and owned, until a read-back settles it',
        effect: this.view(effect), mode: 'local', record,
      };
    }

    if (!read_back || typeof read_back !== 'object' || typeof read_back.postcondition_met !== 'boolean' || typeof read_back.downstream_changed !== 'boolean') {
      throw new Error('read_back must say { postcondition_met: boolean, downstream_changed: boolean } about the downstream state you read back.');
    }
    const { postcondition_met, downstream_changed, observed_at, evidence_digest, detail, fence } = read_back;
    if (!HEX_64.test(String(evidence_digest ?? ''))) throw new Error('read_back.evidence_digest (the sha256 hex of what was read back) is required: a read-back without evidence proves nothing.');
    if (typeof observed_at !== 'string' || Number.isNaN(Date.parse(observed_at))) throw new Error('read_back.observed_at (when it was read back, ISO 8601) is required.');
    if (detail !== undefined && !text(detail, 300)) throw new Error('read_back.detail must be up to 300 characters.');
    const observedMs = Date.parse(observed_at);
    const startedMs = Date.parse(effect.started_at);
    if (observedMs < startedMs || observedMs > nowMs || nowMs - observedMs > READ_BACK_MAX_AGE_MS) {
      return this.refuse('READ_BACK_BINDING_INVALID', `A read-back closes this attempt only if it was taken after its start (${effect.started_at}), not in the future and within the last ${READ_BACK_MAX_AGE_MS / 60000} minutes; this one was taken at ${observed_at}.`);
    }
    const nothingChanged = !postcondition_met && !downstream_changed;
    if (fence !== undefined) {
      if (!fence || typeof fence !== 'object' || !FENCE_KINDS.includes(fence.kind)) throw new Error(`read_back.fence.kind must be one of ${FENCE_KINDS.join(', ')}.`);
      if (!nothingChanged) throw new Error('A fence shows an attempt can no longer land; it goes only with a read-back that shows nothing changed.');
      if (fence.kind === 'CONSUMED_NOT_RELEASED' && !HEX_64.test(String(fence.receipt_digest ?? ''))) {
        throw new Error("A CONSUMED_NOT_RELEASED fence carries receipt_digest: the sha256 hex of the downstream's receipt that it took this attempt and will never apply it.");
      }
      if (fence.kind === 'EXPIRED_UNUSED') {
        const deadlineMs = Date.parse(effect.deadline_at);
        if (nowMs < deadlineMs) {
          return this.refuse('FENCE_NOT_IN_FORCE', `This attempt can be used until its deadline ${effect.deadline_at}; until then a late call may still land, so nothing seen is IN_DOUBT, not ABORTED.`);
        }
        if (observedMs < deadlineMs) {
          return this.refuse('FENCE_NOT_IN_FORCE', `The read-back was taken at ${observed_at}, before the deadline ${effect.deadline_at}; read back again after it.`);
        }
      }
    }
    const sealedReadBack = {
      observed_at, evidence_digest, postcondition_met, downstream_changed,
      ...(fence ? { fence: { kind: fence.kind, ...(fence.receipt_digest ? { receipt_digest: fence.receipt_digest } : {}) } } : {}),
      ...(detail ? { detail } : {}),
    };

    if (nothingChanged && !fence) {
      effect.lease = null;
      const record = this.markInDoubt(effect, 'NOTHING_SEEN_UNFENCED', { lease_generation: leaseGeneration, plan_digest: effect.plan_digest, read_back: sealedReadBack });
      return {
        status: 'IN_DOUBT', outcome: 'IN_DOUBT',
        why: `the read-back shows nothing changed, but nothing shows this attempt can no longer land: it stays IN_DOUBT until it is fenced (after the deadline ${effect.deadline_at}, read back again with fence EXPIRED_UNUSED, or give the downstream's CONSUMED_NOT_RELEASED receipt)`,
        effect: this.view(effect), mode: 'local', record,
      };
    }

    const okSteps = new Set(effect.receipts.filter((r) => r.status === 'ok').map((r) => r.step));
    const missing = effect.steps.filter((s) => !okSteps.has(s));
    let outcome;
    let why;
    if (nothingChanged) {
      outcome = 'ABORTED';
      why = fence.kind === 'EXPIRED_UNUSED'
        ? 'the read-back, taken after the deadline, shows nothing changed, and the attempt can no longer be used'
        : "the read-back shows nothing changed, and the downstream's receipt says it took this attempt and will never apply it";
    } else if (postcondition_met && missing.length === 0) {
      outcome = 'COMMITTED';
      why = 'the read-back shows the postcondition and every step has an ok receipt';
    } else {
      outcome = 'PARTIAL';
      why = postcondition_met
        ? `the read-back shows the postcondition but steps ${missing.join(', ')} have no ok receipt`
        : 'the read-back shows the downstream changed without reaching the postcondition';
    }
    const record = this.seal('EFFECT_CLOSED', {
      effect_id, effect_key: effect.effect_key, attempt: effect.attempt, plan_digest: effect.plan_digest, lease_generation: leaseGeneration,
      outcome,
      read_back: sealedReadBack,
      steps_ok: effect.steps.filter((s) => okSteps.has(s)),
      steps_missing: missing,
      ...(effect.compensates ? { compensates: effect.compensates } : {}),
    });
    effect.state = outcome;
    effect.lease = null;
    effect.closed_at = iso(nowMs);
    const result = { status: 'CLOSED', outcome, why, effect: this.view(effect), mode: 'local', record };
    // A committed compensation, whose read-back showed the earlier state, settles the effect it undoes.
    if (effect.compensates && outcome === 'COMMITTED') {
      const target = this.effects.get(effect.compensates);
      if (target && ['IN_DOUBT', 'PARTIAL', 'COMMITTED'].includes(target.state)) {
        const prior = target.state;
        target.state = 'COMPENSATED';
        target.lease = null;
        target.compensated_by = effect.effect_id;
        result.compensated_record = this.seal('EFFECT_COMPENSATED', {
          effect_id: target.effect_id, effect_key: target.effect_key, attempt: target.attempt, prior_state: prior,
          compensation_effect_id: effect.effect_id, compensation_attempt: effect.attempt,
        });
        result.compensated = this.view(target);
      }
    }
    return result;
  }

  /**
   * Takes over an IN_DOUBT effect to reconcile its outcome: a new lease (the next generation) for a read-back and a
   * close. The earlier lease's writes are refused from then on. Capped, after which a person decides.
   */
  claim(args) {
    if (!args || typeof args !== 'object') throw new Error('Arguments object is required.');
    this.sweep();
    const { effect_id, attempt, claimant } = args;
    const effect = this.effects.get(effect_id);
    if (!effect) throw new Error('effect_id must name an effect this server started in this run.');
    if (!Number.isInteger(attempt)) throw new Error("attempt (the effect's attempt number) is required.");
    if (attempt !== effect.attempt) {
      return this.refuse('ATTEMPT_MISMATCH', `Effect ${effect_id} is attempt ${effect.attempt}, not ${attempt}.`);
    }
    if (effect.state !== 'IN_DOUBT') {
      return this.refuse('NOTHING_TO_RECONCILE', `Effect ${effect_id} is ${effect.state}; only an IN_DOUBT effect is claimed to reconcile it.`);
    }
    const live = this.liveLease(effect);
    if (live) return this.refuse('EFFECT_LEASED', `Effect ${effect_id} is held (${live.purpose}) until ${live.until}; one holder at a time.`);
    const compensation = this.openCompensationOf(effect_id);
    if (compensation) {
      return this.refuse('COMPENSATION_OPEN', `Compensation ${compensation.effect_id} of ${effect_id} is ${compensation.state}; settle it first.`);
    }
    if (effect.claims >= MAX_RECONCILE_CLAIMS) {
      return this.refuse('CLAIM_LIMIT', `Effect ${effect_id} has been claimed ${MAX_RECONCILE_CLAIMS} times without settling; a person decides now (arobi_accept_effect or arobi_compensate).`);
    }
    const who = claimant === undefined ? effect.cleanup_owner : claimant;
    if (!text(who, 200)) throw new Error('claimant must name who reconciles the effect (default: its cleanup owner).');
    const nowMs = this.now();
    const generation = effect.last_generation + 1;
    const lease = { token: crypto.randomBytes(16).toString('hex'), generation, purpose: 'RECONCILE', holder: who, until: iso(nowMs + RECONCILE_LEASE_MS), until_ms: nowMs + RECONCILE_LEASE_MS };
    effect.lease = lease;
    effect.last_generation = generation;
    effect.claims += 1;
    const record = this.seal('EFFECT_CLAIMED', {
      effect_id, effect_key: effect.effect_key, attempt: effect.attempt, claimant: who, lease_generation: generation, lease_until: lease.until,
    });
    return { status: 'CLAIMED', effect: this.view(effect), lease: this.leaseView(lease, true), mode: 'local', record };
  }

  /** Starts the compensation of an effect: an authorized effect of its own, on the same key, linked to it. */
  compensate(args) {
    if (!args || typeof args !== 'object') throw new Error('Arguments object is required.');
    this.sweep();
    const original = this.effects.get(args.effect_id);
    if (!original) throw new Error('effect_id must name an effect this server started in this run.');
    if (original.reversal.class === 'IRREVERSIBLE') {
      return this.refuse('EFFECT_IRREVERSIBLE', `Effect ${original.effect_id} was declared IRREVERSIBLE; it can be ACCEPTED by a person, not compensated.`);
    }
    if (!['IN_DOUBT', 'PARTIAL', 'COMMITTED'].includes(original.state)) {
      return this.refuse('NOTHING_TO_COMPENSATE', `Effect ${original.effect_id} is ${original.state}; only an IN_DOUBT, PARTIAL or COMMITTED effect is compensated.`);
    }
    const live = this.liveLease(original);
    if (live) return this.refuse('EFFECT_LEASED', `Effect ${original.effect_id} is held (${live.purpose}) until ${live.until}; one holder at a time.`);
    if (this.mayStillLand(original)) {
      return this.refuse('ATTEMPT_NOT_FENCED', `Effect ${original.effect_id} can still land until its deadline ${original.deadline_at} (a step without an ok receipt may be in flight); a compensation started now could be overtaken by a late landing.`);
    }
    const { effect_id: _original, ...start } = args;
    return this.begin({ ...start, effect_key: original.effect_key }, { compensates: original.effect_id });
  }

  /** A person accepts an effect as it stands (IN_DOUBT or PARTIAL): sealed, with who and how they authenticated. */
  accept(args) {
    if (!args || typeof args !== 'object') throw new Error('Arguments object is required.');
    this.sweep();
    const { effect_id, attempt, accepted_by, auth_method, auth_freshness_sec, reason } = args;
    const effect = this.effects.get(effect_id);
    if (!effect) throw new Error('effect_id must name an effect this server started in this run.');
    if (!Number.isInteger(attempt)) throw new Error("attempt (the effect's attempt number) is required.");
    if (attempt !== effect.attempt) {
      return this.refuse('ATTEMPT_MISMATCH', `Effect ${effect_id} is attempt ${effect.attempt}, not ${attempt}.`);
    }
    if (!['IN_DOUBT', 'PARTIAL'].includes(effect.state)) {
      return this.refuse('NOTHING_TO_ACCEPT', `Effect ${effect_id} is ${effect.state}; only an IN_DOUBT or PARTIAL effect is accepted.`);
    }
    const live = this.liveLease(effect);
    if (live) return this.refuse('EFFECT_LEASED', `Effect ${effect_id} is held (${live.purpose}) until ${live.until}; one holder at a time.`);
    const compensation = this.openCompensationOf(effect_id);
    if (compensation) {
      return this.refuse('COMPENSATION_OPEN', `Compensation ${compensation.effect_id} of ${effect_id} is ${compensation.state}; settle or accept it first.`);
    }
    if (!text(accepted_by, 200) || !text(auth_method, 100) || !(typeof auth_freshness_sec === 'number' && auth_freshness_sec >= 0 && auth_freshness_sec <= 300)) {
      throw new Error('accepted_by, auth_method and auth_freshness_sec (at most 300) name the person who accepts it.');
    }
    if (!text(reason, 500)) throw new Error('reason (up to 500 characters) is required.');
    const prior = effect.state;
    const record = this.seal('EFFECT_ACCEPTED', {
      effect_id, effect_key: effect.effect_key, attempt: effect.attempt, prior_state: prior, accepted_by, auth_method, auth_freshness_sec, reason,
    });
    effect.state = 'ACCEPTED';
    effect.accepted_from = prior;
    effect.lease = null;
    effect.closed_at = iso(this.now());
    // Accepting closes the obligation, never the outcome, and never the fence.
    const landable = this.mayStillLand(effect);
    return {
      status: 'ACCEPTED',
      why: `accepted as it stood: the obligation is closed; the outcome ${prior === 'IN_DOUBT' ? 'is still unknown' : 'stays PARTIAL, with its receipts'}${landable ? `, and the key stays fenced until ${effect.deadline_at}, while the attempt can still land` : ''}`,
      effect: this.view(effect),
      ...(landable ? { key_fenced_until: effect.deadline_at } : {}),
      mode: 'local',
      record,
    };
  }

  listOpen() {
    this.sweep();
    const nowMs = this.now();
    const open = [...this.effects.values()].filter((e) => OPEN_STATES.includes(e.state)).map((e) => ({
      ...this.view(e),
      age_sec: Math.floor((nowMs - Date.parse(e.started_at)) / 1000),
    }));
    return { open_count: open.length, open, mode: 'local' };
  }

  /** A lease as its holder sees it: with the token only in the result that grants it, never in a record or a view. */
  leaseView(lease, withToken) {
    return {
      ...(withToken ? { token: lease.token } : {}),
      generation: lease.generation,
      purpose: lease.purpose,
      holder: lease.holder,
      until: lease.until,
      live: this.now() < lease.until_ms,
    };
  }

  view(effect) {
    return {
      effect_id: effect.effect_id,
      state: effect.state,
      effect_key: effect.effect_key,
      attempt: effect.attempt,
      plan_digest: effect.plan_digest,
      authorization_record_hash: effect.authorization_record_hash,
      steps: [...effect.steps],
      postcondition: effect.postcondition,
      reversal: { ...effect.reversal },
      started_at: effect.started_at,
      deadline_at: effect.deadline_at,
      cleanup_owner: effect.cleanup_owner,
      receipts: effect.receipts.map((r) => ({ ...r })),
      lease: effect.lease ? this.leaseView(effect.lease, false) : null,
      reconcile_claims: effect.claims,
      ...(effect.compensates ? { compensates: effect.compensates } : {}),
      ...(effect.compensated_by ? { compensated_by: effect.compensated_by } : {}),
      ...(effect.accepted_from ? { accepted_from: effect.accepted_from } : {}),
      ...(effect.in_doubt_at ? { in_doubt_at: effect.in_doubt_at, in_doubt_cause: effect.in_doubt_cause } : {}),
      ...(effect.closed_at ? { closed_at: effect.closed_at } : {}),
      started_record_hash: effect.started_record_hash,
    };
  }

  refuse(code, reason) {
    return { status: 'DENIED', reason_code: code, reason, mode: 'local' };
  }
}
