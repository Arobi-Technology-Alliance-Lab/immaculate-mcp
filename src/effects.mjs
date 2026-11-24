/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Partly-run actions in the local engine: an authorized effect gets a checked life, sealed in the engine's hash chain.
 *
 *   AUTHORIZED -> STARTED -> (step receipts) -> CLOSED: COMMITTED | ABORTED | PARTIAL
 *                    |                                        |
 *                    +-- deadline passes, no close -> IN_DOUBT +--> COMPENSATED | ACCEPTED
 *
 * - Detect. A start names its deadline; an effect still open after it is marked IN_DOUBT by the clock, on the next
 *   call to the engine, with no call from the executor. Each step leaves its own receipt. A close is checked, not
 *   asserted: COMMITTED needs a read-back that shows the declared postcondition and an ok receipt for every step; a
 *   run that "succeeded" and changed nothing closes ABORTED.
 * - Own. A start names its cleanup owner (by default the grant's issuer). Open obligations are listed with their
 *   owner, age and receipts. While an effect on a key is open, a new authorization or start on that key is denied
 *   and names it; a retry with the same idempotency key replays the start instead of applying it again.
 * - Reverse. A start declares REVERSIBLE, COMPENSABLE or IRREVERSIBLE. IRREVERSIBLE needs a named human's approval
 *   at authorization. A compensation is itself an authorized effect linked to the one it undoes, and COMPENSATED needs
 *   its read-back to show the earlier state; a person may instead close an effect as ACCEPTED.
 *
 * Local engine only: the read-backs and the human approval are what the caller reports. The engine checks that they
 * were reported, that they agree with what the start declared, and seals them; it does not observe the downstream
 * system itself.
 */

import crypto from 'node:crypto';

export const REVERSAL_CLASSES = Object.freeze(['REVERSIBLE', 'COMPENSABLE', 'IRREVERSIBLE']);
export const OPEN_STATES = Object.freeze(['STARTED', 'IN_DOUBT', 'PARTIAL']);
const HEX_64 = /^[0-9a-f]{64}$/;
const EFFECT_KEY = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,199}$/;
const MAX_STEPS = 32;
const MAX_DEADLINE_SEC = 7 * 24 * 60 * 60;
/** How recent a human approval of an IRREVERSIBLE effect must be, by the engine's clock. */
const APPROVAL_MAX_AGE_MS = 15 * 60 * 1000;

const text = (value, max) => typeof value === 'string' && value.trim().length > 0 && value.length <= max;

export class EffectLedger {
  constructor({ seal, now }) {
    this.seal = seal;
    this.now = now;
    this.effects = new Map();
    // GRANTED authorizations this run sealed, by record hash: what a start may rest on.
    this.authorizations = new Map();
  }

  /** Marks every started effect whose deadline has passed IN_DOUBT, once, and seals that. Runs on every effect call. */
  sweep() {
    const nowMs = this.now();
    for (const effect of this.effects.values()) {
      if (effect.state !== 'STARTED' || Date.parse(effect.deadline_at) > nowMs) continue;
      effect.state = 'IN_DOUBT';
      effect.in_doubt_at = new Date(nowMs).toISOString();
      this.seal('EFFECT_IN_DOUBT', {
        effect_id: effect.effect_id,
        effect_key: effect.effect_key,
        deadline_at: effect.deadline_at,
        cleanup_owner: effect.cleanup_owner,
        receipts: effect.receipts.map((r) => ({ step: r.step, status: r.status })),
      });
    }
  }

  openEffectOn(effectKey) {
    return [...this.effects.values()].find((e) => e.effect_key === effectKey && OPEN_STATES.includes(e.state)) ?? null;
  }

  /**
   * The checks an authorization with an effect key or a reversal class must pass, beyond the grant's own: no open
   * effect on the key, and a fresh named human approval for an IRREVERSIBLE one. Null when they pass.
   */
  authorizationGate({ effect_key, reversal_class, human_approval, compensates_effect_id }) {
    this.sweep();
    if (effect_key !== undefined) {
      if (!text(effect_key, 200) || !EFFECT_KEY.test(effect_key)) {
        return { reason_code: 'EFFECT_KEY_INVALID', reason: 'effect_key must be 1-200 characters: letters, digits and . _ : / @ -.' };
      }
      const open = this.openEffectOn(effect_key);
      // The one authorization an open effect admits on its key is the one for its own compensation.
      if (open && open.effect_id !== compensates_effect_id) {
        return {
          reason_code: 'EFFECT_OPEN',
          reason: `Effect ${open.effect_id} on ${effect_key} is ${open.state}; it must be closed, compensated or accepted before another effect on this key is authorized.`,
          open_effect_id: open.effect_id,
        };
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

  begin(args, { compensates } = {}) {
    if (!args || typeof args !== 'object') throw new Error('Arguments object is required.');
    this.sweep();
    const {
      authorization_record_hash, effect_key, steps, postcondition, reversal, deadline_sec, cleanup_owner,
      idempotency_key, attempt = 1,
    } = args;
    if (!HEX_64.test(String(authorization_record_hash ?? ''))) {
      throw new Error('authorization_record_hash must be the record_hash of a GRANTED AUTHORIZATION this server sealed.');
    }
    if (!text(idempotency_key, 200) || idempotency_key.length < 8) throw new Error('idempotency_key (8-200 characters) is required.');
    const auth = this.authorizations.get(authorization_record_hash);
    const key = effect_key ?? auth?.effect_key;

    // A retry with the same idempotency key on the same key replays the start: it is never applied twice.
    const replay = [...this.effects.values()].find((e) => e.effect_key === key && e.idempotency_key === idempotency_key);
    if (replay) {
      return { status: 'REPLAYED', effect: this.view(replay), mode: 'local' };
    }

    if (!auth) {
      return this.refuse('AUTHORIZATION_UNKNOWN', 'authorization_record_hash names no GRANTED AUTHORIZATION this server sealed in this run.');
    }
    if (auth.used_by) {
      return this.refuse('AUTHORIZATION_ALREADY_USED', `That authorization already started effect ${auth.used_by}; authorize again for a new effect.`);
    }
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
    if (!(Number.isInteger(attempt) && attempt >= 1 && attempt <= 1000)) throw new Error('attempt must be a whole number from 1.');
    const open = this.openEffectOn(key);
    if (open && open.effect_id !== compensates) {
      return { ...this.refuse('EFFECT_OPEN', `Effect ${open.effect_id} on ${key} is ${open.state}; close, compensate or accept it first.`), open_effect_id: open.effect_id };
    }
    const owner = cleanup_owner === undefined ? auth.granted_by : cleanup_owner;
    if (!text(owner, 200)) throw new Error('cleanup_owner must name who cleans up if the effect is left part-done.');

    const effect = {
      effect_id: `ef_${crypto.randomBytes(8).toString('hex')}`,
      state: 'STARTED',
      authorization_record_hash,
      effect_key: key,
      steps: [...steps],
      postcondition,
      reversal: { class: reversal.class, ...(reversal.inverse ? { inverse: reversal.inverse } : {}), ...(reversal.compensation ? { compensation: reversal.compensation } : {}) },
      started_at: new Date(this.now()).toISOString(),
      deadline_at: new Date(this.now() + deadline_sec * 1000).toISOString(),
      cleanup_owner: owner,
      idempotency_key,
      attempt,
      receipts: [],
      ...(compensates ? { compensates } : {}),
    };
    const { state, receipts, ...sealedStart } = effect;
    const record = this.seal('EFFECT_STARTED', sealedStart);
    effect.started_record_hash = record.record_hash;
    auth.used_by = effect.effect_id;
    this.effects.set(effect.effect_id, effect);
    return { status: 'STARTED', effect: this.view(effect), mode: 'local', record };
  }

  recordStep(args) {
    if (!args || typeof args !== 'object') throw new Error('Arguments object is required.');
    this.sweep();
    const { effect_id, step, status, evidence_digest, detail } = args;
    const effect = this.effects.get(effect_id);
    if (!effect) throw new Error('effect_id must name an effect this server started in this run.');
    if (!['STARTED', 'IN_DOUBT'].includes(effect.state)) {
      return this.refuse('EFFECT_CLOSED', `Effect ${effect_id} is ${effect.state}; a closed effect takes no more receipts.`);
    }
    if (!effect.steps.includes(step)) throw new Error(`step must be one of the declared steps: ${effect.steps.join(', ')}.`);
    if (!['ok', 'failed'].includes(status)) throw new Error("status must be 'ok' or 'failed'.");
    if (evidence_digest !== undefined && !HEX_64.test(String(evidence_digest))) throw new Error('evidence_digest must be a sha256 hex digest.');
    if (detail !== undefined && !text(detail, 300)) throw new Error('detail must be up to 300 characters.');
    if (effect.receipts.some((r) => r.step === step && r.status === 'ok')) {
      return this.refuse('STEP_ALREADY_RECORDED', `Step ${step} of ${effect_id} already has an ok receipt; it is not recorded twice.`);
    }
    const receipt = {
      effect_id, step, status,
      ...(evidence_digest ? { evidence_digest } : {}),
      ...(detail ? { detail } : {}),
      // A receipt after the deadline still says what landed; it is marked so.
      ...(effect.state === 'IN_DOUBT' ? { late: true } : {}),
    };
    const record = this.seal('EFFECT_STEP', receipt);
    effect.receipts.push({ step, status, record_hash: record.record_hash, ...(receipt.late ? { late: true } : {}) });
    return { status: 'RECORDED', effect: this.view(effect), mode: 'local', record };
  }

  close(args) {
    if (!args || typeof args !== 'object') throw new Error('Arguments object is required.');
    this.sweep();
    const { effect_id, read_back } = args;
    const effect = this.effects.get(effect_id);
    if (!effect) throw new Error('effect_id must name an effect this server started in this run.');
    if (!['STARTED', 'IN_DOUBT'].includes(effect.state)) {
      return this.refuse('EFFECT_CLOSED', `Effect ${effect_id} is already ${effect.state}.`);
    }
    if (read_back !== undefined) {
      if (!read_back || typeof read_back !== 'object' || typeof read_back.postcondition_met !== 'boolean' || typeof read_back.downstream_changed !== 'boolean') {
        throw new Error('read_back must say { postcondition_met: boolean, downstream_changed: boolean } about the downstream state you read back.');
      }
      if (read_back.evidence_digest !== undefined && !HEX_64.test(String(read_back.evidence_digest))) throw new Error('read_back.evidence_digest must be a sha256 hex digest.');
      if (read_back.detail !== undefined && !text(read_back.detail, 300)) throw new Error('read_back.detail must be up to 300 characters.');
    }
    const okSteps = new Set(effect.receipts.filter((r) => r.status === 'ok').map((r) => r.step));
    const missing = effect.steps.filter((s) => !okSteps.has(s));
    let outcome;
    let why;
    if (!read_back) {
      // An exit status is not a read-back: without one the effect is never COMMITTED.
      outcome = okSteps.size === 0 ? 'ABORTED' : 'PARTIAL';
      why = 'closed without a read-back of the downstream state, so it cannot be COMMITTED';
    } else if (read_back.postcondition_met && missing.length === 0) {
      outcome = 'COMMITTED';
      why = 'the read-back shows the postcondition and every step has an ok receipt';
    } else if (!read_back.postcondition_met && !read_back.downstream_changed) {
      outcome = 'ABORTED';
      why = 'the read-back shows nothing changed downstream, whatever the steps reported';
    } else {
      outcome = 'PARTIAL';
      why = read_back.postcondition_met
        ? `the read-back shows the postcondition but steps ${missing.join(', ')} have no ok receipt`
        : 'the read-back shows the downstream changed without reaching the postcondition';
    }
    const record = this.seal('EFFECT_CLOSED', {
      effect_id, effect_key: effect.effect_key, outcome,
      ...(read_back ? { read_back: { postcondition_met: read_back.postcondition_met, downstream_changed: read_back.downstream_changed, ...(read_back.evidence_digest ? { evidence_digest: read_back.evidence_digest } : {}), ...(read_back.detail ? { detail: read_back.detail } : {}) } } : {}),
      steps_ok: effect.steps.filter((s) => okSteps.has(s)),
      steps_missing: missing,
      ...(effect.compensates ? { compensates: effect.compensates } : {}),
    });
    effect.state = outcome;
    effect.closed_at = new Date(this.now()).toISOString();
    const result = { status: 'CLOSED', outcome, why, effect: this.view(effect), mode: 'local', record };
    // A committed compensation, whose read-back showed the earlier state, closes the effect it undoes.
    if (effect.compensates && outcome === 'COMMITTED') {
      const original = this.effects.get(effect.compensates);
      if (original && ['IN_DOUBT', 'PARTIAL', 'COMMITTED'].includes(original.state)) {
        const prior = original.state;
        original.state = 'COMPENSATED';
        original.compensated_by = effect.effect_id;
        result.compensated = this.view(original);
        result.compensated_record = this.seal('EFFECT_COMPENSATED', {
          effect_id: original.effect_id, effect_key: original.effect_key, prior_state: prior, compensation_effect_id: effect.effect_id,
        });
      }
    }
    return result;
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
    const { effect_id: _ignored, ...start } = args;
    return this.begin({ ...start, effect_key: original.effect_key }, { compensates: original.effect_id });
  }

  /** A person accepts an effect as it stands (IN_DOUBT or PARTIAL): sealed, with who and how they authenticated. */
  accept(args) {
    if (!args || typeof args !== 'object') throw new Error('Arguments object is required.');
    this.sweep();
    const { effect_id, accepted_by, auth_method, auth_freshness_sec, reason } = args;
    const effect = this.effects.get(effect_id);
    if (!effect) throw new Error('effect_id must name an effect this server started in this run.');
    if (!['IN_DOUBT', 'PARTIAL'].includes(effect.state)) {
      return this.refuse('NOTHING_TO_ACCEPT', `Effect ${effect_id} is ${effect.state}; only an IN_DOUBT or PARTIAL effect is accepted.`);
    }
    if (!text(accepted_by, 200) || !text(auth_method, 100) || !(typeof auth_freshness_sec === 'number' && auth_freshness_sec >= 0 && auth_freshness_sec <= 300)) {
      throw new Error('accepted_by, auth_method and auth_freshness_sec (at most 300) name the person who accepts it.');
    }
    if (!text(reason, 500)) throw new Error('reason (up to 500 characters) is required.');
    const prior = effect.state;
    const record = this.seal('EFFECT_ACCEPTED', { effect_id, effect_key: effect.effect_key, prior_state: prior, accepted_by, auth_method, auth_freshness_sec, reason });
    effect.state = 'ACCEPTED';
    return { status: 'ACCEPTED', effect: this.view(effect), mode: 'local', record };
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

  view(effect) {
    const { idempotency_key, started_record_hash, ...visible } = effect;
    return { ...visible, receipts: effect.receipts.map((r) => ({ ...r })), started_record_hash };
  }

  refuse(code, reason) {
    return { status: 'DENIED', reason_code: code, reason, mode: 'local' };
  }
}
