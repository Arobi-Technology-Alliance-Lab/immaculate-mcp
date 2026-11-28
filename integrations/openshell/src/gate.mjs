/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * The gate's decisions. For each request a sandbox sends, before OpenShell adds credentials:
 *   1. who is asking: the request context's sandbox_id, which must match the caller's token when tokens are checked;
 *   2. what the request is: an Immaculate action and consequence tier, from the sandbox policy's rules (policy.mjs);
 *   3. whether it is allowed: Immaculate's local engine authorizes the action against the operator's grant for that
 *      sandbox (signature, revocation, expiry, scope, consequence tier). Only GRANTED lets the request continue.
 *      DENIED and ESCALATED deny it: a critical action needs a person's fresh authentication, which a sandboxed agent's
 *      request does not carry, so it is held.
 * Every decision seals an OPENSHELL_GATE_DECISION record, after the engine's AUTHORIZATION record when one was made,
 * and both are written to disk before the answer goes back. A decision whose record cannot be written is a denial.
 *
 * The engine's key, grants and chain last for one run, as in the MCP server. The gate starts a new run (new key, new
 * records file, the same grants with the same expiry, re-sealed) every `rotateAfterRecords` records, so memory stays
 * bounded on a long-lived service.
 */

import { closeSync, mkdirSync, openSync, writeSync } from 'node:fs';
import path from 'node:path';

import { LocalImmaculateEngine, sha256Hex } from '../../../src/engine.mjs';
import { classifyRequest } from './policy.mjs';

export const DECISION_RECORD = 'OPENSHELL_GATE_DECISION';
const REASON_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const MAX_REASON_CHARS = 1000;
const RETRY_AFTER_MS = 5000;

/** An OpenShell reason code for an engine reason code: "immaculate_" and the code in lower case (1-64 bytes). */
export function gateReasonCode(engineCode) {
  const code = `immaculate_${String(engineCode || 'denied').toLowerCase()}`;
  return REASON_CODE.test(code) ? code : 'immaculate_denied';
}

const shortText = (value) => (value.length > MAX_REASON_CHARS ? `${value.slice(0, MAX_REASON_CHARS - 1)}…` : value);
const textOrNull = (value) => (typeof value === 'string' && value ? value : null);

export class ImmaculateGate {
  /**
   * @param {object} options
   * @param {{route_id: string, granted_by: string, sandboxes: string[], actions: string[], expires_at: string}[]} options.grants
   * @param {string} options.recordsDir      a new JSONL file per run is created here
   * @param {number} [options.rotateAfterRecords]
   * @param {() => number} [options.now]     the clock in milliseconds, for tests
   * @param {(level: string, message: string, fields?: object) => void} [options.log]
   */
  constructor({ grants, recordsDir, rotateAfterRecords = 50_000, now = () => Date.now(), log = () => {} }) {
    if (!Array.isArray(grants) || grants.length === 0) throw new Error('The gate needs at least one grant.');
    this.grants = grants;
    this.recordsDir = recordsDir;
    this.rotateAfterRecords = rotateAfterRecords;
    this.now = now;
    this.log = log;
    this.run = null;
    this.lastFailedStart = -Infinity;
    this.runCount = 0;
  }

  /** Opens the first run: a new key, the grants sealed under it and written to a new records file. Throws on failure. */
  start() {
    this.run = this.openRun();
    return this;
  }

  get signerKid() {
    return this.run?.engine.signerKid ?? null;
  }

  get recordsFile() {
    return this.run?.file ?? null;
  }

  openRun() {
    const engine = new LocalImmaculateEngine({ now: this.now });
    mkdirSync(this.recordsDir, { recursive: true });
    this.runCount += 1;
    const stamp = new Date(this.now()).toISOString().replace(/[:.]/g, '-');
    const file = path.join(this.recordsDir, `${stamp}-${engine.signerKid}-${this.runCount}.jsonl`);
    const fd = openSync(file, 'wx');
    const run = { engine, file, fd, written: 0, bySandbox: new Map(), anySandbox: null, broken: null };
    try {
      for (const grant of this.grants) {
        for (const sandbox of grant.sandboxes) {
          const { route_grant: routeGrant } = engine.routeGrant({
            route_id: grant.route_id,
            scope: { actions: grant.actions },
            granted_by: grant.granted_by,
            delegated_to: `openshell-sandbox:${sandbox}`,
            expires_at: grant.expires_at,
            revocable: true,
          });
          if (sandbox === '*') run.anySandbox = routeGrant;
          else run.bySandbox.set(sandbox, routeGrant);
        }
      }
      this.flush(run);
    } catch (error) {
      this.closeRunFile(run);
      throw error;
    }
    return run;
  }

  /** Closes a run's records file once; its descriptor is forgotten so a reused number is never closed by mistake. */
  closeRunFile(run) {
    if (!run || run.fd === null) return;
    const { fd } = run;
    run.fd = null;
    try {
      closeSync(fd);
    } catch (error) {
      this.log('warn', 'could not close a records file', { file: run.file, error: error.message });
    }
  }

  /** Writes the run's records that are not on disk yet, every byte, in order. */
  flush(run) {
    const pending = run.engine.chain.slice(run.written);
    if (pending.length === 0) return;
    const data = Buffer.from(pending.map((record) => `${JSON.stringify(record)}\n`).join(''), 'utf8');
    let offset = 0;
    while (offset < data.length) offset += writeSync(run.fd, data, offset, data.length - offset);
    run.written += pending.length;
  }

  /** Starts a new run in place of the current one (rotation, or after a failed write). After a failed start, the next
   * attempt waits a few seconds, so a full disk is not hammered on every request. */
  maybeReplaceRun(reason) {
    if (this.now() - this.lastFailedStart < RETRY_AFTER_MS) return;
    let next;
    try {
      next = this.openRun();
    } catch (error) {
      this.lastFailedStart = this.now();
      this.log('error', 'could not start a new run of the gate', { reason, error: error.message });
      return;
    }
    const previous = this.run;
    this.run = next;
    this.closeRunFile(previous);
    this.log('info', 'new run of the gate', { reason, previous_file: previous.file, records_file: next.file, signer_kid: next.engine.signerKid });
  }

  /**
   * One decision.
   * @param {object} input
   * @param {object} input.target     the preflight's request target { scheme, host, port, method, path, query }
   * @param {object} input.context    the preflight's request context { request_id, sandbox_id, sandbox, workspace, originating_process }
   * @param {object} input.policy     a policy validated by validatePolicyConfig
   * @param {object|null} input.caller  the verified token claims, or null when tokens are not checked (insecure transport)
   * @param {{reason_code: string, reason: string}} [input.refusal]  a denial the server decided before classifying (an
   *   unsupported phase, an invalid policy config); it is sealed like any other decision
   * @returns {{ verdict: 'continue'|'deny', reason_code: string, reason: string, metadata: Record<string, string> }}
   */
  decide({ target, context, policy, caller, refusal }) {
    if (this.run.broken) this.maybeReplaceRun('records could not be written');
    const run = this.run;
    if (run.broken) {
      return {
        verdict: 'deny',
        reason_code: 'immaculate_record_write_failed',
        reason: 'The gate cannot write its sealed records, so it allows nothing until it can.',
        metadata: { immaculate_verdict: 'deny', immaculate_reason_code: 'immaculate_record_write_failed' },
      };
    }

    const sandboxId = textOrNull(context?.sandbox_id);
    let classification = null;
    let authorization = null;
    let outcome;
    const deny = (reasonCode, reason) => ({ verdict: 'deny', reason_code: reasonCode, reason });
    if (refusal) {
      outcome = deny(refusal.reason_code, refusal.reason);
    } else if (!sandboxId) {
      outcome = deny('immaculate_no_sandbox_id', 'The request context names no sandbox_id, so no grant can apply.');
    } else if (caller && caller.caller_kind !== 'supervisor') {
      outcome = deny('immaculate_caller_not_supervisor', `Requests are evaluated for sandbox supervisors; this call came from a ${caller.caller_kind}.`);
    } else if (caller && caller.sandbox_id !== sandboxId) {
      outcome = deny('immaculate_sandbox_mismatch', 'The caller token names a different sandbox than the request context.');
    } else {
      classification = classifyRequest(policy, target);
      if (classification.kind === 'deny') {
        outcome = deny(classification.reason_code, classification.reason);
      } else {
        const routeGrant = run.bySandbox.get(sandboxId) ?? run.anySandbox;
        if (!routeGrant) {
          outcome = deny('immaculate_no_grant', `No grant covers sandbox ${sandboxId}.`);
        } else {
          authorization = run.engine.authorize({
            route_grant: routeGrant,
            action: classification.action,
            consequence_tier: classification.tier,
            principal: `openshell-sandbox:${sandboxId}`,
          });
          outcome = authorization.decision === 'GRANTED'
            ? { verdict: 'continue', reason_code: '', reason: authorization.reason }
            : deny(gateReasonCode(authorization.reason_code), authorization.reason);
        }
      }
    }

    const query = typeof target?.query === 'string' && target.query ? target.query : null;
    const record = run.engine.sealRecord(DECISION_RECORD, {
      request_id: textOrNull(context?.request_id),
      sandbox_id: sandboxId,
      sandbox_name: textOrNull(context?.sandbox),
      workspace: textOrNull(context?.workspace),
      process_binary: textOrNull(context?.originating_process?.binary),
      caller_kind: caller ? caller.caller_kind : null,
      method: textOrNull(target?.method),
      scheme: textOrNull(target?.scheme),
      host: textOrNull(target?.host),
      port: Number.isInteger(target?.port) ? target.port : null,
      // Paths and queries can carry personal data or secrets: only their digests are sealed.
      path_sha256: typeof target?.path === 'string' ? sha256Hex(target.path) : null,
      query_sha256: query === null ? null : sha256Hex(query),
      rule: classification?.rule_id ?? null,
      action: classification?.action ?? null,
      tier: classification?.tier ?? null,
      verdict: outcome.verdict,
      reason_code: outcome.reason_code || null,
      authorization_record: authorization ? authorization.record.record_hash : null,
      engine_decision: authorization ? authorization.decision : null,
    });

    try {
      this.flush(run);
    } catch (error) {
      run.broken = error;
      this.closeRunFile(run);
      this.log('error', 'sealed records could not be written; the gate denies until a new run can write', { file: run.file, error: error.message });
      return {
        verdict: 'deny',
        reason_code: 'immaculate_record_write_failed',
        reason: 'The decision could not be written to the sealed records, so the request is denied.',
        metadata: { immaculate_verdict: 'deny', immaculate_reason_code: 'immaculate_record_write_failed' },
      };
    }

    const metadata = {
      immaculate_verdict: outcome.verdict,
      immaculate_record: record.record_hash,
      immaculate_record_seq: String(record.seq),
      immaculate_signer_kid: run.engine.signerKid,
    };
    if (outcome.reason_code) metadata.immaculate_reason_code = outcome.reason_code;
    if (classification?.action) {
      metadata.immaculate_action = classification.action;
      metadata.immaculate_tier = classification.tier;
    }
    if (classification?.rule_id) metadata.immaculate_rule = classification.rule_id;
    if (authorization) {
      metadata.immaculate_authorization_record = authorization.record.record_hash;
      metadata.immaculate_engine_decision = authorization.decision;
    }

    // A failed rotation is retried on later decisions, at most every few seconds (maybeReplaceRun spaces them).
    if (run.engine.chain.length >= this.rotateAfterRecords) this.maybeReplaceRun('rotation');
    return { verdict: outcome.verdict, reason_code: outcome.reason_code, reason: shortText(outcome.reason), metadata };
  }

  /** Closes the current records file. */
  close() {
    this.closeRunFile(this.run);
    this.run = null;
  }
}
