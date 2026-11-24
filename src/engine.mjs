/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Arobi Immaculate Local Governance & Evidence Engine.
 * Self-contained, zero-dependency implementation of Immaculate MCP's local
 * pre-action governance, model routing, and cryptographic hash-chain
 * verification tools via Node.js built-in `node:crypto` (SHA-256 + Ed25519).
 */

import crypto from 'node:crypto';
import {
  complexityOf, evidenceFromHistory, evidenceInScope, FEATURE_NAMES, isScopeLabel, routeFeatures, thresholdForStrongRate,
  winProbability,
} from './route-learning.mjs';
import { EffectLedger } from './effects.mjs';

// How much routing evidence one run keeps (oldest dropped first): win probabilities for calibration, outcomes and
// pairwise preferences, and the routing decisions outcomes can refer to.
const ROUTE_MEMORY = 5000;

export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys
    .filter((k) => value[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
    .join(',')}}`;
}

export function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function matchesActionPattern(allowedActions, requestedAction) {
  if (!Array.isArray(allowedActions)) return false;
  for (const pattern of allowedActions) {
    if (typeof pattern !== 'string') continue;
    if (pattern === '*' || pattern === requestedAction) return true;
    if (pattern.endsWith('.*')) {
      const prefix = pattern.slice(0, -1);
      if (requestedAction.startsWith(prefix)) return true;
    }
  }
  return false;
}

// signerKidOf names an Ed25519 public key (PEM) the way the engine names its own: the first 16 hex digits of the
// SHA-256 of its SPKI encoding. It returns null for anything that is not a public key.
export function signerKidOf(publicKeyPem) {
  try {
    const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
    return crypto.createHash('sha256').update(der).digest('hex').slice(0, 16);
  } catch {
    return null;
  }
}

export class LocalImmaculateEngine {
  // The signing key is generated when the engine starts: grants and records are signed by this run's key, and a
  // grant is good only for the run of the server that sealed it. `now` is the clock (milliseconds), for tests.
  constructor(options = {}) {
    this.now = typeof options.now === 'function' ? options.now : () => Date.now();
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    this.signerKid = signerKidOf(this.publicKeyPem);
    this.chain = [];
    this.seenPrompts = new Map();
    // Grants revoked in this run, by grant_hash. Like the key, they last for the run: a restarted server honours none
    // of the old run's grants anyway.
    this.revocations = new Map();
    // Learned escalation (RouteLLM-style): content-free evidence, the run's past win probabilities for threshold
    // calibration ({ scope, p }, so each scope calibrates on its own), and the recorded routing decisions an outcome
    // can refer to. Like the key, these last for the run.
    this.routeEvidence = [];
    this.winScores = [];
    this.routeDecisions = new Map();
    // Partly-run actions: the life of each authorized effect, sealed in this chain (src/effects.mjs).
    this.effects = new EffectLedger({ seal: (type, payload) => this.sealRecord(type, payload), now: () => this.now() });
  }

  remember(list, item) {
    list.push(item);
    if (list.length > ROUTE_MEMORY) list.shift();
  }

  // grantStatus says whether route_grant was sealed by this engine: 'ok', 'unsigned', 'foreign' (signed with
  // another key, which anyone can make) or 'invalid' (its hash or signature does not verify).
  grantStatus(routeGrant) {
    const { grant_hash, signer_kid, public_key_pem, signature_b64, ...core } = routeGrant;
    if (typeof grant_hash !== 'string' || typeof signature_b64 !== 'string') return 'unsigned';
    if (signer_kid !== this.signerKid || (public_key_pem !== undefined && signerKidOf(public_key_pem) !== this.signerKid)) {
      return 'foreign';
    }
    if (sha256Hex(canonicalJson(core)) !== grant_hash) return 'invalid';
    try {
      return crypto.verify(null, Buffer.from(grant_hash, 'utf8'), this.publicKey, Buffer.from(signature_b64, 'base64'))
        ? 'ok'
        : 'invalid';
    } catch {
      return 'invalid';
    }
  }

  sealRecord(recordType, payload) {
    const seq = this.chain.length + 1;
    const prevHash = this.chain.length === 0 ? 'genesis' : this.chain[this.chain.length - 1].record_hash;
    const timestamp = new Date(this.now()).toISOString();

    const body = {
      seq,
      record_type: recordType,
      prev_hash: prevHash,
      timestamp,
      payload,
    };

    const recordHash = sha256Hex(canonicalJson(body));
    const signatureB64 = crypto
      .sign(null, Buffer.from(recordHash, 'utf8'), this.privateKey)
      .toString('base64');

    const record = {
      ...body,
      record_hash: recordHash,
      signer_kid: this.signerKid,
      public_key_pem: this.publicKeyPem,
      signature_b64: signatureB64,
    };

    this.chain.push(record);
    return record;
  }

  routeGrant(args) {
    if (!args || typeof args !== 'object') {
      throw new Error('Arguments object is required.');
    }
    const { route_id, scope, granted_by, delegated_to, attenuation, expires_at, revocable } = args;
    if (!route_id || typeof route_id !== 'string') throw new Error('route_id (string) is required.');
    if (!scope || typeof scope !== 'object' || !Array.isArray(scope.actions)) {
      throw new Error('scope.actions (string[]) is required.');
    }
    if (!granted_by || typeof granted_by !== 'string') throw new Error('granted_by (string) is required.');
    if (!delegated_to || typeof delegated_to !== 'string') throw new Error('delegated_to (string) is required.');

    const issuedAt = new Date(this.now()).toISOString();
    const resolvedExpiry =
      typeof expires_at === 'string' && expires_at.trim()
        ? expires_at.trim()
        : new Date(this.now() + 24 * 60 * 60 * 1000).toISOString();

    if (Number.isNaN(Date.parse(resolvedExpiry))) {
      throw new Error('expires_at must be a valid ISO 8601 timestamp.');
    }

    const grantCore = {
      grant_id: `gr_${crypto.randomBytes(8).toString('hex')}`,
      route_id,
      scope: {
        actions: scope.actions,
        ...(scope.category_caps ? { category_caps: scope.category_caps } : {}),
      },
      granted_by,
      delegated_to,
      attenuation: typeof attenuation === 'string' ? attenuation : '',
      issued_at: issuedAt,
      expires_at: resolvedExpiry,
      revocable: revocable !== undefined ? Boolean(revocable) : true,
    };

    const grantHash = sha256Hex(canonicalJson(grantCore));
    const grantSignature = crypto
      .sign(null, Buffer.from(grantHash, 'utf8'), this.privateKey)
      .toString('base64');

    const routeGrant = {
      ...grantCore,
      grant_hash: grantHash,
      signer_kid: this.signerKid,
      public_key_pem: this.publicKeyPem,
      signature_b64: grantSignature,
    };

    const record = this.sealRecord('ROUTE_GRANT', {
      grant_id: routeGrant.grant_id,
      route_id: routeGrant.route_id,
      granted_by: routeGrant.granted_by,
      delegated_to: routeGrant.delegated_to,
      expires_at: routeGrant.expires_at,
      grant_hash: routeGrant.grant_hash,
    });

    return {
      status: 'SEALED',
      mode: 'local',
      route_grant: routeGrant,
      record,
    };
  }

  // revokeGrant ends a grant this server sealed before it expires. It seals a ROUTE_REVOKE record, chained after the
  // records before it, and returns route_revoke. From then on arobi_authorize DENIES the grant (GRANT_REVOKED). Only a
  // grant this server sealed, marked revocable, not expired and not already revoked can be revoked; anything else is
  // REFUSED with a reason code and nothing is sealed.
  revokeGrant(args) {
    if (!args || typeof args !== 'object') {
      throw new Error('Arguments object is required.');
    }
    const { route_grant, reason } = args;
    if (!route_grant || typeof route_grant !== 'object') {
      throw new Error('route_grant (object) is required: the route_grant arobi_route_grant returned.');
    }
    if (reason !== undefined && (typeof reason !== 'string' || reason.length > 2000)) {
      throw new Error('reason must be a string of up to 2,000 characters.');
    }
    const refuse = (reasonCode, why, extra = {}) => ({ status: 'REFUSED', reason_code: reasonCode, reason: why, mode: 'local', ...extra });

    const grantStatus = this.grantStatus(route_grant);
    if (grantStatus === 'unsigned') {
      return refuse('GRANT_UNSIGNED', 'Route grant is not signed, so this server never sealed it and there is nothing to revoke.');
    }
    if (grantStatus === 'foreign') {
      return refuse('GRANT_FOREIGN_SIGNER', `Route grant was not sealed by this server (signer ${this.signerKid}). Only the server run that sealed a grant can revoke it.`);
    }
    if (grantStatus !== 'ok') {
      return refuse('GRANT_SIGNATURE_INVALID', 'Route grant hash or Ed25519 signature verification failed.');
    }
    if (route_grant.revocable === false) {
      return refuse('GRANT_NOT_REVOCABLE', 'This grant was sealed with revocable: false. It ends when it expires.');
    }
    const prior = this.revocations.get(route_grant.grant_hash);
    if (prior) {
      return refuse('GRANT_ALREADY_REVOKED', `This grant was already revoked at ${prior.revoked_at}.`, { route_revoke: prior });
    }
    const expMs = Date.parse(route_grant.expires_at);
    if (!Number.isNaN(expMs) && expMs <= this.now()) {
      return refuse('GRANT_EXPIRED', `This grant already ended when it expired at ${route_grant.expires_at}; it authorizes nothing.`);
    }

    const revokeCore = {
      revoke_id: `rv_${crypto.randomBytes(8).toString('hex')}`,
      grant_id: route_grant.grant_id,
      grant_hash: route_grant.grant_hash,
      route_id: route_grant.route_id,
      reason: typeof reason === 'string' ? reason : '',
      revoked_at: new Date(this.now()).toISOString(),
    };
    const revokeHash = sha256Hex(canonicalJson(revokeCore));
    const revokeSignature = crypto
      .sign(null, Buffer.from(revokeHash, 'utf8'), this.privateKey)
      .toString('base64');
    const routeRevoke = {
      ...revokeCore,
      revoke_hash: revokeHash,
      signer_kid: this.signerKid,
      public_key_pem: this.publicKeyPem,
      signature_b64: revokeSignature,
    };

    const record = this.sealRecord('ROUTE_REVOKE', { ...revokeCore, revoke_hash: revokeHash });
    this.revocations.set(route_grant.grant_hash, routeRevoke);

    return {
      status: 'REVOKED',
      mode: 'local',
      route_revoke: routeRevoke,
      record,
    };
  }

  authorize(args) {
    if (!args || typeof args !== 'object') {
      throw new Error('Arguments object is required.');
    }
    const {
      route_grant,
      action,
      consequence_tier,
      transaction,
      principal,
      auth_method,
      auth_freshness_sec,
      route_revoke,
      effect_key,
      reversal_class,
      human_approval,
      compensates_effect_id,
    } = args;

    if (!route_grant || typeof route_grant !== 'object') {
      throw new Error('route_grant (object) is required. Call arobi_route_grant first.');
    }
    if (route_revoke !== undefined && (!route_revoke || typeof route_revoke !== 'object')) {
      throw new Error('route_revoke must be the route_revoke object arobi_revoke_grant returned.');
    }
    if (!action || typeof action !== 'string') throw new Error('action (string) is required.');
    if (!['low', 'medium', 'high', 'critical'].includes(consequence_tier)) {
      throw new Error('consequence_tier must be one of: low, medium, high, critical.');
    }
    if (!principal || typeof principal !== 'string') throw new Error('principal (string) is required.');

    const checks = [];
    let decision = 'GRANTED';
    let reasonCode = 'WITHIN_ROUTE_GRANT_SCOPE';
    let reason = `Action "${action}" is authorized within route grant scope for principal "${principal}".`;

    // Only a grant this server sealed counts. An unsigned grant, or one signed with any other key, is refused:
    // otherwise a caller could write its own grant and be authorized by it.
    const grantStatus = this.grantStatus(route_grant);
    checks.push({ check: 'grant_signature', passed: grantStatus === 'ok' });
    if (grantStatus !== 'ok') {
      decision = 'DENIED';
      if (grantStatus === 'unsigned') {
        reasonCode = 'GRANT_UNSIGNED';
        reason = 'Route grant is not signed. Call arobi_route_grant to seal one.';
      } else if (grantStatus === 'foreign') {
        reasonCode = 'GRANT_FOREIGN_SIGNER';
        reason = `Route grant was not sealed by this server (signer ${this.signerKid}). A grant is good only for the run of the server that sealed it.`;
      } else {
        reasonCode = 'GRANT_SIGNATURE_INVALID';
        reason = 'Route grant hash or Ed25519 signature verification failed.';
      }
    }

    // A revoked grant authorizes nothing. This run knows its own revocations; a route_revoke passed in is honoured too,
    // and one that names a different grant is refused rather than ignored. Honouring a revocation can only take
    // authority away, so it fails closed.
    let revokeId;
    if (decision === 'GRANTED') {
      const known = this.revocations.get(route_grant.grant_hash);
      const mismatch = route_revoke !== undefined && route_revoke.grant_hash !== route_grant.grant_hash;
      const revoked = known ?? (route_revoke !== undefined && !mismatch ? route_revoke : undefined);
      checks.push({ check: 'grant_not_revoked', passed: !revoked && !mismatch });
      if (mismatch) {
        decision = 'DENIED';
        reasonCode = 'ROUTE_REVOKE_MISMATCH';
        reason = 'The route_revoke passed names a different grant than route_grant. Pass the route_revoke issued for this grant, or none.';
      } else if (revoked) {
        decision = 'DENIED';
        reasonCode = 'GRANT_REVOKED';
        revokeId = typeof revoked.revoke_id === 'string' ? revoked.revoke_id : undefined;
        reason = `Route grant ${route_grant.grant_id} was revoked${typeof revoked.revoked_at === 'string' ? ` at ${revoked.revoked_at}` : ''}; it authorizes nothing more.`;
      }
    }

    if (decision === 'GRANTED' && route_grant.expires_at) {
      const expMs = Date.parse(route_grant.expires_at);
      const notExpired = !Number.isNaN(expMs) && expMs > this.now();
      checks.push({ check: 'grant_not_expired', passed: notExpired });
      if (!notExpired) {
        decision = 'DENIED';
        reasonCode = 'GRANT_EXPIRED';
        reason = `Route grant expired at ${route_grant.expires_at}.`;
      }
    }

    if (decision === 'GRANTED') {
      const allowedActions = route_grant.scope?.actions || [];
      const inScope = matchesActionPattern(allowedActions, action);
      checks.push({ check: 'action_in_scope', passed: inScope });
      if (!inScope) {
        decision = 'DENIED';
        reasonCode = 'ACTION_OUT_OF_SCOPE';
        reason = `Action "${action}" is not permitted by route grant scope [${allowedActions.join(', ')}].`;
      }
    }

    if (decision === 'GRANTED' && transaction && typeof transaction === 'object') {
      const caps = route_grant.scope?.category_caps;
      const category = transaction.category;
      const amount = Number(transaction.amount);
      if (caps && category && Object.prototype.hasOwnProperty.call(caps, category) && Number.isFinite(amount)) {
        const cap = Number(caps[category]);
        const withinCap = amount <= cap;
        checks.push({ check: 'category_cap', passed: withinCap, amount, cap, category });
        if (!withinCap) {
          decision = 'DENIED';
          reasonCode = 'CATEGORY_CAP_EXCEEDED';
          reason = `Transaction amount ${amount} exceeds cap ${cap} for category "${category}".`;
        }
      }
    }

    // An action with a downstream effect: no open effect on its key, and an IRREVERSIBLE one only with a person's
    // approval, decided here at authorization rather than discovered afterwards.
    let openEffectId;
    if (decision === 'GRANTED' && (effect_key !== undefined || reversal_class !== undefined)) {
      const refused = this.effects.authorizationGate({ effect_key, reversal_class, human_approval, compensates_effect_id });
      checks.push({ check: 'effect_gate', passed: !refused });
      if (refused) {
        decision = 'DENIED';
        reasonCode = refused.reason_code;
        reason = refused.reason;
        openEffectId = refused.open_effect_id;
      }
    }

    if (decision === 'GRANTED') {
      const freshness = typeof auth_freshness_sec === 'number' ? auth_freshness_sec : null;
      const hasMethod = typeof auth_method === 'string' && auth_method.trim().length > 0;
      if (consequence_tier === 'critical') {
        const freshEnough = hasMethod && freshness !== null && freshness <= 300;
        checks.push({ check: 'critical_auth_freshness', passed: freshEnough });
        if (!freshEnough) {
          decision = 'ESCALATED';
          reasonCode = 'CRITICAL_REQUIRES_FRESH_AUTH';
          reason = 'Critical consequence tier requires explicit auth_method and auth_freshness_sec <= 300.';
        }
      } else if (consequence_tier === 'high' && freshness !== null && freshness > 900) {
        checks.push({ check: 'high_tier_auth_freshness', passed: false });
        decision = 'ESCALATED';
        reasonCode = 'STALE_AUTHENTICATION';
        reason = `Authentication age (${freshness}s) exceeds 900s threshold for high-consequence action.`;
      } else {
        checks.push({ check: 'consequence_tier_policy', passed: true });
      }
    }

    const record = this.sealRecord('AUTHORIZATION', {
      grant_id: route_grant.grant_id || null,
      route_id: route_grant.route_id || null,
      action,
      consequence_tier,
      principal,
      auth_method: auth_method || null,
      auth_freshness_sec: auth_freshness_sec ?? null,
      transaction: transaction || null,
      decision,
      reason_code: reasonCode,
      // Only on a decision a revocation made; canonical JSON drops undefined, so other records are unchanged.
      revoke_id: revokeId,
      // Only when the action declares an effect; the same rule keeps other records unchanged.
      effect_key,
      reversal_class,
      human_approval: human_approval && typeof human_approval === 'object'
        ? { approver: human_approval.approver, auth_method: human_approval.auth_method, approved_at: human_approval.approved_at }
        : undefined,
      compensates_effect_id,
      open_effect_id: openEffectId,
    });

    if (decision === 'GRANTED') {
      this.effects.rememberAuthorization(record.record_hash, {
        action, effect_key, reversal_class, granted_by: route_grant.granted_by,
      });
    }

    return {
      decision,
      reason_code: reasonCode,
      reason,
      checks,
      ...(openEffectId ? { open_effect_id: openEffectId } : {}),
      mode: 'local',
      record,
    };
  }

  // Partly-run actions (src/effects.mjs): start, step receipts, checked close, open obligations, compensation, acceptance.
  beginEffect(args) { return this.effects.begin(args); }

  recordEffectStep(args) { return this.effects.recordStep(args); }

  closeEffect(args) { return this.effects.close(args); }

  listOpenEffects() { return this.effects.listOpen(); }

  compensateEffect(args) { return this.effects.compensate(args); }

  acceptEffect(args) { return this.effects.accept(args); }

  classifyAndRoute(args) {
    if (!args || typeof args !== 'object') {
      throw new Error('Arguments object is required.');
    }
    const { prompt, candidates, required_capabilities = [], quality_exception, record: shouldRecord = true } = args;
    if (!prompt || typeof prompt !== 'string') throw new Error('prompt (string) is required.');
    if (!Array.isArray(candidates) || candidates.length === 0) {
      throw new Error('candidates (non-empty array) is required.');
    }

    // Eight content-free numbers stand for the request; the text is hashed and never kept.
    const features = routeFeatures(prompt);
    const complexity = complexityOf(prompt, features);

    const promptHash = sha256Hex(prompt.trim());
    const priorEntry = this.seenPrompts.get(promptHash);
    const alreadyDone = Boolean(priorEntry);

    const normalized = candidates.map((c, idx) => {
      const promptCost = Number(c.cost_per_1k_prompt_usd ?? 0);
      const completionCost = Number(c.cost_per_1k_completion_usd ?? 0);
      const totalUnitCost = Number((promptCost + completionCost).toFixed(6));
      const caps = Array.isArray(c.capabilities) ? c.capabilities : [];
      const hasAllRequired = required_capabilities.every((reqCap) => caps.includes(reqCap));
      return {
        index: idx,
        id: c.id || c.model || c.name || `candidate_${idx}`,
        total_unit_cost_usd: totalUnitCost,
        capabilities: caps,
        observed_success_rate: typeof c.observed_success_rate === 'number' ? c.observed_success_rate : null,
        observed_sample_size: typeof c.observed_sample_size === 'number' ? c.observed_sample_size : 0,
        capable: hasAllRequired,
        raw: c,
      };
    });

    const capable = normalized
      .filter((c) => c.capable)
      .sort((a, b) => a.total_unit_cost_usd - b.total_unit_cost_usd);

    if (capable.length === 0) {
      return {
        status: 'NO_CAPABLE_ROUTE',
        complexity,
        already_done: alreadyDone,
        required_capabilities,
        selected: null,
        justification: 'No candidate satisfies all required_capabilities.',
        mode: 'local',
      };
    }

    const cheapest = capable[0];
    let selected = cheapest;
    let justification = required_capabilities.length > 0
      ? `Selected cheapest candidate satisfying required_capabilities [${required_capabilities.join(', ')}].`
      : 'Selected cheapest capable candidate; no justified quality exception triggered.';
    let justificationType = required_capabilities.length > 0 ? 'required_capability' : 'cheapest_capable';

    if (quality_exception && typeof quality_exception === 'object') {
      const minUplift = Number(quality_exception.min_success_uplift);
      const minSamples = Number(quality_exception.min_sample_size);
      const maxPremium =
        quality_exception.max_premium_usd !== undefined ? Number(quality_exception.max_premium_usd) : Infinity;

      if (
        Number.isFinite(minUplift) &&
        Number.isFinite(minSamples) &&
        cheapest.observed_success_rate !== null &&
        cheapest.observed_sample_size >= minSamples
      ) {
        const qualifying = capable
          .slice(1)
          .filter((cand) => {
            if (cand.observed_success_rate === null || cand.observed_sample_size < minSamples) return false;
            const uplift = cand.observed_success_rate - cheapest.observed_success_rate;
            const premium = cand.total_unit_cost_usd - cheapest.total_unit_cost_usd;
            return uplift >= minUplift && premium <= maxPremium;
          })
          .sort((a, b) => b.observed_success_rate - a.observed_success_rate);

        if (qualifying.length > 0) {
          selected = qualifying[0];
          const uplift = Number((selected.observed_success_rate - cheapest.observed_success_rate).toFixed(4));
          justificationType = 'quality_exception';
          justification = `Selected ${selected.id} under explicit quality_exception: observed success uplift +${uplift} (>= ${minUplift}) with >= ${minSamples} samples on both routes.`;
        }
      }
    }

    // Learned escalation (opt-in through `escalation`): pay for a dearer capable candidate only when the chance its
    // answer beats the cheapest capable one on THIS request clears the cost threshold (RouteLLM, Eq. 2). The capability
    // floor and max_premium_usd still bound it, and it can only escalate, never undo an explicit quality_exception.
    let escalationResult;
    let escalationScope;
    const escalation = args.escalation;
    if (escalation !== undefined) {
      if (!escalation || typeof escalation !== 'object') throw new Error('escalation must be an object.');
      const { cost_threshold, target_strong_rate, strong_candidate, max_premium_usd, scope } = escalation;
      if (cost_threshold !== undefined && !(typeof cost_threshold === 'number' && cost_threshold >= 0 && cost_threshold <= 1)) {
        throw new Error('escalation.cost_threshold must be a number from 0 to 1.');
      }
      if (target_strong_rate !== undefined && !(typeof target_strong_rate === 'number' && target_strong_rate >= 0 && target_strong_rate <= 1)) {
        throw new Error('escalation.target_strong_rate must be a number from 0 to 1.');
      }
      if (scope !== undefined && !isScopeLabel(scope)) {
        throw new Error('escalation.scope must be a lowercase label of 1 to 64 characters (a-z, 0-9, . _ : / -), starting with a letter or digit.');
      }
      // The trade-off is the caller's to state. P = 0.5 + (expected quality gain) / 2, so any threshold near 0.5 buys
      // the premium whenever the dearer candidate is better at all, which on public benchmarks is 83-100% of requests.
      if (cost_threshold === undefined && target_strong_rate === undefined) {
        throw new Error('escalation needs cost_threshold or target_strong_rate: P = 0.5 + (expected quality gain) / 2, so cost_threshold 0.6 escalates only when the dearer candidate is expected to score 20 points higher on requests like this one, and target_strong_rate 0.2 escalates about a fifth of requests.');
      }
      escalationScope = scope;
      const premiumCap = max_premium_usd !== undefined ? Number(max_premium_usd) : Infinity;
      const dearer = capable.filter((c) => c !== cheapest && c.total_unit_cost_usd - cheapest.total_unit_cost_usd <= premiumCap);
      let strong = null;
      if (strong_candidate !== undefined) {
        strong = dearer.find((c) => c.id === strong_candidate) ?? null;
      } else if (dearer.length > 0) {
        // The likeliest-best dearer candidate: the highest observed success rate, then the dearer one.
        strong = [...dearer].sort((a, b) => ((b.observed_success_rate ?? -1) - (a.observed_success_rate ?? -1))
          || (b.total_unit_cost_usd - a.total_unit_cost_usd))[0];
      }
      // Present in the result (and so in the sealed record) only when given, so unscoped records are as before.
      const scoped = scope === undefined ? {} : { scope };
      if (!strong) {
        escalationResult = {
          escalated: false,
          ...scoped,
          reason: strong_candidate !== undefined
            ? `strong_candidate ${strong_candidate} is not a capable candidate within the premium cap.`
            : 'No dearer capable candidate within the premium cap.',
        };
      } else {
        // With a scope, only evidence recorded under that scope counts: the run's own and the caller's history.
        const evidence = evidenceInScope([...this.routeEvidence, ...evidenceFromHistory(args.preference_history)], scope);
        const win = winProbability({ features, weakId: cheapest.id, strongId: strong.id, evidence, complexity });
        let threshold = cost_threshold;
        let thresholdSource = 'cost_threshold';
        if (threshold === undefined) {
          // Calibrated from this scope's past estimates; until there are 20 there is no threshold to guess, so
          // nothing is escalated (a guessed 0.5 would escalate almost everything).
          const pastScores = this.winScores.filter((s) => s.scope === scope).map((s) => s.p);
          const calibrated = thresholdForStrongRate(pastScores, target_strong_rate);
          threshold = calibrated;
          thresholdSource = calibrated === null ? 'calibrating_until_20_scores' : 'calibrated_to_target_strong_rate';
        }
        // Calibration takes only estimates that rested on evidence: the prior is a constant per complexity.
        if (win.source !== 'complexity_prior') this.remember(this.winScores, { scope, p: win.p });
        const escalate = threshold !== null && win.p >= threshold && selected !== strong;
        if (escalate) {
          selected = strong;
          justificationType = 'learned_escalation';
          justification = `Escalated to ${strong.id}: P(it beats ${cheapest.id} on this request) = ${win.p} >= cost threshold ${threshold} (${win.source}${scope === undefined ? '' : `, scope ${scope}`}).`;
        }
        escalationResult = {
          escalated: escalate,
          ...scoped,
          strong_id: strong.id,
          win_probability: win.p,
          win_probability_source: win.source,
          pair_evidence: win.pair_evidence,
          outcome_evidence: win.outcome_evidence,
          cost_threshold: threshold,
          cost_threshold_source: thresholdSource,
        };
      }
    }

    const premiumUsd = Number((selected.total_unit_cost_usd - cheapest.total_unit_cost_usd).toFixed(6));

    let sealed = null;
    if (shouldRecord) {
      sealed = this.sealRecord('ROUTING_DECISION', {
        prompt_hash: promptHash,
        complexity,
        selected_id: selected.id,
        cheapest_id: cheapest.id,
        premium_usd: premiumUsd,
        justification_type: justificationType,
        already_done: alreadyDone,
        // Only when escalation was asked for; canonical JSON drops undefined, so other records are unchanged.
        features: escalationResult ? features : undefined,
        escalation: escalationResult,
      });
      this.seenPrompts.set(promptHash, { selected_id: selected.id, record_hash: sealed.record_hash });
      this.routeDecisions.set(sealed.record_hash, {
        features, cheapest_id: cheapest.id, selected_id: selected.id, escalated: Boolean(escalationResult?.escalated),
        candidate_ids: capable.map((c) => c.id), scope: escalationScope,
      });
      if (this.routeDecisions.size > ROUTE_MEMORY) this.routeDecisions.delete(this.routeDecisions.keys().next().value);
    }

    return {
      status: 'ROUTED',
      complexity,
      already_done: alreadyDone,
      selected: {
        id: selected.id,
        total_unit_cost_usd: selected.total_unit_cost_usd,
        capabilities: selected.capabilities,
      },
      cheapest_capable: {
        id: cheapest.id,
        total_unit_cost_usd: cheapest.total_unit_cost_usd,
      },
      premium_usd: premiumUsd,
      justification_type: justificationType,
      justification,
      ...(escalationResult ? { escalation: escalationResult, features: Object.fromEntries(FEATURE_NAMES.map((n, i) => [n, features[i]])) } : {}),
      mode: 'local',
      ...(sealed ? { record: sealed } : {}),
    };
  }

  // recordRouteOutcome feeds learned escalation: how a routed request turned out (a quality in [0, 1], or ok), and
  // optionally how it compared with another candidate on the same request. It refers to a ROUTING_DECISION this run
  // sealed, takes that decision's content-free features, and seals a ROUTE_OUTCOME record. No text is involved.
  recordRouteOutcome(args) {
    if (!args || typeof args !== 'object') throw new Error('Arguments object is required.');
    const { routing_record_hash, candidate_id, quality, ok, compared_with, record: shouldRecord = true } = args;
    const decision = typeof routing_record_hash === 'string' ? this.routeDecisions.get(routing_record_hash) : undefined;
    if (!decision) throw new Error('routing_record_hash must name a ROUTING_DECISION this server sealed in this run.');
    const candidateId = candidate_id ?? decision.selected_id;
    if (!decision.candidate_ids.includes(candidateId)) throw new Error(`candidate_id ${candidateId} was not a capable candidate of that decision.`);
    let q;
    if (typeof quality === 'number') {
      if (!(quality >= 0 && quality <= 1)) throw new Error('quality must be from 0 to 1.');
      q = quality;
    } else if (typeof ok === 'boolean') {
      q = ok ? 1 : 0;
    } else {
      throw new Error('Give quality (0 to 1) or ok (boolean).');
    }
    let pair = null;
    if (compared_with !== undefined) {
      const other = compared_with?.candidate_id;
      const result = compared_with?.result;
      if (typeof other !== 'string' || other === candidateId || !decision.candidate_ids.includes(other)) {
        throw new Error('compared_with.candidate_id must be another capable candidate of that decision.');
      }
      if (!['win', 'loss', 'tie'].includes(result)) throw new Error("compared_with.result must be 'win', 'loss' or 'tie'.");
      pair = result === 'tie'
        ? { kind: 'pair', features: decision.features, a: candidateId, b: other, tie: true }
        : { kind: 'pair', features: decision.features, a: result === 'win' ? candidateId : other, b: result === 'win' ? other : candidateId, tie: false };
    }
    // Evidence keeps the scope its decision was routed under, so it teaches only that scope's later requests.
    const scoped = decision.scope === undefined ? {} : { scope: decision.scope };
    this.remember(this.routeEvidence, { kind: 'outcome', features: decision.features, candidate_id: candidateId, quality: q, ...scoped });
    if (pair) this.remember(this.routeEvidence, { ...pair, ...scoped });
    const sealed = shouldRecord
      ? this.sealRecord('ROUTE_OUTCOME', {
        routing_record_hash,
        candidate_id: candidateId,
        quality: q,
        compared_with: pair ? { candidate_id: compared_with.candidate_id, result: compared_with.result } : undefined,
      })
      : null;
    const outcomes = this.routeEvidence.filter((e) => e.kind === 'outcome');
    const byCandidate = {};
    for (const e of outcomes) {
      byCandidate[e.candidate_id] ??= { n: 0, mean_quality: 0 };
      const c = byCandidate[e.candidate_id];
      c.mean_quality = (c.mean_quality * c.n + e.quality) / (c.n + 1);
      c.n += 1;
    }
    for (const c of Object.values(byCandidate)) c.mean_quality = Number(c.mean_quality.toFixed(4));
    const decisions = [...this.routeDecisions.values()];
    return {
      status: 'RECORDED',
      candidate_id: candidateId,
      quality: q,
      evidence: { outcomes: outcomes.length, pairs: this.routeEvidence.length - outcomes.length },
      stats: {
        decisions: decisions.length,
        escalated_share: decisions.length ? Number((decisions.filter((d) => d.escalated).length / decisions.length).toFixed(4)) : 0,
        by_candidate: byCandidate,
      },
      mode: 'local',
      ...(sealed ? { record: sealed } : {}),
    };
  }

  // verifyChain checks that records are one unbroken hash chain, every record signed by one Ed25519 key. Without
  // expected_signer_kid that shows the chain is intact as signed, not who signed it: a chain re-sealed with another
  // key passes too. With it, the signer must be that key. An unsigned record fails unless allow_unsigned is true.
  verifyChain(args) {
    if (!args || typeof args !== 'object' || !Array.isArray(args.records)) {
      throw new Error('records (array) is required.');
    }
    const { records, expected_signer_kid, allow_unsigned = false } = args;
    if (expected_signer_kid !== undefined && (typeof expected_signer_kid !== 'string' || !expected_signer_kid)) {
      throw new Error('expected_signer_kid must be a non-empty string.');
    }
    const broken = (i, reason) => ({ valid: false, checked_count: i, first_broken_index: i, reason, mode: 'local' });
    let chainSigner = null;
    let unsigned = 0;
    if (records.length === 0) {
      return {
        valid: true,
        checked_count: 0,
        first_broken_index: null,
        reason: 'Empty chain contains no records to break continuity.',
        mode: 'local',
      };
    }

    for (let i = 0; i < records.length; i++) {
      const rec = records[i];
      if (!rec || typeof rec !== 'object') {
        return {
          valid: false,
          checked_count: i,
          first_broken_index: i,
          reason: `Record at index ${i} is not an object.`,
          mode: 'local',
        };
      }

      const expectedPrev = i === 0 ? 'genesis' : records[i - 1].record_hash;
      if (rec.prev_hash !== expectedPrev) {
        return {
          valid: false,
          checked_count: i,
          first_broken_index: i,
          reason: `Hash chain discontinuity at index ${i}: expected prev_hash "${expectedPrev}", found "${rec.prev_hash}".`,
          mode: 'local',
        };
      }

      const body = {
        seq: rec.seq,
        record_type: rec.record_type,
        prev_hash: rec.prev_hash,
        timestamp: rec.timestamp,
        payload: rec.payload,
      };
      const recomputedHash = sha256Hex(canonicalJson(body));
      if (rec.record_hash !== recomputedHash) {
        return {
          valid: false,
          checked_count: i,
          first_broken_index: i,
          reason: `Digest mismatch at index ${i}: expected record_hash "${recomputedHash}", found "${rec.record_hash}".`,
          mode: 'local',
        };
      }

      if (!rec.signature_b64 || !rec.public_key_pem) {
        if (!allow_unsigned) {
          return broken(i, `Record at index ${i} is not signed (pass allow_unsigned: true to check the hash chain alone).`);
        }
        unsigned++;
        continue;
      }
      const kid = signerKidOf(rec.public_key_pem);
      if (kid === null || (rec.signer_kid !== undefined && rec.signer_kid !== kid)) {
        return broken(i, `Record at index ${i} names signer ${rec.signer_kid}, which is not the key it carries.`);
      }
      if (chainSigner === null) chainSigner = kid;
      if (kid !== chainSigner) {
        return broken(i, `Record at index ${i} is signed by ${kid}, not by ${chainSigner} like the records before it.`);
      }
      if (expected_signer_kid !== undefined && kid !== expected_signer_kid) {
        return broken(i, `Record at index ${i} is signed by ${kid}, not by the expected signer ${expected_signer_kid}.`);
      }
      let sigValid = false;
      try {
        sigValid = crypto.verify(
          null,
          Buffer.from(rec.record_hash, 'utf8'),
          rec.public_key_pem,
          Buffer.from(rec.signature_b64, 'base64')
        );
      } catch {
        sigValid = false;
      }
      if (!sigValid) {
        return broken(i, `Ed25519 signature verification failed at index ${i}.`);
      }
    }

    const signed = records.length - unsigned;
    let reason = `All ${records.length} record(s) form one unbroken SHA-256 hash chain`;
    if (signed > 0) {
      reason += expected_signer_kid !== undefined
        ? `, and ${signed} signed by the expected signer ${chainSigner}.`
        : `, and ${signed} signed by one key (signer ${chainSigner}). Pass expected_signer_kid to check that this is the signer you trust: a chain re-sealed with another key also passes without it.`;
    } else {
      reason += ', and none is signed.';
    }
    return {
      valid: true,
      checked_count: records.length,
      first_broken_index: null,
      head_hash: records[records.length - 1].record_hash,
      signer_kid: chainSigner,
      signer_pinned: expected_signer_kid !== undefined && signed > 0,
      unsigned_count: unsigned,
      reason,
      mode: 'local',
    };
  }
}
