/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Arobi Immaculate Local Governance & Evidence Engine.
 * Self-contained, zero-dependency implementation of Immaculate MCP's local
 * pre-action governance, model routing, and cryptographic hash-chain
 * verification tools via Node.js built-in `node:crypto` (SHA-256 + Ed25519).
 */

import crypto from 'node:crypto';

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

export class LocalImmaculateEngine {
  constructor() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const der = publicKey.export({ type: 'spki', format: 'der' });
    this.signerKid = crypto.createHash('sha256').update(der).digest('hex').slice(0, 16);
    this.chain = [];
    this.seenPrompts = new Map();
  }

  sealRecord(recordType, payload) {
    const seq = this.chain.length + 1;
    const prevHash = this.chain.length === 0 ? 'genesis' : this.chain[this.chain.length - 1].record_hash;
    const timestamp = new Date().toISOString();

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

    const issuedAt = new Date().toISOString();
    const resolvedExpiry =
      typeof expires_at === 'string' && expires_at.trim()
        ? expires_at.trim()
        : new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

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
    } = args;

    if (!route_grant || typeof route_grant !== 'object') {
      throw new Error('route_grant (object) is required. Call arobi_route_grant first.');
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

    if (route_grant.grant_hash && route_grant.signature_b64 && route_grant.public_key_pem) {
      const { grant_hash, signer_kid, public_key_pem, signature_b64, ...core } = route_grant;
      const expectedHash = sha256Hex(canonicalJson(core));
      let sigOk = false;
      try {
        sigOk =
          expectedHash === grant_hash &&
          crypto.verify(
            null,
            Buffer.from(grant_hash, 'utf8'),
            public_key_pem,
            Buffer.from(signature_b64, 'base64')
          );
      } catch {
        sigOk = false;
      }
      checks.push({ check: 'grant_signature', passed: sigOk });
      if (!sigOk) {
        decision = 'DENIED';
        reasonCode = 'GRANT_SIGNATURE_INVALID';
        reason = 'Route grant hash or Ed25519 signature verification failed.';
      }
    }

    if (decision === 'GRANTED' && route_grant.expires_at) {
      const expMs = Date.parse(route_grant.expires_at);
      const notExpired = !Number.isNaN(expMs) && expMs > Date.now();
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
    });

    return {
      decision,
      reason_code: reasonCode,
      reason,
      checks,
      mode: 'local',
      record,
    };
  }

  classifyAndRoute(args) {
    if (!args || typeof args !== 'object') {
      throw new Error('Arguments object is required.');
    }
    const { prompt, candidates, required_capabilities = [], quality_exception, record: shouldRecord = true } = args;
    if (!prompt || typeof prompt !== 'string') throw new Error('prompt (string) is required.');
    if (!Array.isArray(candidates) || candidates.length === 0) {
      throw new Error('candidates (non-empty array) is required.');
    }

    const lower = prompt.toLowerCase();
    const highSignals = /(architect|proof|cryptograph|security audit|distributed|concurrent|formal|migration|multi-step|incident)/;
    const mediumSignals = /(refactor|implement|analyze|debug|compare|design|summarize|test suite|sql)/;
    let complexity = 'low';
    if (prompt.length > 600 || highSignals.test(lower)) complexity = 'high';
    else if (prompt.length > 160 || mediumSignals.test(lower)) complexity = 'medium';

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
      });
      this.seenPrompts.set(promptHash, { selected_id: selected.id, record_hash: sealed.record_hash });
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
      mode: 'local',
      ...(sealed ? { record: sealed } : {}),
    };
  }

  verifyChain(args) {
    if (!args || typeof args !== 'object' || !Array.isArray(args.records)) {
      throw new Error('records (array) is required.');
    }
    const { records } = args;
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

      if (rec.signature_b64 && rec.public_key_pem) {
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
          return {
            valid: false,
            checked_count: i,
            first_broken_index: i,
            reason: `Ed25519 signature verification failed at index ${i}.`,
            mode: 'local',
          };
        }
      }
    }

    return {
      valid: true,
      checked_count: records.length,
      first_broken_index: null,
      head_hash: records[records.length - 1].record_hash,
      reason: `All ${records.length} record(s) passed canonical SHA-256 hash-chain and Ed25519 signature verification.`,
      mode: 'local',
    };
  }
}
