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
  // grant is good only for the run of the server that sealed it.
  constructor() {
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
    if (!Number.isNaN(expMs) && expMs <= Date.now()) {
      return refuse('GRANT_EXPIRED', `This grant already ended when it expired at ${route_grant.expires_at}; it authorizes nothing.`);
    }

    const revokeCore = {
      revoke_id: `rv_${crypto.randomBytes(8).toString('hex')}`,
      grant_id: route_grant.grant_id,
      grant_hash: route_grant.grant_hash,
      route_id: route_grant.route_id,
      reason: typeof reason === 'string' ? reason : '',
      revoked_at: new Date().toISOString(),
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
      // Only on a decision a revocation made; canonical JSON drops undefined, so other records are unchanged.
      revoke_id: revokeId,
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
