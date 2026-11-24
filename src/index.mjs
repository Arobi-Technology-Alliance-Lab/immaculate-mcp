#!/usr/bin/env node
/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Arobi Immaculate MCP Server — Self-Contained Local Stdio Implementation.
 *
 * Implements the Model Context Protocol (JSON-RPC 2.0 over stdio) locally with
 * zero external runtime dependencies:
 *   - arobi_route_grant        Seal a signed, bounded route grant locally
 *   - arobi_revoke_grant       End a grant this server sealed before it expires & seal a ROUTE_REVOKE record
 *   - arobi_authorize          Evaluate an action against a route grant & seal AUTHORIZATION record
 *   - arobi_classify_and_route Pick the cheapest capable model or justify a quality exception
 *   - arobi_record_route_outcome Teach learned escalation how a routed request turned out
 *   - arobi_begin_effect, arobi_record_step, arobi_close_effect, arobi_claim_effect, arobi_list_open_effects,
 *     arobi_compensate, arobi_accept_effect
 *                              Partly-run actions: an authorized effect's life, from its start to a checked outcome
 *   - arobi_verify_chain       Re-derive SHA-256 hash-chain continuity & Ed25519 signatures
 */

import readline from 'node:readline';
import { LocalImmaculateEngine } from './engine.mjs';

const SERVER_INFO = {
  name: 'arobi-immaculate-mcp',
  title: 'Arobi Immaculate MCP (local engine)',
  version: '1.5.0',
};

// What each tool does to this server's local chain, for MCP clients that decide by it (behaviour annotations). The
// writing tools append to the in-memory chain of this run only; nothing outside this process changes.
const APPENDS_LOCAL_CHAIN = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false };

const SUPPORTED_PROTOCOL_VERSIONS = ['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'];

const SERVER_INSTRUCTIONS =
  'Arobi Immaculate MCP server. Seal authority with arobi_route_grant, end it early with arobi_revoke_grant, evaluate actions with arobi_authorize, choose policy-justified models with arobi_classify_and_route, and verify hash-chained records with arobi_verify_chain. For an action that changes something downstream, authorize it with an effect_key, start it with arobi_begin_effect, record each step with arobi_record_step and close it on a read-back with arobi_close_effect: unless a read-back proves otherwise it stays IN_DOUBT, and arobi_list_open_effects shows who owns it. Records that no call returned itself (the overdue sweep\'s) come back in also_sealed.';

/** How often the overdue sweep runs between calls, so an effect whose executor went quiet reads IN_DOUBT on time. */
const EFFECT_SWEEP_INTERVAL_MS = 10_000;

export const TOOL_DEFINITIONS = [
  {
    name: 'arobi_route_grant',
    title: 'Grant authority to a workflow',
    description:
      'Seal WHO granted WHAT authority to WHICH workflow, with scope, category caps, attenuation, and expiry. Returns a locally Ed25519-signed route_grant and hash-chained ROUTE_GRANT record.',
    annotations: { title: 'Grant authority to a workflow', ...APPENDS_LOCAL_CHAIN },
    inputSchema: {
      type: 'object',
      properties: {
        route_id: { type: 'string', description: 'Unique identifier for this workflow route.' },
        scope: {
          type: 'object',
          description: 'Allowed actions and optional per-category spending caps.',
          properties: {
            actions: {
              type: 'array',
              items: { type: 'string' },
              description: 'Allowed action names or wildcard patterns (e.g. ["issue.refund", "ticket.*"]).',
            },
            category_caps: {
              type: 'object',
              description: 'Optional numeric caps keyed by category name (e.g. { "refund": 250 }).',
              additionalProperties: { type: 'number' },
            },
          },
          required: ['actions'],
        },
        granted_by: { type: 'string', description: 'Principal issuing the authority grant.' },
        delegated_to: { type: 'string', description: 'Agent or workflow receiving delegated authority.' },
        attenuation: { type: 'string', description: 'Plain-language limits carried with the grant.' },
        expires_at: { type: 'string', description: 'ISO 8601 expiry timestamp (defaults to +24h).' },
        revocable: { type: 'boolean', description: 'Whether arobi_revoke_grant can end the grant before it expires (default true).' },
      },
      required: ['route_id', 'scope', 'granted_by', 'delegated_to'],
    },
  },
  {
    name: 'arobi_revoke_grant',
    title: 'Revoke a route grant',
    description:
      'End a route grant this server sealed before it expires: seal a hash-chained ROUTE_REVOKE record and return route_revoke. From then on arobi_authorize DENIES the grant (GRANT_REVOKED). A grant that is unsigned, signed by another key, sealed with revocable: false, expired or already revoked is REFUSED with a reason code, and nothing is sealed. Like the signing key, a revocation lasts for this server run.',
    annotations: { title: 'Revoke a route grant', readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    inputSchema: {
      type: 'object',
      properties: {
        route_grant: {
          type: 'object',
          description: 'The route_grant to revoke, exactly as arobi_route_grant returned it in this server run.',
        },
        reason: {
          type: 'string',
          maxLength: 2000,
          description: 'Optional. Why the grant is revoked, up to 2,000 characters; carried in the ROUTE_REVOKE record.',
        },
      },
      required: ['route_grant'],
    },
  },
  {
    name: 'arobi_authorize',
    title: 'Authorize an agent action',
    annotations: { title: 'Authorize an agent action', ...APPENDS_LOCAL_CHAIN },
    description:
      'Decide whether an agent action is permitted against a route grant this server sealed, and seal a hash-chained AUTHORIZATION record. Returns GRANTED, DENIED, or ESCALATED with checks and reason code. A grant that is unsigned, signed by any other key, or revoked with arobi_revoke_grant is DENIED; the signing key is made when the server starts, so a grant is good for the run that sealed it.',
    inputSchema: {
      type: 'object',
      properties: {
        route_grant: {
          type: 'object',
          description: 'The route_grant object returned by arobi_route_grant in this server run.',
        },
        route_revoke: {
          type: 'object',
          description:
            'Optional. The route_revoke arobi_revoke_grant returned for this grant. This server already knows its own revocations, so the grant is DENIED either way; one that names a different grant is DENIED as ROUTE_REVOKE_MISMATCH.',
        },
        action: { type: 'string', description: 'Action name, e.g. issue.refund' },
        consequence_tier: {
          type: 'string',
          enum: ['low', 'medium', 'high', 'critical'],
          description:
            'Impact tier of the proposed action. high: an authentication older than 900 s (auth_freshness_sec) is ESCALATED. critical: auth_method and an auth_freshness_sec of 300 s or less are required, or the action is ESCALATED. An amount over the grant\'s cap for its category is DENIED (CATEGORY_CAP_EXCEEDED) at any tier.',
        },
        transaction: {
          type: 'object',
          description: 'Optional action context, recorded with the decision.',
          properties: {
            amount: { type: 'number', description: 'The amount, checked against the grant\'s scope.category_caps for its category.' },
            category: { type: 'string', description: 'The spending category, e.g. refund: the key into scope.category_caps.' },
            payee: { type: 'string', description: 'Who receives the money or the result.' },
            resource: { type: 'string', description: 'What the action acts on, e.g. order:456.' },
          },
        },
        principal: { type: 'string', description: 'Who is acting.' },
        auth_method: { type: 'string', description: 'How the principal authenticated, e.g. webauthn.' },
        auth_freshness_sec: { type: 'number', description: 'Age in seconds of that authentication.' },
        effect_key: {
          type: 'string',
          description: 'Optional. The downstream thing this action changes, e.g. deploy:site-a. While an effect on this key is open (started, IN_DOUBT or PARTIAL), the action is DENIED as EFFECT_OPEN and the answer names the open effect.',
        },
        reversal_class: {
          type: 'string',
          enum: ['REVERSIBLE', 'COMPENSABLE', 'IRREVERSIBLE'],
          description: 'Optional. How the effect can be undone. IRREVERSIBLE (mail sent, a chain transaction, physical motion) is DENIED unless human_approval names a person who approved it in the last 15 minutes.',
        },
        human_approval: {
          type: 'object',
          description: 'For an IRREVERSIBLE effect: the person who approved it. The local engine records what you report; it does not verify the person.',
          properties: {
            approver: { type: 'string', description: 'Who approved.' },
            auth_method: { type: 'string', description: 'How they authenticated.' },
            approved_at: { type: 'string', description: 'When they approved, ISO 8601.' },
          },
        },
        compensates_effect_id: {
          type: 'string',
          description: 'Optional. When this authorization is for the compensation of an open effect on the same key, that effect\'s id; it is the one authorization an open effect admits on its key.',
        },
      },
      required: ['route_grant', 'action', 'consequence_tier', 'principal'],
    },
  },
  {
    name: 'arobi_classify_and_route',
    title: 'Choose the cheapest capable route',
    annotations: { title: 'Choose the cheapest capable route', ...APPENDS_LOCAL_CHAIN },
    description:
      'Classify a prompt and choose the cheapest route capable of the work from your candidate set, reporting whether any cost above the cheapest capable route is justified by required_capabilities, an explicit quality_exception policy, or learned escalation. With escalation set, a dearer capable candidate is chosen only when the predicted chance it beats the cheapest capable one on this request (similarity-weighted over recorded outcomes, after RouteLLM) reaches the cost threshold; escalation needs cost_threshold or target_strong_rate, and with escalation.scope only evidence recorded under the same scope counts. No prompt text is kept: the request becomes sixteen content-free numbers. Set record=false to preview without appending to the local chain.',
    inputSchema: {
      type: 'object',
      properties: {
        prompt: { type: 'string', description: 'Prompt text to classify and route.' },
        candidates: {
          type: 'array',
          description:
            'Candidate models with id/model, cost_per_1k_prompt_usd, cost_per_1k_completion_usd, capabilities, observed_success_rate, and observed_sample_size.',
          items: {
            type: 'object',
            properties: {
              id: { type: 'string', description: 'Your name for the candidate (model or name are taken too).' },
              cost_per_1k_prompt_usd: { type: 'number', description: 'USD per 1,000 prompt tokens (default 0).' },
              cost_per_1k_completion_usd: { type: 'number', description: 'USD per 1,000 completion tokens (default 0).' },
              capabilities: { type: 'array', items: { type: 'string' }, description: 'What the candidate can do, matched against required_capabilities.' },
              observed_success_rate: { type: 'number', description: 'The success rate you observed, 0 to 1, used by quality_exception.' },
              observed_sample_size: { type: 'number', description: 'How many runs observed_success_rate is from (default 0).' },
            },
          },
        },
        required_capabilities: {
          type: 'array',
          items: { type: 'string' },
          description: 'Capabilities a candidate must advertise to be considered capable.',
        },
        quality_exception: {
          type: 'object',
          description:
            'Optional policy allowing a higher-cost route only when its observed success rate beats the cheapest capable route by min_success_uplift with at least min_sample_size samples on each side.',
          properties: {
            min_success_uplift: { type: 'number', description: 'How much higher the dearer route\'s observed success rate must be, e.g. 0.05.' },
            min_sample_size: { type: 'integer', description: 'The fewest observed runs each of the two routes needs before the uplift counts.' },
            max_premium_usd: { type: 'number', description: 'Optional. The most extra USD the exception may spend over the cheapest capable route.' },
          },
          required: ['min_success_uplift', 'min_sample_size'],
        },
        escalation: {
          type: 'object',
          description:
            'Optional learned escalation. Escalate from the cheapest capable candidate to a dearer one only when P(the dearer one wins on this request) >= the cost threshold. Give cost_threshold or target_strong_rate (one is required): P = 0.5 + (expected quality gain) / 2, so a threshold near 0.5 would escalate whenever the dearer one is better at all. It never picks an incapable candidate and never undoes quality_exception.',
          properties: {
            cost_threshold: { type: 'number', description: 'Escalate when the win probability is at least this, 0 to 1. Higher saves more: 0.6 means the dearer candidate is expected to score 20 points higher on requests like this one.' },
            target_strong_rate: {
              type: 'number',
              description: 'Instead of cost_threshold: the share of requests (0 to 1) you want escalated. The threshold is calibrated from this run\'s past evidence-based win probabilities (per scope); until there are 20, nothing is escalated.',
            },
            strong_candidate: { type: 'string', description: 'Which dearer candidate to consider; default the dearer capable one with the highest observed success rate.' },
            max_premium_usd: { type: 'number', description: 'The most extra USD per 1,000 prompt plus completion tokens an escalation may cost.' },
            scope: {
              type: 'string',
              pattern: '^[a-z0-9][a-z0-9._:/-]{0,63}$',
              description: 'Optional label for the population this request belongs to (a product surface, workflow or subject, e.g. support:refunds). The estimate then uses only evidence recorded under the same scope, and outcomes recorded for this decision teach only that scope. On public benchmarks this is what makes learned escalation beat chance. A label, never personal data.',
            },
          },
        },
        preference_history: {
          type: 'array',
          description:
            'Optional evidence you kept from earlier runs, content-free: each item has features (the sixteen numbers a past answer reported, or the eight from 1.3.0) and either winner_id and loser_id, tie [a, b], or candidate_id with quality 0 to 1.',
          items: {
            type: 'object',
            properties: {
              features: { type: 'array', items: { type: 'number' }, description: 'The feature numbers of that request (sixteen, or eight from 1.3.0), each 0 to 1.' },
              winner_id: { type: 'string', description: 'The candidate whose answer was better.' },
              loser_id: { type: 'string', description: 'The candidate whose answer was worse.' },
              tie: { type: 'array', items: { type: 'string' }, description: 'Two candidate ids whose answers were as good as each other.' },
              candidate_id: { type: 'string', description: 'The candidate an outcome is about.' },
              quality: { type: 'number', description: 'That outcome\'s quality, 0 to 1 (1 = fully successful).' },
              scope: { type: 'string', pattern: '^[a-z0-9][a-z0-9._:/-]{0,63}$', description: 'The escalation.scope that request was routed under, if any; a scoped request counts only items of its own scope.' },
            },
          },
        },
        record: {
          type: 'boolean',
          description: 'Default true. Set false to evaluate without sealing a chain record.',
        },
      },
      required: ['prompt', 'candidates'],
    },
  },
  {
    name: 'arobi_record_route_outcome',
    title: 'Record how a routed request turned out',
    annotations: { title: 'Record how a routed request turned out', ...APPENDS_LOCAL_CHAIN },
    description:
      'Teach learned escalation: record the outcome of a request routed by arobi_classify_and_route in this run (quality 0 to 1, or ok), and optionally how it compared with another candidate on the same request. Uses that decision\'s content-free features, seals a ROUTE_OUTCOME record, and returns the run\'s routing stats.',
    inputSchema: {
      type: 'object',
      properties: {
        routing_record_hash: { type: 'string', description: 'record_hash of the ROUTING_DECISION record the outcome is about.' },
        candidate_id: { type: 'string', description: 'The candidate that answered; default the one that decision selected.' },
        quality: { type: 'number', description: 'How good the answer was, 0 to 1.' },
        ok: { type: 'boolean', description: 'Instead of quality: true for a successful answer (1), false for a failed one (0).' },
        compared_with: {
          type: 'object',
          description: 'Optional: a comparison with another capable candidate of the same decision on this request.',
          properties: {
            candidate_id: { type: 'string', description: 'The other candidate.' },
            result: { type: 'string', enum: ['win', 'loss', 'tie'], description: 'How candidate_id did against it.' },
          },
          required: ['candidate_id', 'result'],
        },
        record: { type: 'boolean', description: 'Default true. Set false to learn from it without sealing a chain record.' },
      },
      required: ['routing_record_hash'],
    },
  },
  {
    name: 'arobi_begin_effect',
    title: 'Start an authorized effect',
    annotations: { title: 'Start an authorized effect', ...APPENDS_LOCAL_CHAIN },
    description:
      'Start the effect a GRANTED authorization allows, and seal EFFECT_STARTED: its steps, the postcondition a read-back must show, how it is undone, a deadline and the cleanup owner (default: the grant\'s issuer). Returns the effect (its attempt number and plan_digest) and a lease: pass attempt and lease.token with every step and the close, and give the downstream the effect_id as this attempt\'s request id. The lease ends at the deadline by the clock; an effect not closed by then reads IN_DOUBT, with no call needed from the executor. A retry with the same idempotency_key replays the start (without the lease) instead of applying it twice; only after that attempt closed ABORTED does the same key start the next attempt (at most 3). A start on a key with an open effect, or under a revoked or expired grant, is DENIED. Say deadline_enforced_downstream: true only if the downstream refuses this attempt after its deadline; only then can the deadline fence it (EXPIRED_UNUSED).',
    inputSchema: {
      type: 'object',
      properties: {
        authorization_record_hash: { type: 'string', description: 'record_hash of the GRANTED AUTHORIZATION this effect carries out (one effect per authorization).' },
        effect_key: { type: 'string', description: 'The downstream thing it changes; default the authorization\'s effect_key.' },
        steps: { type: 'array', items: { type: 'string' }, description: 'The step names, in order (1 to 32, distinct). Each gets its own receipt.' },
        postcondition: { type: 'string', description: 'What a read-back of the downstream state must show for the effect to be COMMITTED.' },
        reversal: {
          type: 'object',
          description: 'How the effect is undone.',
          properties: {
            class: { type: 'string', enum: ['REVERSIBLE', 'COMPENSABLE', 'IRREVERSIBLE'], description: 'REVERSIBLE names its inverse; COMPENSABLE names the action that undoes it; IRREVERSIBLE needs the authorization\'s human approval.' },
            inverse: { type: 'string', description: 'For REVERSIBLE: the inverse operation.' },
            compensation: { type: 'string', description: 'For COMPENSABLE: the compensating action, e.g. revert the commit or restore the previous deploy.' },
          },
          required: ['class'],
        },
        deadline_sec: { type: 'integer', description: 'Seconds from now by which the effect is closed (1 to 604800); after that it reads IN_DOUBT.' },
        cleanup_owner: { type: 'string', description: 'Who cleans up if it is left part-done; default the grant\'s issuer.' },
        idempotency_key: { type: 'string', description: 'Your key for this effect (8 to 200 characters); a retry with the same key replays the start. Only its sha256 is sealed.' },
        deadline_enforced_downstream: { type: 'boolean', description: 'True only if you pass deadline_at to the downstream as the call\'s own expiry and it refuses this attempt after it. Default false: then the deadline proves nothing about a call in flight, and an effect that saw nothing change is ABORTED only on the downstream\'s CONSUMED_NOT_RELEASED receipt.' },
      },
      required: ['authorization_record_hash', 'steps', 'postcondition', 'reversal', 'deadline_sec', 'idempotency_key'],
    },
  },
  {
    name: 'arobi_record_step',
    title: 'Record one step of an effect',
    annotations: { title: 'Record one step of an effect', ...APPENDS_LOCAL_CHAIN },
    description:
      'Seal the receipt of one declared step of a started effect, under its lease: ok or failed, with an optional digest of its evidence. A step already recorded ok is not recorded twice. A receipt after the deadline is refused (the lease ended with it), and so is one that names an older attempt or a lease that was replaced.',
    inputSchema: {
      type: 'object',
      properties: {
        effect_id: { type: 'string', description: 'The effect arobi_begin_effect started.' },
        attempt: { type: 'integer', description: 'The effect\'s attempt number, from its start.' },
        lease_token: { type: 'string', description: 'The lease token arobi_begin_effect returned.' },
        step: { type: 'string', description: 'One of its declared steps.' },
        status: { type: 'string', enum: ['ok', 'failed'], description: 'How the step ended.' },
        evidence_digest: { type: 'string', description: 'Optional sha256 hex of the step\'s evidence.' },
        detail: { type: 'string', description: 'Optional note, up to 300 characters.' },
      },
      required: ['effect_id', 'attempt', 'lease_token', 'step', 'status'],
    },
  },
  {
    name: 'arobi_close_effect',
    title: 'Close an effect on its read-back',
    annotations: { title: 'Close an effect on its read-back', ...APPENDS_LOCAL_CHAIN },
    description:
      'Settle an attempt on its read-back, under its lease. The outcome is decided here, not asserted, and IN_DOUBT is the default: with no read-back, or a read-back that shows nothing changed but no fence, the effect stays IN_DOUBT (open, owned, its key still fenced), because a call that timed out may still land. COMMITTED needs a read-back that shows the postcondition and an ok receipt for every step. ABORTED needs a read-back that shows nothing changed and a fence: CONSUMED_NOT_RELEASED (the downstream\'s receipt that it took this attempt and will never apply it), or EXPIRED_UNUSED (the deadline has passed and the read-back was taken after it), which counts only if the start said deadline_enforced_downstream: true. PARTIAL otherwise. A read-back counts only if it was taken after the start, not in the future and within the last 5 minutes, with an evidence digest. A committed compensation also marks the effect it undoes COMPENSATED.',
    inputSchema: {
      type: 'object',
      properties: {
        effect_id: { type: 'string', description: 'The effect to close.' },
        attempt: { type: 'integer', description: 'The effect\'s attempt number, from its start.' },
        lease_token: { type: 'string', description: 'The lease token from arobi_begin_effect, or from arobi_claim_effect for an IN_DOUBT effect.' },
        read_back: {
          type: 'object',
          description: 'What you read back from the downstream system for this attempt. Without it what landed is unknown, and the effect stays IN_DOUBT.',
          properties: {
            postcondition_met: { type: 'boolean', description: 'Whether the downstream state shows the declared postcondition.' },
            downstream_changed: { type: 'boolean', description: 'Whether anything changed downstream at all.' },
            observed_at: { type: 'string', description: 'When it was read back (ISO 8601): after the start, not in the future, at most 5 minutes ago.' },
            evidence_digest: { type: 'string', description: 'sha256 hex of what was read back.' },
            detail: { type: 'string', description: 'Optional note, up to 300 characters.' },
            fence: {
              type: 'object',
              description: 'Only with a read-back that shows nothing changed: why this attempt can no longer land.',
              properties: {
                kind: { type: 'string', enum: ['EXPIRED_UNUSED', 'CONSUMED_NOT_RELEASED'], description: 'EXPIRED_UNUSED: the deadline has passed, the read-back was taken after it, and the start said the downstream enforces the deadline. CONSUMED_NOT_RELEASED: the downstream took this attempt and will never apply it.' },
                receipt_digest: { type: 'string', description: 'For CONSUMED_NOT_RELEASED: sha256 hex of the downstream\'s receipt saying so.' },
              },
              required: ['kind'],
            },
          },
          required: ['postcondition_met', 'downstream_changed', 'observed_at', 'evidence_digest'],
        },
      },
      required: ['effect_id', 'attempt', 'lease_token'],
    },
  },
  {
    name: 'arobi_claim_effect',
    title: 'Claim an IN_DOUBT effect to reconcile it',
    annotations: { title: 'Claim an IN_DOUBT effect to reconcile it', ...APPENDS_LOCAL_CHAIN },
    description:
      'Take over an IN_DOUBT effect to read back its outcome: seals EFFECT_CLAIMED and returns a reconciliation lease (the next generation, for 15 minutes) to close it with arobi_close_effect. The earlier lease\'s writes are refused from then on. One holder at a time: refused while a lease is live or a compensation of the effect is open. At most 5 claims per effect; after that a person decides (arobi_accept_effect or arobi_compensate).',
    inputSchema: {
      type: 'object',
      properties: {
        effect_id: { type: 'string', description: 'The IN_DOUBT effect.' },
        attempt: { type: 'integer', description: 'Its attempt number.' },
        claimant: { type: 'string', description: 'Who reconciles it; default its cleanup owner.' },
      },
      required: ['effect_id', 'attempt'],
    },
  },
  {
    name: 'arobi_list_open_effects',
    title: 'List open effects and their owners',
    annotations: { title: 'List open effects and their owners', ...APPENDS_LOCAL_CHAIN },
    description:
      'List every effect still open in this run (started, IN_DOUBT or PARTIAL) with its cleanup owner, age, deadline, lease and the receipts that landed. Listing first marks overdue effects IN_DOUBT, which seals a record (returned in also_sealed), so this tool is not read-only.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'arobi_compensate',
    title: 'Start the compensation of an effect',
    annotations: { title: 'Start the compensation of an effect', ...APPENDS_LOCAL_CHAIN },
    description:
      'Start the compensation of an IN_DOUBT, PARTIAL or COMMITTED effect as an effect of its own on the same key, linked to it, with its own attempt number, lease and deadline, under its own GRANTED authorization (authorize it with compensates_effect_id). Record its steps, then close it: when its read-back shows the earlier state (its postcondition), the original becomes COMPENSATED. It starts on its own only once the original can no longer land (every step has an ok receipt, or its deadline has passed and the downstream enforces it); while the original could still land, only with human_approval from a named person, sealed as compensating_while_landable, because a late landing may overtake it. Never while the original is held by a lease, and never under a revoked or expired grant. A compensation that does not settle is IN_DOUBT like any effect, and no other compensation of the same effect starts until it is settled; at most 3 per effect. An IRREVERSIBLE effect cannot be compensated, only accepted.',
    inputSchema: {
      type: 'object',
      properties: {
        effect_id: { type: 'string', description: 'The effect to undo.' },
        authorization_record_hash: { type: 'string', description: 'record_hash of the GRANTED AUTHORIZATION for the compensation.' },
        steps: { type: 'array', items: { type: 'string' }, description: 'The compensation\'s steps.' },
        postcondition: { type: 'string', description: 'The earlier state the read-back must show.' },
        reversal: {
          type: 'object',
          description: 'How the compensation itself is undone.',
          properties: {
            class: { type: 'string', enum: ['REVERSIBLE', 'COMPENSABLE', 'IRREVERSIBLE'], description: 'Its reversal class.' },
            inverse: { type: 'string', description: 'For REVERSIBLE: the inverse operation.' },
            compensation: { type: 'string', description: 'For COMPENSABLE: the compensating action.' },
          },
          required: ['class'],
        },
        deadline_sec: { type: 'integer', description: 'Seconds from now by which the compensation is closed.' },
        idempotency_key: { type: 'string', description: 'Your key for the compensation (8 to 200 characters).' },
        deadline_enforced_downstream: { type: 'boolean', description: 'True only if the downstream refuses the compensation after its deadline (default false).' },
        human_approval: {
          type: 'object',
          description: 'Needed only while the effect it undoes could still land: the person who decided to compensate it anyway. The local engine records what you report; it does not verify the person.',
          properties: {
            approver: { type: 'string', description: 'Who approved it.' },
            auth_method: { type: 'string', description: 'How they authenticated.' },
            approved_at: { type: 'string', description: 'When (ISO 8601), within the last 15 minutes.' },
          },
          required: ['approver', 'auth_method', 'approved_at'],
        },
      },
      required: ['effect_id', 'authorization_record_hash', 'steps', 'postcondition', 'reversal', 'deadline_sec', 'idempotency_key'],
    },
  },
  {
    name: 'arobi_accept_effect',
    title: 'Accept an effect as it stands',
    annotations: { title: 'Accept an effect as it stands', ...APPENDS_LOCAL_CHAIN },
    description:
      'A person accepts an IN_DOUBT or PARTIAL effect as it stands instead of compensating it, and EFFECT_ACCEPTED is sealed with who they are, how they authenticated (within the last 300 s) and why. Accepting closes the obligation, not the outcome: an IN_DOUBT effect stays unknown and a PARTIAL one keeps its receipts, and its key stays fenced while the attempt can still land (until its deadline if the downstream enforces it, otherwise for the rest of this run). Refused while the effect is held by a lease or a compensation of it is open.',
    inputSchema: {
      type: 'object',
      properties: {
        effect_id: { type: 'string', description: 'The effect to accept.' },
        attempt: { type: 'integer', description: 'Its attempt number.' },
        accepted_by: { type: 'string', description: 'The person accepting it.' },
        auth_method: { type: 'string', description: 'How they authenticated.' },
        auth_freshness_sec: { type: 'number', description: 'Age in seconds of that authentication (at most 300).' },
        reason: { type: 'string', description: 'Why it is accepted as it stands.' },
      },
      required: ['effect_id', 'attempt', 'accepted_by', 'auth_method', 'auth_freshness_sec', 'reason'],
    },
  },
  {
    name: 'arobi_verify_chain',
    title: 'Verify a sealed record chain',
    annotations: { title: 'Verify a sealed record chain', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description:
      'Recompute a set of sealed records locally and report whether they form one unbroken SHA-256 hash chain of plain data signed by one Ed25519 key, numbered from 1 with no gap, repeat or reordering, pinpointing the first broken record index and the reason. Pass expected_signer_kid to check who signed it: without it, a chain re-sealed with another key also passes. Unsigned records fail unless allow_unsigned is true.',
    inputSchema: {
      type: 'object',
      properties: {
        records: {
          type: 'array',
          description:
            'Ordered array of sealed records returned by arobi_route_grant, arobi_revoke_grant, arobi_authorize, or arobi_classify_and_route.',
          items: { type: 'object' },
        },
        expected_signer_kid: {
          type: 'string',
          description: 'The signer_kid the records must be signed by (shown on every record this server seals).',
        },
        allow_unsigned: {
          type: 'boolean',
          description: 'Accept records without a signature and check their hash chain alone. Default false.',
        },
      },
      required: ['records'],
    },
  },
];

const engine = new LocalImmaculateEngine();

function writeMessage(obj) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
}

function handleToolCall(name, args, target) {
  const result = callTool(name, args, target);
  // Records the overdue sweep sealed (between calls, or inside this one) come back with this result, so a client
  // that keeps the records it is given holds the whole chain.
  const swept = target.effects.takeUnreturned();
  return swept.length > 0 ? { ...result, also_sealed: swept } : result;
}

function callTool(name, args, engine) {
  switch (name) {
    case 'arobi_route_grant':
      return engine.routeGrant(args);
    case 'arobi_revoke_grant':
      return engine.revokeGrant(args);
    case 'arobi_authorize':
      return engine.authorize(args);
    case 'arobi_classify_and_route':
      return engine.classifyAndRoute(args);
    case 'arobi_record_route_outcome':
      return engine.recordRouteOutcome(args);
    case 'arobi_begin_effect':
      return engine.beginEffect(args);
    case 'arobi_record_step':
      return engine.recordEffectStep(args);
    case 'arobi_close_effect':
      return engine.closeEffect(args);
    case 'arobi_claim_effect':
      return engine.claimEffect(args);
    case 'arobi_list_open_effects':
      return engine.listOpenEffects();
    case 'arobi_compensate':
      return engine.compensateEffect(args);
    case 'arobi_accept_effect':
      return engine.acceptEffect(args);
    case 'arobi_verify_chain':
      return engine.verifyChain(args);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// The server's own engine answers unless another is passed (the tests pass one with their own clock).
export function handleJsonRpc(msg, target = engine) {
  if (!msg || typeof msg !== 'object') {
    return {
      jsonrpc: '2.0',
      id: null,
      error: { code: -32600, message: 'Invalid Request' },
    };
  }

  const isNotification = msg.id === undefined;

  switch (msg.method) {
    case 'initialize': {
      // The client's version when this server speaks it, else the newest this server speaks.
      const requestedVersion = msg.params?.protocolVersion;
      const protocolVersion = SUPPORTED_PROTOCOL_VERSIONS.includes(requestedVersion)
        ? requestedVersion
        : SUPPORTED_PROTOCOL_VERSIONS[SUPPORTED_PROTOCOL_VERSIONS.length - 1];
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          protocolVersion,
          capabilities: {
            tools: { listChanged: false },
          },
          serverInfo: SERVER_INFO,
          instructions: SERVER_INSTRUCTIONS,
        },
      };
    }

    case 'notifications/initialized':
    case 'notifications/cancelled':
      return null;

    case 'ping':
      return isNotification ? null : { jsonrpc: '2.0', id: msg.id, result: {} };

    case 'tools/list':
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: { tools: TOOL_DEFINITIONS },
      };

    case 'resources/list':
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: { resources: [] },
      };

    case 'prompts/list':
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: { prompts: [] },
      };

    case 'tools/call': {
      const toolName = msg.params?.name;
      const toolArgs = msg.params?.arguments ?? {};
      try {
        const result = handleToolCall(toolName, toolArgs, target);
        return {
          jsonrpc: '2.0',
          id: msg.id,
          result: {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
            structuredContent: result,
            isError: false,
          },
        };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          jsonrpc: '2.0',
          id: msg.id,
          result: {
            content: [{ type: 'text', text: JSON.stringify({ error: message }) }],
            isError: true,
          },
        };
      }
    }

    default:
      if (isNotification) return null;
      return {
        jsonrpc: '2.0',
        id: msg.id,
        error: { code: -32601, message: `Method not found: ${msg.method}` },
      };
  }
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/'))) {
  engine.effects.startSweepTimer(EFFECT_SWEEP_INTERVAL_MS);
  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });

  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      writeMessage({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error: invalid JSON' },
      });
      return;
    }
    const resp = handleJsonRpc(msg);
    if (resp) writeMessage(resp);
  });

  rl.on('close', () => {
    process.exit(0);
  });
}
