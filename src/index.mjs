#!/usr/bin/env node
/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Arobi Immaculate MCP Server — Self-Contained Local Stdio Implementation.
 *
 * Implements the Model Context Protocol (JSON-RPC 2.0 over stdio) locally with
 * zero external runtime dependencies:
 *   - arobi_route_grant        Seal a signed, bounded route grant locally
 *   - arobi_authorize          Evaluate an action against a route grant & seal AUTHORIZATION record
 *   - arobi_classify_and_route Pick the cheapest capable model or justify a quality exception
 *   - arobi_verify_chain       Re-derive SHA-256 hash-chain continuity & Ed25519 signatures
 */

import readline from 'node:readline';
import { LocalImmaculateEngine } from './engine.mjs';

const SERVER_INFO = {
  name: 'arobi-immaculate-mcp',
  title: 'Arobi Immaculate MCP (local engine)',
  version: '1.1.0',
};

// What each tool does to this server's local chain, for MCP clients that decide by it (behaviour annotations). The
// writing tools append to the in-memory chain of this run only; nothing outside this process changes.
const APPENDS_LOCAL_CHAIN = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false };

const SUPPORTED_PROTOCOL_VERSIONS = ['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'];

const SERVER_INSTRUCTIONS =
  'Arobi Immaculate MCP server. Seal authority with arobi_route_grant, evaluate actions with arobi_authorize, choose policy-justified models with arobi_classify_and_route, and verify hash-chained records with arobi_verify_chain.';

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
        revocable: { type: 'boolean', description: 'Whether the grant can be revoked (default true).' },
      },
      required: ['route_id', 'scope', 'granted_by', 'delegated_to'],
    },
  },
  {
    name: 'arobi_authorize',
    title: 'Authorize an agent action',
    annotations: { title: 'Authorize an agent action', ...APPENDS_LOCAL_CHAIN },
    description:
      'Decide whether an agent action is permitted against a route grant this server sealed, and seal a hash-chained AUTHORIZATION record. Returns GRANTED, DENIED, or ESCALATED with checks and reason code. A grant that is unsigned, or signed by any other key, is DENIED; the signing key is made when the server starts, so a grant is good for the run that sealed it.',
    inputSchema: {
      type: 'object',
      properties: {
        route_grant: {
          type: 'object',
          description: 'The route_grant object returned by arobi_route_grant in this server run.',
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
      },
      required: ['route_grant', 'action', 'consequence_tier', 'principal'],
    },
  },
  {
    name: 'arobi_classify_and_route',
    title: 'Choose the cheapest capable route',
    annotations: { title: 'Choose the cheapest capable route', ...APPENDS_LOCAL_CHAIN },
    description:
      'Classify a prompt and choose the cheapest route capable of the work from your candidate set, reporting whether any cost above the cheapest capable route is justified by required_capabilities or an explicit quality_exception policy. Set record=false to preview without appending to the local chain.',
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
        record: {
          type: 'boolean',
          description: 'Default true. Set false to evaluate without sealing a chain record.',
        },
      },
      required: ['prompt', 'candidates'],
    },
  },
  {
    name: 'arobi_verify_chain',
    title: 'Verify a sealed record chain',
    annotations: { title: 'Verify a sealed record chain', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description:
      'Recompute a set of sealed records locally and report whether they form one unbroken SHA-256 hash chain signed by one Ed25519 key, pinpointing the first broken record index and the reason. Pass expected_signer_kid to check who signed it: without it, a chain re-sealed with another key also passes. Unsigned records fail unless allow_unsigned is true.',
    inputSchema: {
      type: 'object',
      properties: {
        records: {
          type: 'array',
          description:
            'Ordered array of sealed records returned by arobi_route_grant, arobi_authorize, or arobi_classify_and_route.',
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

function handleToolCall(name, args) {
  switch (name) {
    case 'arobi_route_grant':
      return engine.routeGrant(args);
    case 'arobi_authorize':
      return engine.authorize(args);
    case 'arobi_classify_and_route':
      return engine.classifyAndRoute(args);
    case 'arobi_verify_chain':
      return engine.verifyChain(args);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

export function handleJsonRpc(msg) {
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
        const result = handleToolCall(toolName, toolArgs);
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
