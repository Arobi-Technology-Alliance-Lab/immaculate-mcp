/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { handleJsonRpc } from '../src/index.mjs';

test('MCP initialize, ping, and tools/list return all 4 tools', () => {
  const init = handleJsonRpc({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '1.0.0' } },
  });
  assert.equal(init.result.serverInfo.name, 'arobi-immaculate-mcp');

  const ping = handleJsonRpc({ jsonrpc: '2.0', id: 2, method: 'ping' });
  assert.deepEqual(ping.result, {});

  const list = handleJsonRpc({ jsonrpc: '2.0', id: 3, method: 'tools/list' });
  const names = list.result.tools.map((t) => t.name);
  assert.deepEqual(names, [
    'arobi_route_grant',
    'arobi_authorize',
    'arobi_classify_and_route',
    'arobi_verify_chain',
  ]);
});

test('End-to-end route grant, authorize verdicts, and tamper-evident chain verification', () => {
  const grantResp = handleJsonRpc({
    jsonrpc: '2.0',
    id: 10,
    method: 'tools/call',
    params: {
      name: 'arobi_route_grant',
      arguments: {
        route_id: 'support-refunds-v1',
        scope: { actions: ['issue.refund'], category_caps: { refund: 250 } },
        granted_by: 'ops-director',
        delegated_to: 'support-agent',
        attenuation: 'Max $250 per refund',
      },
    },
  });
  assert.equal(grantResp.result.isError, false);
  const { route_grant, record: r1 } = grantResp.result.structuredContent;
  assert.ok(route_grant.grant_id);
  assert.equal(r1.prev_hash, 'genesis');

  const okResp = handleJsonRpc({
    jsonrpc: '2.0',
    id: 11,
    method: 'tools/call',
    params: {
      name: 'arobi_authorize',
      arguments: {
        route_grant,
        action: 'issue.refund',
        consequence_tier: 'medium',
        principal: 'support-agent',
        transaction: { category: 'refund', amount: 120 },
      },
    },
  });
  assert.equal(okResp.result.structuredContent.decision, 'GRANTED');
  const r2 = okResp.result.structuredContent.record;

  const capResp = handleJsonRpc({
    jsonrpc: '2.0',
    id: 12,
    method: 'tools/call',
    params: {
      name: 'arobi_authorize',
      arguments: {
        route_grant,
        action: 'issue.refund',
        consequence_tier: 'medium',
        principal: 'support-agent',
        transaction: { category: 'refund', amount: 500 },
      },
    },
  });
  assert.equal(capResp.result.structuredContent.decision, 'DENIED');
  assert.equal(capResp.result.structuredContent.reason_code, 'CATEGORY_CAP_EXCEEDED');
  const r3 = capResp.result.structuredContent.record;

  const escResp = handleJsonRpc({
    jsonrpc: '2.0',
    id: 13,
    method: 'tools/call',
    params: {
      name: 'arobi_authorize',
      arguments: {
        route_grant,
        action: 'issue.refund',
        consequence_tier: 'critical',
        principal: 'support-agent',
        transaction: { category: 'refund', amount: 50 },
      },
    },
  });
  assert.equal(escResp.result.structuredContent.decision, 'ESCALATED');
  const r4 = escResp.result.structuredContent.record;

  const validResp = handleJsonRpc({
    jsonrpc: '2.0',
    id: 14,
    method: 'tools/call',
    params: {
      name: 'arobi_verify_chain',
      arguments: { records: [r1, r2, r3, r4] },
    },
  });
  assert.equal(validResp.result.structuredContent.valid, true);
  assert.equal(validResp.result.structuredContent.checked_count, 4);

  const tampered = structuredClone(r2);
  tampered.payload.decision = 'DENIED';
  const badResp = handleJsonRpc({
    jsonrpc: '2.0',
    id: 15,
    method: 'tools/call',
    params: {
      name: 'arobi_verify_chain',
      arguments: { records: [r1, tampered, r3, r4] },
    },
  });
  assert.equal(badResp.result.structuredContent.valid, false);
  assert.equal(badResp.result.structuredContent.first_broken_index, 1);
});

test('arobi_classify_and_route picks cheapest capable or justified quality exception', () => {
  const candidates = [
    {
      id: 'fast-mini',
      cost_per_1k_prompt_usd: 0.0005,
      cost_per_1k_completion_usd: 0.001,
      capabilities: ['json', 'tools'],
      observed_success_rate: 0.78,
      observed_sample_size: 50,
    },
    {
      id: 'frontier-pro',
      cost_per_1k_prompt_usd: 0.005,
      cost_per_1k_completion_usd: 0.015,
      capabilities: ['json', 'tools', 'vision'],
      observed_success_rate: 0.94,
      observed_sample_size: 50,
    },
  ];

  const cheap = handleJsonRpc({
    jsonrpc: '2.0',
    id: 20,
    method: 'tools/call',
    params: {
      name: 'arobi_classify_and_route',
      arguments: { prompt: 'Summarize ticket #12', candidates, required_capabilities: ['json'], record: false },
    },
  });
  assert.equal(cheap.result.structuredContent.selected.id, 'fast-mini');

  const upgraded = handleJsonRpc({
    jsonrpc: '2.0',
    id: 21,
    method: 'tools/call',
    params: {
      name: 'arobi_classify_and_route',
      arguments: {
        prompt: 'Security audit of distributed authorization chain',
        candidates,
        required_capabilities: ['tools'],
        quality_exception: { min_success_uplift: 0.1, min_sample_size: 30, max_premium_usd: 0.05 },
        record: false,
      },
    },
  });
  assert.equal(upgraded.result.structuredContent.selected.id, 'frontier-pro');
  assert.equal(upgraded.result.structuredContent.justification_type, 'quality_exception');
});
