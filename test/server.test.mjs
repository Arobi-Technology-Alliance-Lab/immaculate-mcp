/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 */

import crypto from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';
import { handleJsonRpc } from '../src/index.mjs';
import { LocalImmaculateEngine } from '../src/engine.mjs';

function call(id, name, args) {
  return handleJsonRpc({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }).result;
}

test('MCP initialize, ping, and tools/list return all 5 tools', () => {
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
    'arobi_revoke_grant',
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

test('initialize answers with a protocol version this server speaks', () => {
  const version = (v) =>
    handleJsonRpc({ jsonrpc: '2.0', id: 40, method: 'initialize', params: { protocolVersion: v, capabilities: {} } }).result
      .protocolVersion;
  assert.equal(version('2025-06-18'), '2025-06-18');
  assert.equal(version('2099-01-01'), '2025-11-25');
  assert.equal(version(undefined), '2025-11-25');
});

test('arobi_authorize refuses a grant this server did not seal', () => {
  const grantArgs = { route_id: 'r1', scope: { actions: ['issue.refund'] }, granted_by: 'owner', delegated_to: 'agent' };
  const ask = { action: 'issue.refund', consequence_tier: 'low', principal: 'agent' };

  // Written by hand, with no signature.
  const unsigned = call(20, 'arobi_authorize', { ...ask, route_grant: { route_id: 'r1', scope: { actions: ['*'] } } });
  assert.equal(unsigned.structuredContent.decision, 'DENIED');
  assert.equal(unsigned.structuredContent.reason_code, 'GRANT_UNSIGNED');

  // Sealed with another key, which anyone can make.
  const other = new LocalImmaculateEngine().routeGrant(grantArgs).route_grant;
  const foreign = call(21, 'arobi_authorize', { ...ask, route_grant: other });
  assert.equal(foreign.structuredContent.decision, 'DENIED');
  assert.equal(foreign.structuredContent.reason_code, 'GRANT_FOREIGN_SIGNER');

  // This server's own grant is honoured; the same grant with its scope widened afterwards is not.
  const own = call(22, 'arobi_route_grant', grantArgs).structuredContent.route_grant;
  assert.equal(call(23, 'arobi_authorize', { ...ask, route_grant: own }).structuredContent.decision, 'GRANTED');
  const widened = call(24, 'arobi_authorize', { ...ask, action: 'wire.transfer', route_grant: { ...own, scope: { actions: ['*'] } } });
  assert.equal(widened.structuredContent.decision, 'DENIED');
  assert.equal(widened.structuredContent.reason_code, 'GRANT_SIGNATURE_INVALID');
});

test('arobi_verify_chain names the signer and refuses unsigned records, mixed signers and an unexpected signer', () => {
  const sealChain = (engine) => {
    const g = engine.routeGrant({ route_id: 'r2', scope: { actions: ['a'] }, granted_by: 'owner', delegated_to: 'agent' });
    const a = engine.authorize({ route_grant: g.route_grant, action: 'a', consequence_tier: 'low', principal: 'agent' });
    return [g.record, a.record];
  };
  const engine = new LocalImmaculateEngine();
  const chain = sealChain(engine);

  const ok = engine.verifyChain({ records: chain });
  assert.equal(ok.valid, true);
  assert.equal(ok.signer_kid, engine.signerKid);
  assert.equal(ok.signer_pinned, false);
  assert.equal(engine.verifyChain({ records: chain, expected_signer_kid: engine.signerKid }).signer_pinned, true);

  // A chain sealed with another key is intact as signed, so it passes alone, and fails against the expected signer.
  const forger = new LocalImmaculateEngine();
  const forged = sealChain(forger);
  assert.equal(engine.verifyChain({ records: forged }).valid, true);
  const pinned = engine.verifyChain({ records: forged, expected_signer_kid: engine.signerKid });
  assert.equal(pinned.valid, false);
  assert.equal(pinned.first_broken_index, 0);

  // One record re-signed with another key.
  const resigned = {
    ...chain[1],
    public_key_pem: forger.publicKeyPem,
    signer_kid: forger.signerKid,
    signature_b64: crypto.sign(null, Buffer.from(chain[1].record_hash, 'utf8'), forger.privateKey).toString('base64'),
  };
  const mixed = engine.verifyChain({ records: [chain[0], resigned] });
  assert.equal(mixed.valid, false);
  assert.equal(mixed.first_broken_index, 1);

  // Signatures stripped: refused, unless the hash chain alone is asked for.
  const stripped = chain.map(({ signature_b64, public_key_pem, signer_kid, ...rest }) => rest);
  assert.equal(engine.verifyChain({ records: stripped }).valid, false);
  const hashOnly = engine.verifyChain({ records: stripped, allow_unsigned: true });
  assert.equal(hashOnly.valid, true);
  assert.equal(hashOnly.unsigned_count, 2);
  assert.equal(hashOnly.signer_kid, null);
});

// Agent readiness (2026-11-20): an agent should never have to guess what a parameter means or whether a tool changes
// anything. Every parameter at every depth is described, and every tool has a title and MCP's behaviour annotations.
test('every tool is titled and annotated, and every parameter is described', () => {
  const list = handleJsonRpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  const missing = [];
  const walk = (properties, path) => {
    for (const [name, schema] of Object.entries(properties ?? {})) {
      if (!schema.description?.trim()) missing.push(`${path}.${name}`);
      walk(schema.properties, `${path}.${name}`);
      walk(schema.items?.properties, `${path}.${name}[]`);
    }
  };
  for (const tool of list.result.tools) {
    walk(tool.inputSchema.properties, tool.name);
    assert.ok(tool.title, `${tool.name} has a title`);
    for (const hint of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']) {
      assert.equal(typeof tool.annotations?.[hint], 'boolean', `${tool.name}.${hint}`);
    }
  }
  assert.deepEqual(missing, []);
  const readOnly = Object.fromEntries(list.result.tools.map((tool) => [tool.name, tool.annotations.readOnlyHint]));
  assert.deepEqual(readOnly, { arobi_route_grant: false, arobi_revoke_grant: false, arobi_authorize: false, arobi_classify_and_route: false, arobi_verify_chain: true });
  const destructive = list.result.tools.filter((tool) => tool.annotations.destructiveHint).map((tool) => tool.name);
  assert.deepEqual(destructive, ['arobi_revoke_grant']);
  const init = handleJsonRpc({ jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: '2025-06-18' } });
  assert.ok(init.result.serverInfo.title);
});

// Lifecycle (2026-11-21): a grant can be ended before it expires. Revoking seals a ROUTE_REVOKE record in the same
// chain, the grant is DENIED from then on, and only this run's own, revocable, live, unrevoked grants can be revoked.
test('arobi_revoke_grant ends a grant: DENIED afterwards, chained, and refused for grants it may not revoke', () => {
  const engine = new LocalImmaculateEngine();
  const grantArgs = { route_id: 'refunds', scope: { actions: ['issue.refund'] }, granted_by: 'ops-director', delegated_to: 'support-agent' };
  const ask = { action: 'issue.refund', consequence_tier: 'low', principal: 'support-agent' };

  const g = engine.routeGrant(grantArgs);
  const before = engine.authorize({ ...ask, route_grant: g.route_grant });
  assert.equal(before.decision, 'GRANTED');

  const rv = engine.revokeGrant({ route_grant: g.route_grant, reason: 'Agent retired from the refunds queue.' });
  assert.equal(rv.status, 'REVOKED');
  assert.equal(rv.record.record_type, 'ROUTE_REVOKE');
  assert.equal(rv.record.prev_hash, before.record.record_hash);
  assert.equal(rv.route_revoke.grant_hash, g.route_grant.grant_hash);
  assert.equal(rv.route_revoke.signer_kid, engine.signerKid);
  assert.equal(rv.record.payload.reason, 'Agent retired from the refunds queue.');

  const after = engine.authorize({ ...ask, route_grant: g.route_grant });
  assert.equal(after.decision, 'DENIED');
  assert.equal(after.reason_code, 'GRANT_REVOKED');
  assert.equal(after.record.payload.revoke_id, rv.route_revoke.revoke_id);
  assert.ok(after.checks.some((c) => c.check === 'grant_not_revoked' && c.passed === false));

  // Passing the route_revoke too changes nothing; a route_revoke for another grant is refused, not ignored.
  assert.equal(engine.authorize({ ...ask, route_grant: g.route_grant, route_revoke: rv.route_revoke }).reason_code, 'GRANT_REVOKED');
  const other = engine.routeGrant({ ...grantArgs, route_id: 'refunds-2' });
  const mismatch = engine.authorize({ ...ask, route_grant: other.route_grant, route_revoke: rv.route_revoke });
  assert.equal(mismatch.decision, 'DENIED');
  assert.equal(mismatch.reason_code, 'ROUTE_REVOKE_MISMATCH');
  assert.equal(engine.authorize({ ...ask, route_grant: other.route_grant }).decision, 'GRANTED');

  // Twice: refused, with the first revocation.
  const again = engine.revokeGrant({ route_grant: g.route_grant });
  assert.equal(again.status, 'REFUSED');
  assert.equal(again.reason_code, 'GRANT_ALREADY_REVOKED');
  assert.equal(again.route_revoke.revoke_id, rv.route_revoke.revoke_id);

  // Not this run's grant, not signed, tampered, not revocable, or already expired: refused, nothing sealed.
  const length = engine.chain.length;
  const foreign = new LocalImmaculateEngine().routeGrant(grantArgs).route_grant;
  assert.equal(engine.revokeGrant({ route_grant: foreign }).reason_code, 'GRANT_FOREIGN_SIGNER');
  assert.equal(engine.revokeGrant({ route_grant: { route_id: 'x', scope: { actions: ['*'] } } }).reason_code, 'GRANT_UNSIGNED');
  assert.equal(engine.revokeGrant({ route_grant: { ...other.route_grant, scope: { actions: ['*'] } } }).reason_code, 'GRANT_SIGNATURE_INVALID');
  const fixed = engine.routeGrant({ ...grantArgs, route_id: 'fixed', revocable: false });
  assert.equal(engine.revokeGrant({ route_grant: fixed.route_grant }).reason_code, 'GRANT_NOT_REVOCABLE');
  assert.equal(engine.authorize({ ...ask, route_grant: fixed.route_grant }).decision, 'GRANTED');
  const expired = engine.routeGrant({ ...grantArgs, route_id: 'old', expires_at: '2020-01-01T00:00:00.000Z' });
  assert.equal(engine.revokeGrant({ route_grant: expired.route_grant }).reason_code, 'GRANT_EXPIRED');
  assert.equal(engine.chain.length, length + 3, 'only the two new grants and the one authorization were sealed');
  assert.throws(() => engine.revokeGrant({ route_grant: g.route_grant, reason: 'x'.repeat(2001) }), /2,000/);
  assert.throws(() => engine.authorize({ ...ask, route_grant: g.route_grant, route_revoke: 'rv_1' }), /route_revoke/);

  // The whole run, revocation included, is one chain signed by this run's key.
  const verified = engine.verifyChain({ records: engine.chain, expected_signer_kid: engine.signerKid });
  assert.equal(verified.valid, true);
  assert.equal(verified.signer_pinned, true);
});

test('arobi_revoke_grant over MCP: REVOKED, then the grant is DENIED', () => {
  const grant = call(40, 'arobi_route_grant', { route_id: 'mcp-revoke', scope: { actions: ['ticket.close'] }, granted_by: 'owner', delegated_to: 'agent' });
  const routeGrant = grant.structuredContent.route_grant;
  const revoked = call(41, 'arobi_revoke_grant', { route_grant: routeGrant, reason: 'Done for today.' });
  assert.equal(revoked.isError, false);
  assert.equal(revoked.structuredContent.status, 'REVOKED');
  const denied = call(42, 'arobi_authorize', { route_grant: routeGrant, action: 'ticket.close', consequence_tier: 'low', principal: 'agent' });
  assert.equal(denied.structuredContent.decision, 'DENIED');
  assert.equal(denied.structuredContent.reason_code, 'GRANT_REVOKED');
  // The text content an MCP client reads carries the same verdict and names the revocation.
  const text = JSON.parse(denied.content[0].text);
  assert.equal(text.record.payload.revoke_id, revoked.structuredContent.route_revoke.revoke_id);
  assert.equal(text.record.prev_hash, revoked.structuredContent.record.record_hash);
});
