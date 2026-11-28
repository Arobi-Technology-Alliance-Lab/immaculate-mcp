#!/usr/bin/env node
/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 *   immaculate-openshell-gate serve --config gate.json
 *       Serve the gate for OpenShell. Logs are JSON lines on stdout.
 *   immaculate-openshell-gate check --config gate.json [--policy policy-config.json] [--request "POST https://host/path"]
 *       Check the operator's file and a policy entry's config (JSON), and show what one request would be classified as.
 *   immaculate-openshell-gate verify <records.jsonl> [--signer <kid>]
 *       Check a records file: hash chain, signatures, one signer, and every line complete.
 */

import { readFileSync } from 'node:fs';
import process from 'node:process';

import grpc from '@grpc/grpc-js';

import { LocalImmaculateEngine } from '../../../src/engine.mjs';
import { ExtensionTokenVerifier } from './auth.mjs';
import { loadGateConfig } from './config.mjs';
import { DECISION_RECORD, ImmaculateGate } from './gate.mjs';
import { classifyRequest, validatePolicyConfig } from './policy.mjs';
import { createGateServer, VERSION } from './server.mjs';

function jsonLogger(stream = process.stdout) {
  return (level, message, fields = {}) => {
    stream.write(`${JSON.stringify({ ts: new Date().toISOString(), level, message, ...fields })}\n`);
  };
}

function option(args, name) {
  const at = args.indexOf(name);
  if (at === -1) return undefined;
  const value = args[at + 1];
  if (value === undefined || value.startsWith('--')) throw new Error(`${name} needs a value.`);
  return value;
}

async function serve(args) {
  const file = option(args, '--config');
  if (!file) throw new Error('serve needs --config <gate.json>.');
  const log = jsonLogger();
  const config = loadGateConfig(file);
  if (config.insecure) {
    log('warn', 'plaintext transport with no token checks: any client that reaches this port can call the gate. For local development only.');
  }
  const verifier = config.auth ? await new ExtensionTokenVerifier(config.auth).init() : null;
  const gate = new ImmaculateGate({ grants: config.grants, recordsDir: config.recordsDir, rotateAfterRecords: config.rotateAfterRecords, log }).start();
  const server = createGateServer({ gate, verifier, log });
  const credentials = config.insecure
    ? grpc.ServerCredentials.createInsecure()
    : grpc.ServerCredentials.createSsl(null, [{ private_key: config.tls.key, cert_chain: config.tls.cert }], false);

  await new Promise((resolve, reject) => {
    server.bindAsync(config.listen, credentials, (error, port) => {
      if (error) {
        reject(new Error(`cannot listen on ${config.listen}: ${error.message}`));
        return;
      }
      log('info', 'serving', {
        version: VERSION,
        listen: config.listen,
        port,
        transport: config.insecure ? 'plaintext' : 'tls',
        token_checks: Boolean(verifier),
        audience: verifier ? verifier.audience : null,
        grants: config.grants.length,
        signer_kid: gate.signerKid,
        records_file: gate.recordsFile,
      });
      resolve();
    });
  });

  let stopping = false;
  const stop = (signal) => {
    if (stopping) return;
    stopping = true;
    log('info', 'stopping; requests that select the gate are blocked until it is back (OpenShell fails closed)', { signal });
    const force = setTimeout(() => {
      server.forceShutdown();
      gate.close();
      process.exit(0);
    }, 10_000);
    force.unref();
    server.tryShutdown(() => {
      gate.close();
      process.exit(0);
    });
  };
  process.on('SIGINT', () => stop('SIGINT'));
  process.on('SIGTERM', () => stop('SIGTERM'));
}

function check(args) {
  const out = {};
  const file = option(args, '--config');
  if (file) {
    const config = loadGateConfig(file);
    out.config = {
      ok: true,
      listen: config.listen,
      transport: config.insecure ? 'plaintext' : 'tls',
      token_checks: Boolean(config.auth),
      records_dir: config.recordsDir,
      rotate_after_records: config.rotateAfterRecords,
      grants: config.grants.map((grant) => ({ route_id: grant.route_id, granted_by: grant.granted_by, sandboxes: grant.sandboxes, actions: grant.actions, expires_at: grant.expires_at })),
    };
  }
  const policyFile = option(args, '--policy');
  if (policyFile) {
    const checked = validatePolicyConfig(JSON.parse(readFileSync(policyFile, 'utf8')));
    out.policy = checked.ok ? { ok: true, rules: checked.policy.rules.length, unmatched: checked.policy.unmatched ?? 'deny' } : { ok: false, reason: checked.reason };
    const request = option(args, '--request');
    if (request && checked.ok) {
      const [method, url] = request.trim().split(/\s+/, 2);
      const parsed = new URL(url);
      out.request = classifyRequest(checked.policy, { method, host: parsed.hostname, path: parsed.pathname });
    }
  }
  if (!file && !policyFile) throw new Error('check needs --config, --policy or both.');
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
  if (out.policy && !out.policy.ok) process.exitCode = 1;
}

function verify(args) {
  const file = args.find((arg) => !arg.startsWith('--'));
  if (!file) throw new Error('verify needs a records file.');
  const signer = option(args, '--signer');
  const text = readFileSync(file, 'utf8');
  const lines = text.split('\n');
  const complete = lines.pop() === '';
  const records = [];
  for (const [index, line] of lines.entries()) {
    try {
      records.push(JSON.parse(line));
    } catch {
      process.stdout.write(`${JSON.stringify({ valid: false, reason: `line ${index + 1} is not a JSON record` })}\n`);
      process.exitCode = 1;
      return;
    }
  }
  const result = new LocalImmaculateEngine().verifyChain({ records, ...(signer ? { expected_signer_kid: signer } : {}) });
  const decisions = records.filter((record) => record.record_type === DECISION_RECORD);
  const summary = {
    ...result,
    records: records.length,
    signer_kid: records[0]?.signer_kid ?? null,
    last_line_complete: complete,
    decisions: decisions.length,
    continued: decisions.filter((record) => record.payload?.verdict === 'continue').length,
    denied: decisions.filter((record) => record.payload?.verdict === 'deny').length,
  };
  if (!complete) {
    summary.valid = false;
    summary.reason = `The file ends in a partial line after record ${records.length}: the gate stopped while writing it.`;
  }
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  if (!summary.valid) process.exitCode = 1;
}

const [command, ...rest] = process.argv.slice(2);
const commands = { serve, check, verify };
if (!commands[command]) {
  process.stderr.write('usage: immaculate-openshell-gate serve --config <gate.json>\n'
    + '       immaculate-openshell-gate check [--config <gate.json>] [--policy <config.json> [--request "<METHOD> <url>"]]\n'
    + '       immaculate-openshell-gate verify <records.jsonl> [--signer <kid>]\n');
  process.exit(2);
}
Promise.resolve()
  .then(() => commands[command](rest))
  .catch((error) => {
    process.stderr.write(`${JSON.stringify({ ts: new Date().toISOString(), level: 'error', message: error.message })}\n`);
    process.exit(1);
  });
