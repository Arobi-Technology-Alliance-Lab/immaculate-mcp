#!/usr/bin/env node
/**
 * Arobi Immaculate MCP — stdio-to-Streamable-HTTP transport bridge.
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved. Arobi Proprietary License (see LICENSE).
 *
 * Bridges local stdio MCP clients (and container-based MCP inspectors) to the
 * hosted Arobi Immaculate Streamable HTTP endpoint (https://aura-genesis.org/api/v1/mcp).
 *
 * Environment variables:
 *   AROBI_TENANT_KEY  Optional for initialize / tools/list introspection; required for metered tools/call.
 *   AROBI_MCP_URL     Override endpoint URL (defaults to https://aura-genesis.org/api/v1/mcp).
 */

import readline from 'node:readline';

const ENDPOINT = (process.env.AROBI_MCP_URL || 'https://aura-genesis.org/api/v1/mcp').trim();
const TENANT_KEY = (process.env.AROBI_TENANT_KEY || '').trim();
let sessionId = null;

function writeMessage(obj) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
}

function parseSseJson(text) {
  const events = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('data:')) {
      const payload = line.slice(5).trim();
      if (!payload || payload === '[DONE]') continue;
      try {
        events.push(JSON.parse(payload));
      } catch {
        // Ignore non-JSON SSE keepalive lines
      }
    }
  }
  return events;
}

async function forwardRequest(msg) {
  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
    'User-Agent': 'arobi-immaculate-mcp-bridge/1.0.0',
  };
  if (TENANT_KEY) {
    headers['X-Arobi-Tenant-Key'] = TENANT_KEY;
  }
  if (sessionId) {
    headers['Mcp-Session-Id'] = sessionId;
  }

  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers,
    body: JSON.stringify(msg),
  });

  const nextSession = res.headers.get('mcp-session-id');
  if (nextSession) sessionId = nextSession;

  if (msg.id === undefined) {
    // JSON-RPC notification: no response expected
    return;
  }

  const contentType = (res.headers.get('content-type') || '').toLowerCase();
  const raw = await res.text();

  if (!res.ok) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.jsonrpc === '2.0') {
        writeMessage({ ...parsed, id: msg.id });
        return;
      }
    } catch {
      // Fall through to generic JSON-RPC error
    }
    writeMessage({
      jsonrpc: '2.0',
      id: msg.id,
      error: {
        code: res.status === 401 || res.status === 403 ? -32001 : -32000,
        message: `Upstream Immaculate MCP returned HTTP ${res.status}: ${raw.slice(0, 300)}`,
      },
    });
    return;
  }

  if (contentType.includes('text/event-stream')) {
    const events = parseSseJson(raw);
    for (const ev of events) writeMessage(ev);
    return;
  }

  if (raw.trim()) {
    const parsed = JSON.parse(raw);
    writeMessage(parsed);
  }
}

async function handleLine(line) {
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

  // Handle MCP ping locally for fast liveness checks
  if (msg.method === 'ping' && msg.id !== undefined) {
    writeMessage({ jsonrpc: '2.0', id: msg.id, result: {} });
    return;
  }

  // Skip forwarding notifications that have no upstream side effects
  if (msg.method === 'notifications/initialized' && msg.id === undefined) {
    return;
  }

  try {
    await forwardRequest(msg);
  } catch (err) {
    if (msg.id !== undefined) {
      writeMessage({
        jsonrpc: '2.0',
        id: msg.id,
        error: {
          code: -32603,
          message: `Bridge transport error: ${err instanceof Error ? err.message : String(err)}`,
        },
      });
    }
  }
}

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
});

// Serialize message handling to preserve JSON-RPC ordering
let queue = Promise.resolve();
rl.on('line', (line) => {
  queue = queue.then(() => handleLine(line));
});

rl.on('close', () => {
  queue.finally(() => process.exit(0));
});
