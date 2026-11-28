#!/usr/bin/env node
/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Downloads OpenShell's supervisor middleware protocol files and OpenShell's licence from the commit pinned in
 * src/protocol.mjs into ./protocol, over HTTPS, and keeps each one only if its SHA-256 is the pinned one. Files already
 * there with the right digest are not downloaded again.
 *   node scripts/fetch-protocol.mjs
 */

import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import path from 'node:path';

import { OPENSHELL_COMMIT, PROTOCOL_DIR, PROTOCOL_FILES, sha256, upstreamUrl } from '../src/protocol.mjs';

const MAX_BYTES = 1024 * 1024;
const TIMEOUT_MS = 15_000;

function download(url) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { timeout: TIMEOUT_MS }, (response) => {
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`${url} answered ${response.statusCode}`));
        return;
      }
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BYTES) {
          request.destroy(new Error(`${url} is larger than ${MAX_BYTES} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve(Buffer.concat(chunks)));
      response.on('error', reject);
    });
    request.on('timeout', () => request.destroy(new Error(`${url} did not answer within ${TIMEOUT_MS} ms`)));
    request.on('error', reject);
  });
}

async function main() {
  mkdirSync(PROTOCOL_DIR, { recursive: true });
  let fetched = 0;
  for (const [name, { upstream, sha256: expected }] of Object.entries(PROTOCOL_FILES)) {
    const target = path.join(PROTOCOL_DIR, name);
    if (existsSync(target) && sha256(readFileSync(target)) === expected) continue;
    const url = upstreamUrl(upstream);
    const bytes = await download(url);
    const actual = sha256(bytes);
    if (actual !== expected) throw new Error(`${url} has SHA-256 ${actual}, not the pinned ${expected}; nothing was written for it.`);
    const partial = `${target}.partial`;
    writeFileSync(partial, bytes);
    rmSync(target, { force: true });
    renameSync(partial, target);
    fetched += 1;
  }
  process.stdout.write(`OpenShell protocol at ${OPENSHELL_COMMIT.slice(0, 12)}: ${Object.keys(PROTOCOL_FILES).length} files checked, ${fetched} downloaded, in ${PROTOCOL_DIR}\n`);
}

main().catch((error) => {
  process.stderr.write(`fetch-protocol: ${error.message}\n`);
  process.exit(1);
});
