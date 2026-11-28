/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Where the gate gets OpenShell's supervisor middleware protocol. The .proto files are OpenShell's (NVIDIA,
 * Apache-2.0) and are not part of this repository: `npm run fetch-protocol` downloads them, with OpenShell's licence,
 * from one pinned upstream commit into ./protocol. Every file is held to its pinned SHA-256 when it is downloaded and
 * again each time the gate loads it, so a changed or partial file stops the gate instead of changing its behaviour.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const PROTOCOL_DIR = fileURLToPath(new URL('../protocol/', import.meta.url));
export const OPENSHELL_REPOSITORY = 'ai-openshell/openshell';
export const OPENSHELL_COMMIT = '659b45f3bed896897de20a8b67289916a3d9fffc';

/** Local name -> upstream path and SHA-256 of the file as published at OPENSHELL_COMMIT. */
export const PROTOCOL_FILES = Object.freeze({
  'supervisor_middleware.proto': { upstream: 'proto/supervisor_middleware.proto', sha256: '62716896a688dafce2b221624d6e603379226e09dfc78dfc3417f614d46cd559' },
  'extension.proto': { upstream: 'proto/extension.proto', sha256: '60f28ee9dc846d41152f4db7e82a439c78d024786efaceb464900d1d1ad129ad' },
  LICENSE: { upstream: 'LICENSE', sha256: 'd07c0367e2861e7fe70fa1b679f879f4fa2f9138ade4457d44ecf8b2e135bb45' },
});

export function upstreamUrl(upstreamPath) {
  return `https://raw.githubusercontent.com/${OPENSHELL_REPOSITORY}/${OPENSHELL_COMMIT}/${upstreamPath}`;
}

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** What is wrong with the protocol files on disk: [] when every file is there with its pinned digest. */
export function protocolProblems(dir = PROTOCOL_DIR) {
  const problems = [];
  for (const [name, { sha256: expected }] of Object.entries(PROTOCOL_FILES)) {
    let bytes;
    try {
      bytes = readFileSync(path.join(dir, name));
    } catch {
      problems.push(`${name} is missing`);
      continue;
    }
    if (sha256(bytes) !== expected) problems.push(`${name} does not match its pinned SHA-256`);
  }
  return problems;
}

/** Throws, saying how to fix it, unless every protocol file is there with its pinned digest. */
export function assertProtocolFiles(dir = PROTOCOL_DIR) {
  const problems = protocolProblems(dir);
  if (problems.length) {
    throw new Error(`OpenShell protocol files in ${dir}: ${problems.join('; ')}. Run "npm run fetch-protocol" in integrations/openshell.`);
  }
}
