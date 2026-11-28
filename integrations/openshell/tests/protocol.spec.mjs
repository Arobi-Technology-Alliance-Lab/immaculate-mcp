import assert from 'node:assert/strict';
import { copyFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { assertProtocolFiles, OPENSHELL_COMMIT, PROTOCOL_DIR, PROTOCOL_FILES, protocolProblems, upstreamUrl } from '../src/protocol.mjs';
import { removeDir, tempDir } from './helpers.mjs';

test('the fetched protocol files are there with their pinned digests', () => {
  assert.deepEqual(protocolProblems(), []);
  assert.doesNotThrow(() => assertProtocolFiles());
});

test('a missing or changed protocol file stops the gate, and says how to fix it', () => {
  const dir = tempDir();
  try {
    for (const name of Object.keys(PROTOCOL_FILES)) copyFileSync(path.join(PROTOCOL_DIR, name), path.join(dir, name));
    assert.deepEqual(protocolProblems(dir), []);
    writeFileSync(path.join(dir, 'extension.proto'), 'syntax = "proto3";\n');
    rmSync(path.join(dir, 'LICENSE'));
    assert.deepEqual(protocolProblems(dir), ['extension.proto does not match its pinned SHA-256', 'LICENSE is missing']);
    assert.throws(() => assertProtocolFiles(dir), /npm run fetch-protocol/);
  } finally {
    removeDir(dir);
  }
});

test('downloads come from the pinned commit, never a branch', () => {
  assert.match(OPENSHELL_COMMIT, /^[0-9a-f]{40}$/);
  assert.equal(upstreamUrl('proto/extension.proto'), `https://raw.githubusercontent.com/ai-openshell/openshell/${OPENSHELL_COMMIT}/proto/extension.proto`);
  for (const { sha256 } of Object.values(PROTOCOL_FILES)) assert.match(sha256, /^[0-9a-f]{64}$/);
});
