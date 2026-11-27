// The Official MCP Registry entry (server.json) against the registry's own limits, so a release tag never reaches a
// publish the registry refuses. The v1.4.0 publish (2026-11-27) failed with 422 "expected length <= 100" on
// body.description after the description grew to 116 characters; the registry checks this only at publish time.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const entry = JSON.parse(readFileSync(new URL('../server.json', import.meta.url), 'utf8'));

test('server.json fits the registry: description at most 100 characters, a semver version, an https remote', () => {
  assert.equal(typeof entry.description, 'string');
  assert.ok(entry.description.length > 0 && entry.description.length <= 100, `description is ${entry.description.length} characters`);
  assert.match(entry.version, /^\d+\.\d+\.\d+$/);
  assert.match(entry.name, /^io\.github\.Arobi-Technology-Alliance-Lab\/[a-z0-9-]+$/);
  assert.ok(Array.isArray(entry.remotes) && entry.remotes.length > 0);
  for (const remote of entry.remotes) assert.match(remote.url, /^https:\/\//);
});
