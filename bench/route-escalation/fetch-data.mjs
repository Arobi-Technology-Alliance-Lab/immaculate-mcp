/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Fetch RouteLLM's published per-question outcomes at the pinned commit in data-manifest.json, and refuse any file whose
 * sha256 differs from the manifest. The files are data only: they are parsed as CSV, never executed. They are not
 * redistributed in this repository; the RouteLLM authors publish them under Apache-2.0.
 *   node bench/route-escalation/fetch-data.mjs
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(readFileSync(join(here, 'data-manifest.json'), 'utf8'));
const dataDir = join(here, '.data');
mkdirSync(dataDir, { recursive: true });

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
let fetched = 0;
let kept = 0;
for (const file of manifest.files) {
  const target = join(dataDir, basename(file.path));
  if (existsSync(target) && sha256(readFileSync(target)) === file.sha256) {
    kept += 1;
    continue;
  }
  const url = `https://raw.githubusercontent.com/lm-sys/RouteLLM/${manifest.commit}/${file.path}`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  const digest = sha256(bytes);
  if (digest !== file.sha256) throw new Error(`${file.path}: sha256 ${digest} does not match the manifest`);
  writeFileSync(target, bytes);
  fetched += 1;
}
console.log(`RouteLLM evals at ${manifest.commit.slice(0, 8)}: ${fetched} fetched, ${kept} already present, all verified`);
