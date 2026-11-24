/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * How well does learned escalation (src/route-learning.mjs) decide, per request, when the dearer model is worth paying
 * for? Measured on RouteLLM's published outcomes (fetch-data.mjs): for every MMLU and GSM8K question, whether Mixtral
 * 8x7B (weak) and GPT-4 1106 (strong) answered correctly.
 *
 * Protocol, as RouteLLM (Ong et al., ICLR 2025, arXiv:2406.18665, Sec. 5): a router scores each question; sending the
 * top share c of questions to the strong model gives accuracy r(c); PGR(c) = (r(c) - r_weak) / (r_strong - r_weak);
 * APGR is the mean PGR over c in [0, 1]; CPT(x) is the smallest strong-call share that reaches PGR x. Random routing
 * scores APGR 0.5. Equal scores are averaged over random tie-breaking, so no router gains from their order.
 * Evidence never crosses folds: 5-fold cross-validation over a seeded shuffle. Each training question contributes two
 * outcome records (weak right?, strong right?) with its content-free features, which is all the engine keeps: the
 * sixteen numbers of 1.4.0, or their first eight, which are exactly what 1.3.0 kept. 95% intervals come from a paired
 * bootstrap over the test questions (the cross-validated scores held fixed).
 *
 * In-distribution cross-validation: training and test questions come from the same benchmark. RouteLLM's own tables
 * train on Chatbot Arena data and test out of distribution, so the numbers are not directly comparable.
 *   node bench/route-escalation/fetch-data.mjs && node bench/route-escalation/run.mjs
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  complexityOf, evidenceInScope, FEATURE_COUNT, FEATURE_COUNT_V1, routeFeatures, winProbability,
} from '../../src/route-learning.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const dataDir = join(here, '.data');
const SEED = 20261124;
const FOLDS = 5;
const WEAK = 'mistralai/Mixtral-8x7B-Instruct-v0.1';
const STRONG = 'gpt-4-1106-preview';

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 1; } else quoted = false;
      } else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') { row.push(field); field = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i += 1;
      row.push(field); rows.push(row); row = []; field = '';
    } else field += ch;
  }
  if (field.length > 0 || row.length > 0) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.length > 1);
}

function load(file, subject) {
  const [header, ...body] = parseCsv(readFileSync(join(dataDir, file), 'utf8'));
  const weakCol = header.indexOf(WEAK);
  const strongCol = header.indexOf(STRONG);
  if (header[0] !== 'prompt' || weakCol < 0 || strongCol < 0) throw new Error(`unexpected header in ${file}`);
  const bool = (v) => {
    if (v === 'True') return 1;
    if (v === 'False') return 0;
    throw new Error(`unexpected value in ${file}`);
  };
  return body.map((r) => {
    const features = routeFeatures(r[0]);
    return { subject, weak: bool(r[weakCol]), strong: bool(r[strongCol]), features, complexity: complexityOf(r[0], features) };
  });
}

function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function foldsOf(n) {
  const order = Array.from({ length: n }, (_, i) => i);
  const random = rng(SEED);
  for (let i = n - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  const fold = new Array(n);
  order.forEach((index, rank) => { fold[index] = rank % FOLDS; });
  return fold;
}

// Each record carries the class as its scope, as arobi_record_route_outcome does for a decision routed with
// escalation.scope; the scoped router then filters with the engine's own evidenceInScope.
const evidenceOf = (items, dims = FEATURE_COUNT) => items.flatMap((item) => [
  { kind: 'outcome', features: item.features.slice(0, dims), candidate_id: 'weak', quality: item.weak, scope: item.subject },
  { kind: 'outcome', features: item.features.slice(0, dims), candidate_id: 'strong', quality: item.strong, scope: item.subject },
]);

/** The information a class-level rule has: 0.5 + (s_strong - s_weak) / 2 over the class, Beta(1, 1)-smoothed. */
function classScore(train) {
  if (train.length === 0) return 0.5;
  const sWeak = (train.reduce((s, i) => s + i.weak, 0) + 1) / (train.length + 2);
  const sStrong = (train.reduce((s, i) => s + i.strong, 0) + 1) / (train.length + 2);
  return 0.5 + (sStrong - sWeak) / 2;
}

function scoreAll(items) {
  const fold = foldsOf(items.length);
  const scores = {
    random: items.map(() => 0.5),
    class_level: new Array(items.length).fill(0),
    learned_v1: new Array(items.length).fill(0),
    learned: new Array(items.length).fill(0),
    learned_v1_scoped: new Array(items.length).fill(0),
    learned_scoped: new Array(items.length).fill(0),
    oracle: items.map((i) => (i.strong > i.weak ? 1 : i.strong < i.weak ? 0 : 0.5)),
  };
  for (let f = 0; f < FOLDS; f += 1) {
    const train = items.filter((_, i) => fold[i] !== f);
    const bySubject = new Map();
    for (const item of train) {
      if (!bySubject.has(item.subject)) bySubject.set(item.subject, []);
      bySubject.get(item.subject).push(item);
    }
    const all = evidenceOf(train);
    const allV1 = evidenceOf(train, FEATURE_COUNT_V1);
    const classScores = new Map([...bySubject].map(([k, v]) => [k, classScore(v)]));
    items.forEach((item, i) => {
      if (fold[i] !== f) return;
      const input = { features: item.features, weakId: 'weak', strongId: 'strong', complexity: item.complexity };
      const inputV1 = { ...input, features: item.features.slice(0, FEATURE_COUNT_V1) };
      scores.class_level[i] = classScores.get(item.subject) ?? 0.5;
      scores.learned_v1[i] = winProbability({ ...inputV1, evidence: allV1 }).p;
      scores.learned[i] = winProbability({ ...input, evidence: all }).p;
      scores.learned_v1_scoped[i] = winProbability({ ...inputV1, evidence: evidenceInScope(allV1, item.subject) }).p;
      scores.learned_scoped[i] = winProbability({ ...input, evidence: evidenceInScope(all, item.subject) }).p;
    });
  }
  return scores;
}

function metrics(items, score) {
  const n = items.length;
  const rWeak = items.reduce((s, i) => s + i.weak, 0) / n;
  const rStrong = items.reduce((s, i) => s + i.strong, 0) / n;
  const order = items.map((_, i) => i).sort((a, b) => score[b] - score[a]);
  const acc = new Array(n + 1);
  let total = items.reduce((s, i) => s + i.weak, 0);
  acc[0] = total / n;
  for (let k = 0; k < n;) {
    let end = k;
    while (end + 1 < n && score[order[end + 1]] === score[order[k]]) end += 1;
    const size = end - k + 1;
    let gain = 0;
    for (let j = k; j <= end; j += 1) gain += items[order[j]].strong - items[order[j]].weak;
    for (let j = 1; j <= size; j += 1) acc[k + j] = (total + (gain * j) / size) / n;
    total += gain;
    k = end + 1;
  }
  const pgr = acc.map((a) => (a - rWeak) / (rStrong - rWeak));
  let area = 0;
  for (let k = 1; k <= n; k += 1) area += (pgr[k - 1] + pgr[k]) / 2;
  const cpt = (x) => {
    const k = pgr.findIndex((p) => p >= x - 1e-12);
    return k < 0 ? null : Number((k / n).toFixed(4));
  };
  return {
    apgr: Number((area / n).toFixed(4)),
    cpt50: cpt(0.5),
    cpt80: cpt(0.8),
    pgr_at_20pct_strong: Number(pgr[Math.round(0.2 * n)].toFixed(4)),
    distinct_scores: new Set(score).size,
  };
}

const BOOT = 300;
const COMPARISONS = [
  ['1.4.0 with scope minus 1.3.0', 'learned_scoped', 'learned_v1'],
  ['sixteen minus eight features, no scope', 'learned', 'learned_v1'],
  ['1.4.0 with scope minus the scope rate alone', 'learned_scoped', 'class_level'],
];

/** APGR and PGR at 20% strong for (weak, strong, score) arrays, ties averaged: metrics() in compact form. */
function apgrOf(weak, strong, score) {
  const n = weak.length;
  let gap = 0;
  for (let i = 0; i < n; i += 1) gap += strong[i] - weak[i];
  const order = Array.from({ length: n }, (_, i) => i).sort((a, b) => score[b] - score[a]);
  const at20 = Math.round(0.2 * n);
  let area = 0;
  let prev = 0;
  let total = 0;
  let pgr20 = 0;
  for (let k = 0; k < n;) {
    let end = k;
    while (end + 1 < n && score[order[end + 1]] === score[order[k]]) end += 1;
    const size = end - k + 1;
    let gain = 0;
    for (let j = k; j <= end; j += 1) gain += strong[order[j]] - weak[order[j]];
    for (let j = 1; j <= size; j += 1) {
      const pgr = (total + (gain * j) / size) / gap;
      area += (prev + pgr) / 2;
      prev = pgr;
      if (k + j === at20) pgr20 = pgr;
    }
    total += gain;
    k = end + 1;
  }
  return { apgr: area / n, pgr20 };
}

/** Paired bootstrap over the test questions: the same resample for every router, the CV scores held fixed. */
function bootstrap(items, scores) {
  const n = items.length;
  const routers = Object.keys(scores).filter((r) => r !== 'random');
  const random = rng(SEED + 7);
  const weak = new Float64Array(n);
  const strong = new Float64Array(n);
  const score = new Float64Array(n);
  for (const r of routers) {
    for (let i = 0; i < n; i += 1) { weak[i] = items[i].weak; strong[i] = items[i].strong; score[i] = scores[r][i]; }
    const full = apgrOf(weak, strong, score);
    if (Math.abs(Number(full.apgr.toFixed(4)) - metrics(items, scores[r]).apgr) > 1e-4) throw new Error(`apgrOf disagrees for ${r}`);
  }
  const draws = Object.fromEntries(routers.map((r) => [r, []]));
  const pick = new Int32Array(n);
  for (let b = 0; b < BOOT; b += 1) {
    for (let i = 0; i < n; i += 1) pick[i] = Math.floor(random() * n);
    for (let i = 0; i < n; i += 1) { weak[i] = items[pick[i]].weak; strong[i] = items[pick[i]].strong; }
    for (const r of routers) {
      for (let i = 0; i < n; i += 1) score[i] = scores[r][pick[i]];
      draws[r].push(apgrOf(weak, strong, score).apgr);
    }
  }
  const ci = (xs) => {
    const sorted = [...xs].sort((a, b) => a - b);
    const q = (p) => sorted[Math.round(p * (sorted.length - 1))];
    return [Number(q(0.025).toFixed(4)), Number(q(0.975).toFixed(4))];
  };
  return {
    resamples: BOOT,
    apgr_95ci: Object.fromEntries(routers.map((r) => [r, ci(draws[r])])),
    paired_differences: COMPARISONS.map(([label, a, b]) => {
      const d = draws[a].map((x, i) => x - draws[b][i]);
      return { comparison: label, a, b, apgr_difference_95ci: ci(d), share_a_better: Number((d.filter((x) => x > 0).length / d.length).toFixed(4)) };
    }),
  };
}

function evaluate(name, items) {
  const scores = scoreAll(items);
  return {
    dataset: name,
    questions: items.length,
    weak_accuracy: Number((items.reduce((s, i) => s + i.weak, 0) / items.length).toFixed(4)),
    strong_accuracy: Number((items.reduce((s, i) => s + i.strong, 0) / items.length).toFixed(4)),
    strong_only_right: items.filter((i) => i.strong > i.weak).length,
    weak_only_right: items.filter((i) => i.weak > i.strong).length,
    distinct_feature_vectors: new Set(items.map((i) => i.features.join(','))).size,
    routers: Object.fromEntries(Object.entries(scores).map(([router, s]) => [router, metrics(items, s)])),
    bootstrap: bootstrap(items, scores),
  };
}

const manifest = JSON.parse(readFileSync(join(here, 'data-manifest.json'), 'utf8'));
const mmluFiles = readdirSync(dataDir).filter((f) => /^mmlu_.*\.csv$/.test(f)).sort();
if (mmluFiles.length !== 57) throw new Error(`expected 57 MMLU files, found ${mmluFiles.length}: run fetch-data.mjs first`);
const results = {
  method: 'RouteLLM protocol (arXiv:2406.18665 Sec. 5); 5-fold CV over a seeded shuffle; ties averaged; in-distribution',
  seed: SEED,
  data: { source: manifest.source, commit: manifest.commit, license: manifest.license, weak: WEAK, strong: STRONG },
  routers: {
    random: 'every question scores 0.5',
    class_level: 'smoothed class-level estimate, class = MMLU subject (GSM8K is one class): what a per-class rule can see',
    learned_v1: '1.3.0: similarity-weighted outcomes from every training question, eight features',
    learned: '1.4.0 without a scope: the same with sixteen features',
    learned_v1_scoped: 'eight features, escalation.scope = the class (evidence from the same class only)',
    learned_scoped: '1.4.0 with escalation.scope = the class: sixteen features, evidence from the same class only',
    oracle: 'upper bound: strong only where it alone is right',
  },
  results: [
    evaluate('mmlu', mmluFiles.flatMap((f) => load(f, f.replace(/^mmlu_|\.csv$/g, '')))),
    evaluate('gsm8k', load('gsm8k_responses.csv', 'gsm8k')),
  ],
};
writeFileSync(join(here, 'results.json'), `${JSON.stringify(results, null, 2)}\n`);
for (const r of results.results) {
  console.log(`${r.dataset}: n=${r.questions} weak=${r.weak_accuracy} strong=${r.strong_accuracy} distinct feature vectors=${r.distinct_feature_vectors}`);
  for (const [name, m] of Object.entries(r.routers)) {
    const ci = r.bootstrap.apgr_95ci[name];
    console.log(`  ${name.padEnd(22)} APGR ${m.apgr}${ci ? ` [${ci[0]}, ${ci[1]}]` : ''}  CPT(50%) ${m.cpt50}  CPT(80%) ${m.cpt80}  PGR@20% ${m.pgr_at_20pct_strong}`);
  }
  for (const d of r.bootstrap.paired_differences) {
    console.log(`  ${d.comparison}: APGR difference 95% CI [${d.apgr_difference_95ci[0]}, ${d.apgr_difference_95ci[1]}], better in ${d.share_a_better} of resamples`);
  }
}
