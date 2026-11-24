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
 * outcome records (weak right?, strong right?) with its eight content-free features, which is all the engine keeps.
 *
 * In-distribution cross-validation: training and test questions come from the same benchmark. RouteLLM's own tables
 * train on Chatbot Arena data and test out of distribution, so the numbers are not directly comparable.
 *   node bench/route-escalation/fetch-data.mjs && node bench/route-escalation/run.mjs
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { complexityOf, routeFeatures, winProbability } from '../../src/route-learning.mjs';

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

const evidenceOf = (items) => items.flatMap((item) => [
  { kind: 'outcome', features: item.features, candidate_id: 'weak', quality: item.weak },
  { kind: 'outcome', features: item.features, candidate_id: 'strong', quality: item.strong },
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
    learned: new Array(items.length).fill(0),
    learned_within_class: new Array(items.length).fill(0),
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
    const within = new Map([...bySubject].map(([k, v]) => [k, evidenceOf(v)]));
    const classScores = new Map([...bySubject].map(([k, v]) => [k, classScore(v)]));
    items.forEach((item, i) => {
      if (fold[i] !== f) return;
      const input = { features: item.features, weakId: 'weak', strongId: 'strong', complexity: item.complexity };
      scores.class_level[i] = classScores.get(item.subject) ?? 0.5;
      scores.learned[i] = winProbability({ ...input, evidence: all }).p;
      scores.learned_within_class[i] = winProbability({ ...input, evidence: within.get(item.subject) ?? [] }).p;
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
    learned: 'learned escalation as this package runs it: similarity-weighted outcomes from every training question',
    learned_within_class: 'learned escalation with evidence restricted to the same class',
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
    console.log(`  ${name.padEnd(22)} APGR ${m.apgr}  CPT(50%) ${m.cpt50}  CPT(80%) ${m.cpt80}  PGR@20% ${m.pgr_at_20pct_strong}`);
  }
}
