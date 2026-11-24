/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Learned escalation (after RouteLLM, arXiv:2406.18665): a dearer capable candidate is paid for only when its
 * predicted chance of beating the cheapest capable one on this request reaches the cost threshold.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { LocalImmaculateEngine } from '../src/engine.mjs';
import { readFileSync } from 'node:fs';
import {
  COMPLEXITY_PRIOR, FEATURE_COUNT, FEATURE_COUNT_V1, FEATURE_NAMES, routeFeatures, similarityWeights, thresholdForStrongRate,
  winProbability, evidenceFromHistory,
} from '../src/route-learning.mjs';

const candidates = [
  { id: 'fast-mini', cost_per_1k_prompt_usd: 0.0005, cost_per_1k_completion_usd: 0.001, capabilities: ['json', 'tools'] },
  { id: 'frontier-pro', cost_per_1k_prompt_usd: 0.005, cost_per_1k_completion_usd: 0.015, capabilities: ['json', 'tools'], observed_success_rate: 0.94, observed_sample_size: 50 },
];
const CODE_PROMPTS = [
  'Refactor this function: ```js\nfunction pay(a){ return a=>a*2 }\n``` and keep the API',
  'Debug this class: ```py\nclass Ledger:\n  def post(self, x): pass\n``` it drops entries',
  'Implement import parsing: ```ts\nimport { a } from "b"\n``` for the build',
  'Fix this SELECT: ```sql\nSELECT * FROM t WHERE a = 1\n``` it is slow',
];
const SIMPLE_PROMPTS = ['Say hello to the team', 'What time zone is Paris in', 'Thank the customer for the order', 'Name three colours'];

test('the request becomes sixteen content-free numbers, and nothing of its text is sealed', () => {
  const f = routeFeatures(CODE_PROMPTS[0]);
  assert.equal(f.length, FEATURE_COUNT);
  assert.ok(f.every((x) => x >= 0 && x <= 1));
  assert.equal(f[1], 1, 'code marker');
  const engine = new LocalImmaculateEngine();
  const out = engine.classifyAndRoute({ prompt: CODE_PROMPTS[0], candidates, escalation: { cost_threshold: 0.9 } });
  const sealed = JSON.stringify(out.record);
  assert.ok(!sealed.includes('function pay'), 'no prompt text in the record');
  assert.deepEqual(out.record.payload.features, f);
  // Without escalation the record is exactly as before: no features, no escalation block.
  const plain = engine.classifyAndRoute({ prompt: 'Summarize ticket #12', candidates });
  assert.equal(plain.record.payload.features, undefined);
  assert.equal(plain.record.payload.escalation, undefined);
  assert.equal(plain.selected.id, 'fast-mini');
});

test('with no evidence the stated complexity prior answers, against the cost threshold', () => {
  const engine = new LocalImmaculateEngine();
  const high = engine.classifyAndRoute({ prompt: 'Security audit of a distributed authorization chain', candidates, escalation: { cost_threshold: 0.7 }, record: false });
  assert.equal(high.escalation.win_probability, COMPLEXITY_PRIOR.high);
  assert.equal(high.escalation.win_probability_source, 'complexity_prior');
  assert.equal(high.selected.id, 'frontier-pro');
  assert.equal(high.justification_type, 'learned_escalation');
  const low = engine.classifyAndRoute({ prompt: 'Say hello', candidates, escalation: { cost_threshold: 0.7 }, record: false });
  assert.equal(low.selected.id, 'fast-mini');
  assert.equal(low.escalation.escalated, false);
});

test('recorded outcomes teach it: code-like requests escalate, simple ones stay on the cheap candidate', () => {
  const engine = new LocalImmaculateEngine();
  // As in RouteLLM, the router ranks requests and the threshold decides where to cut; 0.7 sits between the two groups.
  const esc = { cost_threshold: 0.7 };
  // Training rounds: the cheap candidate fails code-like requests and handles simple ones; the dearer one does both.
  for (const prompt of [...CODE_PROMPTS, ...SIMPLE_PROMPTS]) {
    const routed = engine.classifyAndRoute({ prompt, candidates, escalation: { cost_threshold: 1 } });
    const isCode = CODE_PROMPTS.includes(prompt);
    engine.recordRouteOutcome({ routing_record_hash: routed.record.record_hash, candidate_id: 'fast-mini', ok: !isCode });
    engine.recordRouteOutcome({
      routing_record_hash: routed.record.record_hash, candidate_id: 'frontier-pro', ok: true,
      compared_with: { candidate_id: 'fast-mini', result: isCode ? 'win' : 'tie' },
    });
  }
  const code = engine.classifyAndRoute({ prompt: 'Review this function: ```go\nfunction x(){}\n``` for races', candidates, escalation: esc, record: false });
  assert.equal(code.escalation.win_probability_source, 'similarity_weighted_pairs_and_outcomes');
  assert.ok(code.escalation.win_probability >= 0.8, `code p=${code.escalation.win_probability}`);
  assert.equal(code.selected.id, 'frontier-pro');
  const simple = engine.classifyAndRoute({ prompt: 'Say thanks to the vendor', candidates, escalation: esc, record: false });
  assert.ok(simple.escalation.win_probability < 0.65, `simple p=${simple.escalation.win_probability}`);
  assert.ok(code.escalation.win_probability - simple.escalation.win_probability > 0.2, 'the router separates the two kinds');
  assert.equal(simple.selected.id, 'fast-mini');
});

test('pairwise history from earlier runs counts, weighted by how similar its request was', () => {
  const codeFeatures = routeFeatures(CODE_PROMPTS[1]);
  const simpleFeatures = routeFeatures(SIMPLE_PROMPTS[0]);
  const history = [
    ...Array.from({ length: 6 }, () => ({ features: codeFeatures, winner_id: 'frontier-pro', loser_id: 'fast-mini' })),
    ...Array.from({ length: 6 }, () => ({ features: simpleFeatures, tie: ['frontier-pro', 'fast-mini'] })),
  ];
  const engine = new LocalImmaculateEngine();
  const code = engine.classifyAndRoute({ prompt: CODE_PROMPTS[2], candidates, escalation: { cost_threshold: 0.6 }, preference_history: history, record: false });
  assert.equal(code.selected.id, 'frontier-pro');
  const simple = engine.classifyAndRoute({ prompt: SIMPLE_PROMPTS[3], candidates, escalation: { cost_threshold: 0.6 }, preference_history: history, record: false });
  assert.equal(simple.selected.id, 'fast-mini');
  assert.throws(() => evidenceFromHistory([{ features: [1, 2], winner_id: 'a', loser_id: 'b' }]), /features must be 16 numbers/);
});

test('the capability floor and the premium cap bound every escalation', () => {
  const engine = new LocalImmaculateEngine();
  const strict = engine.classifyAndRoute({
    prompt: 'Security audit of a distributed authorization chain', candidates, required_capabilities: ['json'],
    escalation: { cost_threshold: 0, max_premium_usd: 0.001 }, record: false,
  });
  assert.equal(strict.selected.id, 'fast-mini');
  assert.match(strict.escalation.reason, /premium cap/);
  const named = engine.classifyAndRoute({
    prompt: 'Security audit', candidates: [...candidates, { id: 'vision-only', capabilities: ['vision'], cost_per_1k_prompt_usd: 0.01 }],
    required_capabilities: ['json'], escalation: { cost_threshold: 0, strong_candidate: 'vision-only' }, record: false,
  });
  assert.equal(named.selected.id, 'fast-mini');
  assert.match(named.escalation.reason, /not a capable candidate/);
});

// Evidence that the dearer candidate wins code-like requests and ties simple ones, so estimates rest on evidence.
const TEACHING_HISTORY = [
  ...CODE_PROMPTS.flatMap((p) => [
    { features: routeFeatures(p), candidate_id: 'frontier-pro', quality: 1 },
    { features: routeFeatures(p), candidate_id: 'fast-mini', quality: 0 },
  ]),
  ...SIMPLE_PROMPTS.flatMap((p) => [
    { features: routeFeatures(p), candidate_id: 'frontier-pro', quality: 1 },
    { features: routeFeatures(p), candidate_id: 'fast-mini', quality: 1 },
  ]),
];

test('target_strong_rate calibrates the threshold from the run\'s own evidence-based win probabilities (the 1 - rate quantile)', () => {
  assert.equal(thresholdForStrongRate([0.1, 0.2], 0.5), null);
  const scores = Array.from({ length: 21 }, (_, i) => i / 20);
  assert.equal(thresholdForStrongRate(scores, 0.25), 0.75);
  const engine = new LocalImmaculateEngine();
  const seen = [];
  for (let i = 0; i < 24; i += 1) {
    const prompt = i % 2 ? `${CODE_PROMPTS[i % 4]} (case ${i})` : `${SIMPLE_PROMPTS[i % 4]} ${i}`;
    seen.push(engine.classifyAndRoute({ prompt, candidates, escalation: { target_strong_rate: 0.5 }, preference_history: TEACHING_HISTORY, record: false }));
  }
  // Until 20 evidence-based estimates exist nothing is escalated, however high P is: there is no threshold to guess.
  assert.ok(seen.slice(0, 20).every((r) => r.escalation.cost_threshold_source === 'calibrating_until_20_scores' && r.escalation.escalated === false));
  assert.ok(seen.slice(0, 20).some((r) => r.escalation.win_probability > 0.8), 'warm-up refused even a strong estimate');
  const last = seen[23];
  assert.equal(last.escalation.cost_threshold_source, 'calibrated_to_target_strong_rate');
  assert.equal(typeof last.escalation.cost_threshold, 'number');
  // Estimates that rested on the stated prior never calibrate anything.
  const priorOnly = new LocalImmaculateEngine();
  let prior;
  for (let i = 0; i < 24; i += 1) {
    prior = priorOnly.classifyAndRoute({ prompt: `Security audit number ${i} of a distributed system`, candidates, escalation: { target_strong_rate: 0.5 }, record: false });
  }
  assert.equal(prior.escalation.win_probability_source, 'complexity_prior');
  assert.equal(prior.escalation.cost_threshold_source, 'calibrating_until_20_scores');
  assert.equal(prior.selected.id, 'fast-mini');
});

test('defaults cannot over-pay: escalation needs a stated trade-off', () => {
  const engine = new LocalImmaculateEngine();
  for (const escalation of [{}, { scope: 'support:billing' }, { max_premium_usd: 1 }, { strong_candidate: 'frontier-pro' }]) {
    assert.throws(
      () => engine.classifyAndRoute({ prompt: CODE_PROMPTS[0], candidates, escalation, preference_history: TEACHING_HISTORY, record: false }),
      /escalation needs cost_threshold or target_strong_rate/,
      JSON.stringify(escalation),
    );
  }
  // With evidence that the dearer candidate is ten points better on every request, a threshold of 0.5 buys the
  // premium on all of them; that is a choice the caller must now state, never a default.
  const tenPointsBetter = SIMPLE_PROMPTS.flatMap((q) => [
    { features: routeFeatures(q), candidate_id: 'frontier-pro', quality: 1 },
    { features: routeFeatures(q), candidate_id: 'fast-mini', quality: 0.9 },
  ]);
  const atHalf = SIMPLE_PROMPTS.map((p) => engine.classifyAndRoute({
    prompt: p, candidates, escalation: { cost_threshold: 0.5 }, preference_history: tenPointsBetter, record: false,
  }));
  assert.ok(atHalf.every((r) => r.selected.id === 'frontier-pro'), 'P just above 0.5 escalates everything');
  const twentyPointBar = SIMPLE_PROMPTS.map((p) => engine.classifyAndRoute({
    prompt: p, candidates, escalation: { cost_threshold: 0.6 }, preference_history: tenPointsBetter, record: false,
  }));
  assert.ok(twentyPointBar.every((r) => r.selected.id === 'fast-mini'), 'a 10-point gain does not clear a 20-point bar');
});

test('the sixteen features equal the definition the held-out benchmark measured', () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/route-features-v2.json', import.meta.url), 'utf8'));
  assert.ok(fixture.cases.length >= 20);
  for (const { prompt, features } of fixture.cases) {
    assert.deepEqual(routeFeatures(prompt), features, JSON.stringify(prompt).slice(0, 60));
  }
  assert.equal(FEATURE_NAMES.length, FEATURE_COUNT);
  assert.equal(FEATURE_COUNT, 16);
  assert.equal(FEATURE_COUNT_V1, 8);
});

test('an eight-number history from 1.3.0 still counts, compared on the first eight features', () => {
  const request = routeFeatures(CODE_PROMPTS[2]);
  const old = TEACHING_HISTORY.map((item) => ({ ...item, features: item.features.slice(0, FEATURE_COUNT_V1) }));
  const evidence = evidenceFromHistory(old);
  // Comparing a sixteen-number request with eight-number evidence is exactly comparing their first eight numbers.
  assert.deepEqual(similarityWeights(request, evidence), similarityWeights(request.slice(0, FEATURE_COUNT_V1), evidence));
  // Mixed evidence compares every item on the eight numbers all of them have.
  const mixed = [...evidenceFromHistory(TEACHING_HISTORY.slice(0, 2)), ...evidence];
  const truncated = mixed.map((e) => ({ ...e, features: e.features.slice(0, FEATURE_COUNT_V1) }));
  assert.deepEqual(similarityWeights(request, mixed), similarityWeights(request.slice(0, FEATURE_COUNT_V1), truncated));
  const win = winProbability({ features: request, weakId: 'fast-mini', strongId: 'frontier-pro', evidence, complexity: 'medium' });
  const asBefore = winProbability({ features: request.slice(0, FEATURE_COUNT_V1), weakId: 'fast-mini', strongId: 'frontier-pro', evidence, complexity: 'medium' });
  assert.deepEqual(win, asBefore);
  const engine = new LocalImmaculateEngine();
  const routed = engine.classifyAndRoute({ prompt: CODE_PROMPTS[2], candidates, escalation: { cost_threshold: 0.7 }, preference_history: old, record: false });
  assert.equal(routed.selected.id, 'frontier-pro');
  assert.equal(routed.escalation.outcome_evidence, old.length);
});

test('the win model: outcomes give 0.5 + (s_strong - s_weak) / 2, and no evidence about the pair falls back', () => {
  const f = routeFeatures('x');
  const evidence = [
    ...Array.from({ length: 50 }, () => ({ kind: 'outcome', features: f, candidate_id: 'S', quality: 1 })),
    ...Array.from({ length: 50 }, () => ({ kind: 'outcome', features: f, candidate_id: 'W', quality: 0 })),
  ];
  const win = winProbability({ features: f, weakId: 'W', strongId: 'S', evidence, complexity: 'low' });
  assert.ok(win.p > 0.95, `p=${win.p}`);
  const onlyOne = winProbability({ features: f, weakId: 'W', strongId: 'S', evidence: evidence.slice(0, 5), complexity: 'medium' });
  assert.equal(onlyOne.source, 'complexity_prior');
  assert.equal(onlyOne.p, COMPLEXITY_PRIOR.medium);
});

test('outcomes are refused unless they name this run\'s decision and one of its capable candidates, and the chain still verifies', () => {
  const engine = new LocalImmaculateEngine();
  assert.throws(() => engine.recordRouteOutcome({ routing_record_hash: 'nope', ok: true }), /ROUTING_DECISION this server sealed/);
  const routed = engine.classifyAndRoute({ prompt: 'Summarize ticket #12', candidates, required_capabilities: ['json'] });
  assert.throws(() => engine.recordRouteOutcome({ routing_record_hash: routed.record.record_hash, quality: 1.5 }), /quality must be from 0 to 1/);
  assert.throws(() => engine.recordRouteOutcome({ routing_record_hash: routed.record.record_hash, candidate_id: 'ghost', ok: true }), /not a capable candidate/);
  const out = engine.recordRouteOutcome({ routing_record_hash: routed.record.record_hash, ok: true });
  assert.equal(out.status, 'RECORDED');
  assert.equal(out.candidate_id, 'fast-mini');
  assert.equal(out.record.record_type, 'ROUTE_OUTCOME');
  assert.deepEqual(out.stats.by_candidate['fast-mini'], { n: 1, mean_quality: 1 });
  const verified = engine.verifyChain({ records: engine.chain, expected_signer_kid: engine.signerKid });
  assert.equal(verified.valid, true);
});

test('escalation.scope: a scoped request is estimated only from its own scope\'s evidence', () => {
  const engine = new LocalImmaculateEngine();
  // One prompt, so the eight features cannot tell the two populations apart; only the scope can.
  const prompt = 'Answer the question about the attached ticket';
  for (let i = 0; i < 8; i += 1) {
    for (const scope of ['support:billing', 'support:greetings']) {
      const routed = engine.classifyAndRoute({ prompt, candidates, escalation: { cost_threshold: 1, scope } });
      assert.equal(routed.record.payload.escalation.scope, scope, 'the scope is sealed with the decision');
      // billing: the cheap candidate fails and the dearer one succeeds; greetings: both succeed.
      engine.recordRouteOutcome({ routing_record_hash: routed.record.record_hash, candidate_id: 'fast-mini', ok: scope === 'support:greetings' });
      engine.recordRouteOutcome({ routing_record_hash: routed.record.record_hash, candidate_id: 'frontier-pro', ok: true });
    }
  }
  const esc = (scope) => ({ cost_threshold: 0.6, ...(scope ? { scope } : {}) });
  const billing = engine.classifyAndRoute({ prompt, candidates, escalation: esc('support:billing'), record: false });
  const greetings = engine.classifyAndRoute({ prompt, candidates, escalation: esc('support:greetings'), record: false });
  const pooled = engine.classifyAndRoute({ prompt, candidates, escalation: esc(), record: false });
  assert.equal(billing.escalation.scope, 'support:billing');
  assert.equal(billing.escalation.outcome_evidence, 16, 'only the 16 billing outcomes');
  assert.ok(billing.escalation.win_probability > 0.85, `billing p=${billing.escalation.win_probability}`);
  assert.equal(billing.selected.id, 'frontier-pro');
  assert.ok(Math.abs(greetings.escalation.win_probability - 0.5) < 0.01, `greetings p=${greetings.escalation.win_probability}`);
  assert.equal(greetings.selected.id, 'fast-mini');
  // Unscoped, the two populations pool and the estimate lands between them.
  assert.equal(pooled.escalation.scope, undefined);
  assert.equal(pooled.escalation.outcome_evidence, 32);
  assert.ok(pooled.escalation.win_probability > greetings.escalation.win_probability
    && pooled.escalation.win_probability < billing.escalation.win_probability, `pooled p=${pooled.escalation.win_probability}`);
  // A scope with no evidence of its own falls back to the stated prior, never to another scope's evidence.
  const fresh = engine.classifyAndRoute({ prompt, candidates, escalation: esc('support:refunds'), record: false });
  assert.equal(fresh.escalation.win_probability_source, 'complexity_prior');
});

test('escalation.scope is a lowercase label, refused otherwise, and scoped history counts only in its scope', () => {
  const engine = new LocalImmaculateEngine();
  for (const scope of ['', 'Support', 'a b', '-lead', 'x'.repeat(65), 'mail@example', 7]) {
    assert.throws(() => engine.classifyAndRoute({ prompt: 'hello', candidates, escalation: { scope } }), /escalation\.scope must be/);
  }
  for (const scope of ['a', 'support:refunds', 'mmlu/college_physics', 'v1.2_beta-3']) {
    assert.doesNotThrow(() => engine.classifyAndRoute({ prompt: 'hello', candidates, escalation: { cost_threshold: 0.9, scope }, record: false }));
  }
  assert.throws(() => evidenceFromHistory([{ features: routeFeatures('x'), candidate_id: 'a', quality: 1, scope: 'Bad Scope' }]), /scope must be/);
  const f = routeFeatures('Draft the reply');
  const history = [
    ...Array.from({ length: 10 }, () => ({ features: f, candidate_id: 'frontier-pro', quality: 1, scope: 'legal' })),
    ...Array.from({ length: 10 }, () => ({ features: f, candidate_id: 'fast-mini', quality: 0, scope: 'legal' })),
  ];
  const legal = engine.classifyAndRoute({ prompt: 'Draft the reply', candidates, escalation: { cost_threshold: 0.7, scope: 'legal' }, preference_history: history, record: false });
  assert.equal(legal.selected.id, 'frontier-pro');
  const other = engine.classifyAndRoute({ prompt: 'Draft the reply', candidates, escalation: { cost_threshold: 0.7, scope: 'marketing' }, preference_history: history, record: false });
  assert.equal(other.escalation.win_probability_source, 'complexity_prior', 'legal history does not teach marketing');
  // Without a scope the history pools, exactly as in 1.3.0.
  const pooled = engine.classifyAndRoute({ prompt: 'Draft the reply', candidates, escalation: { cost_threshold: 0.7 }, preference_history: history, record: false });
  assert.equal(pooled.escalation.outcome_evidence, 20);
});

test('target_strong_rate calibrates each scope on its own past win probabilities', () => {
  const engine = new LocalImmaculateEngine();
  for (let i = 0; i < 24; i += 1) {
    engine.classifyAndRoute({ prompt: `Say hello ${i}`, candidates, escalation: { target_strong_rate: 0.5 }, preference_history: TEACHING_HISTORY, record: false });
  }
  const unscoped = engine.classifyAndRoute({ prompt: 'Say hello', candidates, escalation: { target_strong_rate: 0.5 }, preference_history: TEACHING_HISTORY, record: false });
  assert.equal(unscoped.escalation.cost_threshold_source, 'calibrated_to_target_strong_rate');
  const scopedHistory = TEACHING_HISTORY.map((item) => ({ ...item, scope: 'new' }));
  const scoped = engine.classifyAndRoute({ prompt: 'Say hello', candidates, escalation: { target_strong_rate: 0.5, scope: 'new' }, preference_history: scopedHistory, record: false });
  assert.equal(scoped.escalation.cost_threshold_source, 'calibrating_until_20_scores', 'a new scope has no past scores yet');
  assert.equal(scoped.escalation.escalated, false);
});
