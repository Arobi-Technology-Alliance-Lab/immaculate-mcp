/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Learned escalation (after RouteLLM, arXiv:2406.18665): a dearer capable candidate is paid for only when its
 * predicted chance of beating the cheapest capable one on this request reaches the cost threshold.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { LocalImmaculateEngine } from '../src/engine.mjs';
import {
  COMPLEXITY_PRIOR, FEATURE_COUNT, routeFeatures, thresholdForStrongRate, winProbability, evidenceFromHistory,
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

test('the request becomes eight content-free numbers, and nothing of its text is sealed', () => {
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
  assert.throws(() => evidenceFromHistory([{ features: [1, 2], winner_id: 'a', loser_id: 'b' }]), /features must be 8 numbers/);
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

test('target_strong_rate calibrates the threshold from the run\'s own win probabilities (the 1 - rate quantile)', () => {
  assert.equal(thresholdForStrongRate([0.1, 0.2], 0.5), null);
  const scores = Array.from({ length: 21 }, (_, i) => i / 20);
  assert.equal(thresholdForStrongRate(scores, 0.25), 0.75);
  const engine = new LocalImmaculateEngine();
  let last;
  for (let i = 0; i < 24; i += 1) {
    const prompt = i % 2 ? `Security audit number ${i} of a distributed system` : `Say hello ${i}`;
    last = engine.classifyAndRoute({ prompt, candidates, escalation: { target_strong_rate: 0.5 }, record: false });
  }
  assert.equal(last.escalation.cost_threshold_source, 'calibrated_to_target_strong_rate');
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
