/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * Learned escalation for arobi_classify_and_route, after RouteLLM (Ong et al., "RouteLLM: Learning to Route LLMs with
 * Preference Data", ICLR 2025, arXiv:2406.18665). Two parts, as in the paper:
 *  - a win-prediction model P(strong wins | q): the chance the dearer candidate's answer beats the cheapest capable
 *    one on this request, estimated by the paper's similarity-weighted ranking (Sec. 4.2): past evidence is weighted
 *    by how similar its request was, with exponential weights 10 * 10^(sim / max_sim) as in the reference code;
 *  - a cost threshold alpha: escalate only when P(strong wins) >= alpha (Eq. 2). alpha can be set directly or derived
 *    from a target share of strong calls, as the reference calibrate_threshold does (the (1 - rate) quantile of past
 *    win probabilities).
 *
 * Unlike the paper, nothing here reads or keeps prompt text. A request is represented by sixteen content-free numbers
 * (routeFeatures); only those numbers and outcomes are remembered. Pure functions, no I/O, deterministic.
 *
 * Feature sets. 1.3.0 kept eight numbers (FEATURE_NAMES_V1). 1.4.0 appends eight more counts and shares and leaves
 * the first eight unchanged, so an eight-number vector from 1.3.0 is a prefix of its sixteen-number successor and
 * still compares (similarityWeights uses the longest prefix every vector has). The eight new numbers were frozen
 * before they were tested on data they were not designed against (bench/route-escalation).
 */

export const FEATURE_NAMES_V1 = Object.freeze([
  'length', 'code', 'math', 'deep_reasoning', 'task', 'structured_output', 'multi_question', 'non_ascii',
]);
export const FEATURE_NAMES = Object.freeze([
  ...FEATURE_NAMES_V1,
  'numbers', 'sentences', 'negation', 'lettered_choices', 'long_words', 'word_length', 'capitals', 'line_breaks',
]);
export const FEATURE_COUNT_V1 = FEATURE_NAMES_V1.length;
export const FEATURE_COUNT = FEATURE_NAMES.length;

const HIGH_SIGNALS = /(architect|proof|cryptograph|security audit|distributed|concurrent|formal|migration|multi-step|incident)/;
const MEDIUM_SIGNALS = /(refactor|implement|analy[sz]e|debug|compare|design|summari[sz]e|test suite|sql)/;

/** The request as sixteen numbers in [0, 1]; the text itself is never kept. */
export function routeFeatures(prompt) {
  const text = String(prompt ?? '');
  const lower = text.toLowerCase();
  const words = text.match(/[A-Za-zÀ-ɏ]+/g) ?? [];
  const letters = words.reduce((s, w) => s + w.length, 0);
  const cap = (x) => Math.min(1, Math.max(0, x));
  return [
    Math.min(1, Math.log10(1 + text.length) / 4),
    /```|\bfunction\b|\bclass\b|=>|\bdef \w+\(|\bimport \w|#include|\bSELECT\b/.test(text) ? 1 : 0,
    /\d\s*[-+*/^=]\s*\d|\bequation|\bprove\b|\bintegral|\bderivative|\bprobabilit/i.test(text) ? 1 : 0,
    HIGH_SIGNALS.test(lower) ? 1 : 0,
    MEDIUM_SIGNALS.test(lower) ? 1 : 0,
    /\bjson\b|\bschema\b|\byaml\b|\bcsv\b/i.test(text) ? 1 : 0,
    (text.match(/\?/g) ?? []).length > 1 ? 1 : 0,
    /[^\x00-\x7f]/.test(text) ? 1 : 0,
    // 1.4.0: counts and shares, each capped to [0, 1].
    cap((text.match(/\d+(?:\.\d+)?/g) ?? []).length / 20), // numbers in the request
    cap((text.match(/[.!?](\s|$)/g) ?? []).length / 20), // sentences
    /\b(not|except|least|false|incorrect|never)\b/i.test(text) ? 1 : 0, // negation or exception wording
    (text.match(/^\s*[A-H][.)]\s/gm) ?? []).length >= 3 ? 1 : 0, // a lettered list of choices
    words.length ? cap((words.filter((w) => w.length >= 10).length / words.length) * 5) : 0, // long-word share
    words.length ? cap(letters / words.length / 10) : 0, // mean word length
    text.length ? cap(((text.match(/[A-Z]/g) ?? []).length / text.length) * 10) : 0, // capitals share
    cap(Math.log10(1 + (text.match(/\n/g) ?? []).length) / 2), // line breaks
  ];
}

/** The complexity label this tool has always reported, now derived from the same features. */
export function complexityOf(prompt, features = routeFeatures(prompt)) {
  const length = String(prompt ?? '').length;
  if (length > 600 || features[3] === 1) return 'high';
  if (length > 160 || features[4] === 1) return 'medium';
  return 'low';
}

/** A prior P(strong wins) for when there is no evidence yet: a stated guess from complexity, never learned. */
export const COMPLEXITY_PRIOR = Object.freeze({ low: 0.25, medium: 0.5, high: 0.75 });

/** Sixteen numbers in [0, 1], or the eight a 1.3.0 decision recorded. */
export function isFeatureVector(value) {
  return Array.isArray(value) && (value.length === FEATURE_COUNT || value.length === FEATURE_COUNT_V1)
    && value.every((x) => typeof x === 'number' && Number.isFinite(x) && x >= 0 && x <= 1);
}

/**
 * An evidence scope: a short lowercase label the caller chooses for one population of similar requests (a product
 * surface, a workflow, a benchmark subject), for example 'support:refunds' or 'mmlu/college_physics'. With a scope,
 * a request is estimated only from evidence recorded under the same scope. On RouteLLM's public outcomes that is what
 * makes the estimate better than chance (bench/route-escalation). A scope is a label, never personal data.
 */
export const SCOPE_PATTERN = /^[a-z0-9][a-z0-9._:/-]{0,63}$/;

export function isScopeLabel(value) {
  return typeof value === 'string' && SCOPE_PATTERN.test(value);
}

/** The evidence a request may be estimated from: everything without a scope, else only that scope's. */
export function evidenceInScope(evidence, scope) {
  return scope === undefined ? evidence : evidence.filter((item) => item.scope === scope);
}

function cosine(a, b, dims) {
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < dims; i += 1) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) return na === nb ? 1 : 0;
  return dot / Math.sqrt(na * nb);
}

/**
 * Similarity weights for each evidence item, as RouteLLM's SW ranking: 10 * 10^(sim / max_sim). An item identical to
 * the request weighs 100, an unrelated one 10, so near evidence dominates without far evidence being thrown away.
 * Vectors are compared on the longest prefix all of them have: all sixteen numbers, or the first eight when any item
 * was recorded by 1.3.0, so that evidence keeps counting on the features it was recorded with.
 */
export function similarityWeights(features, evidence) {
  const dims = evidence.reduce((d, item) => Math.min(d, item.features.length), features.length);
  const sims = evidence.map((item) => cosine(features, item.features, dims));
  const maxSim = Math.max(...sims, 0);
  return sims.map((sim) => (maxSim > 0 ? 10 * 10 ** (sim / maxSim) : 10));
}

/**
 * P(strong wins | request) for one cheapest/strong pair from the evidence about those two candidates.
 *  - Pairwise evidence {features, winner_id, loser_id} or {features, tie: [a, b]}: a weighted win share, ties as half
 *    (the Bradley-Terry estimate for two players), smoothed by one virtual tie.
 *  - Outcome evidence {features, candidate_id, quality in [0, 1]}: weighted, Beta(1, 1)-smoothed success of each
 *    candidate; for independent outcomes P(strong better) + P(tie) / 2 = 0.5 + (s_strong - s_weak) / 2.
 * The two are mixed by their evidence mass. With no evidence about the pair, the complexity prior answers, and
 * the source says so.
 */
export function winProbability({ features, weakId, strongId, evidence, complexity }) {
  const relevant = evidence.filter((item) => {
    if (item.kind === 'pair') return [weakId, strongId].includes(item.a) && [weakId, strongId].includes(item.b) && item.a !== item.b;
    return item.candidate_id === weakId || item.candidate_id === strongId;
  });
  if (relevant.length === 0) {
    return { p: COMPLEXITY_PRIOR[complexity] ?? 0.5, source: 'complexity_prior', pair_evidence: 0, outcome_evidence: 0 };
  }
  const weights = similarityWeights(features, relevant);
  let pairWins = 0;
  let pairMass = 0;
  const success = { [weakId]: { ok: 0, mass: 0 }, [strongId]: { ok: 0, mass: 0 } };
  let pairCount = 0;
  let outcomeCount = 0;
  relevant.forEach((item, i) => {
    const w = weights[i];
    if (item.kind === 'pair') {
      pairCount += 1;
      pairMass += w;
      if (item.tie) pairWins += w / 2;
      else if (item.a === strongId) pairWins += w; // a is the winner
    } else {
      outcomeCount += 1;
      success[item.candidate_id].ok += w * item.quality;
      success[item.candidate_id].mass += w;
    }
  });
  const pPair = (pairWins + 0.5 * 10) / (pairMass + 10);
  const sWeak = (success[weakId].ok + 10) / (success[weakId].mass + 20);
  const sStrong = (success[strongId].ok + 10) / (success[strongId].mass + 20);
  const pOutcome = 0.5 + (sStrong - sWeak) / 2;
  const outcomeMass = Math.min(success[weakId].mass, success[strongId].mass);
  let p;
  let source;
  if (pairCount > 0 && outcomeCount > 0 && outcomeMass > 0) {
    p = (pPair * pairMass + pOutcome * outcomeMass) / (pairMass + outcomeMass);
    source = 'similarity_weighted_pairs_and_outcomes';
  } else if (pairCount > 0) {
    p = pPair;
    source = 'similarity_weighted_pairs';
  } else if (outcomeMass > 0) {
    p = pOutcome;
    source = 'similarity_weighted_outcomes';
  } else {
    // Outcomes about only one of the two candidates say nothing about which wins.
    return { p: COMPLEXITY_PRIOR[complexity] ?? 0.5, source: 'complexity_prior', pair_evidence: pairCount, outcome_evidence: outcomeCount };
  }
  return { p: Number(Math.min(1, Math.max(0, p)).toFixed(4)), source, pair_evidence: pairCount, outcome_evidence: outcomeCount };
}

/**
 * The cost threshold for a target share of strong calls: the (1 - rate) quantile of past win probabilities, as
 * RouteLLM's calibrate_threshold. Returns null until there are at least `minScores` past probabilities.
 */
export function thresholdForStrongRate(scores, rate, minScores = 20) {
  if (!Array.isArray(scores) || scores.length < minScores || !(rate >= 0 && rate <= 1)) return null;
  const sorted = [...scores].sort((a, b) => a - b);
  const q = 1 - rate;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  const value = sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
  return Number(value.toFixed(4));
}

/** Normalise caller-supplied history into evidence items; anything malformed is refused, never guessed. */
export function evidenceFromHistory(history) {
  if (history === undefined) return [];
  if (!Array.isArray(history)) throw new Error('preference_history must be an array.');
  if (history.length > 5000) throw new Error('preference_history holds at most 5000 items.');
  return history.map((item, i) => {
    if (!item || typeof item !== 'object' || !isFeatureVector(item.features)) {
      throw new Error(`preference_history[${i}].features must be ${FEATURE_COUNT} numbers in [0, 1] (or the ${FEATURE_COUNT_V1} a 1.3.0 answer reported).`);
    }
    if (item.scope !== undefined && !isScopeLabel(item.scope)) {
      throw new Error(`preference_history[${i}].scope must be a lowercase label of 1 to 64 characters (a-z, 0-9, . _ : / -), starting with a letter or digit.`);
    }
    // The scope rides along only when given, so unscoped history is exactly as before.
    const scoped = item.scope === undefined ? {} : { scope: item.scope };
    if (typeof item.winner_id === 'string' && typeof item.loser_id === 'string') {
      return { kind: 'pair', features: item.features, a: item.winner_id, b: item.loser_id, tie: false, ...scoped };
    }
    if (Array.isArray(item.tie) && item.tie.length === 2 && item.tie.every((id) => typeof id === 'string')) {
      return { kind: 'pair', features: item.features, a: item.tie[0], b: item.tie[1], tie: true, ...scoped };
    }
    if (typeof item.candidate_id === 'string' && typeof item.quality === 'number' && item.quality >= 0 && item.quality <= 1) {
      return { kind: 'outcome', features: item.features, candidate_id: item.candidate_id, quality: item.quality, ...scoped };
    }
    throw new Error(`preference_history[${i}] needs winner_id and loser_id, tie [a, b], or candidate_id with quality in [0, 1].`);
  });
}
