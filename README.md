# Arobi Immaculate MCP — Pre-Action AI Governance & Evidence Server

[![Arobi Immaculate MCP connector](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate/badges/score.svg)](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate) [![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/arobi-technology-alliance-lab/immaculate-mcp)

[![Arobi Immaculate MCP server](https://mcprush.com/badge/arobi-immaculate-mcp/card.svg)](https://mcprush.com/to/arobi-immaculate-mcp?ref=badge)

**Official MCP Registry ID:** `io.github.Arobi-Technology-Alliance-Lab/immaculate` · **Glama Remote Connector:** [glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate)

[![Arobi Technology Alliance, Inc.](https://aura-genesis.org/brand/arobi-technology-alliance.jpeg)](https://aura-genesis.org/immaculate/mcp/)

**Arobi Immaculate MCP** is a self-contained, zero-dependency [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server (`stdio` / Docker) built by **[Arobi Technology Alliance, Inc.](https://aura-genesis.org/)**.

It executes **100% locally and offline** using Node.js built-in `node:crypto` (Ed25519 signatures + canonical SHA-256 hash chains) so MCP clients can issue bounded route grants, revoke them before they expire, evaluate pre-action authority checks (**GRANTED**, **DENIED**, or **ESCALATED**), select policy-justified models, and check that a chain of sealed records is intact and who signed it, without an API key or external network calls.

- **Local Implementation:** `src/engine.mjs` + `src/index.mjs` (Node.js ≥ 18, zero external runtime dependencies, includes `Dockerfile` and `npm test`)
- **Hosted Cloud Option (`Streamable HTTP`):** `https://aura-genesis.org/api/v1/mcp` ([Documentation & 110 Free Credits](https://aura-genesis.org/immaculate/mcp/))
- **Published Benchmarks (SHA-256 verifiable):** https://aura-genesis.org/benchmarks/immaculate/
- **Live Service Status:** https://aura-genesis.org/status/

---

## Included Tools & Surface Matrix (Local Engine vs. Hosted Cloud Connector)

To eliminate version ambiguity across MCP directories (Official MCP Registry, Glama, MCP Servers, and TensorBlock), here is the exact tool availability across the **Local Offline Engine (`v1.5.0`, 13 tools)** and the **Hosted Streamable HTTP Connector (`https://aura-genesis.org/api/v1/mcp`, `v1.4.0`, 6 tools: the 5 shared core tools plus `arobi_list_records`)**:

| Tool | Hosted HTTP (`v1.4.0`) | Local Engine (`v1.5.0`) | Purpose |
| :--- | :---: | :---: | :--- |
| `arobi_route_grant` | Yes | Yes | Seals WHO granted WHAT authority to WHICH workflow (`scope.actions`, `scope.category_caps`, `attenuation`, `expires_at`) with an Ed25519 signature and hash-chained `ROUTE_GRANT` record. |
| `arobi_revoke_grant` | Yes (`1.1.0+`) | Yes (`1.2.0+`) | Ends a grant this server sealed before it expires: seals a hash-chained `ROUTE_REVOKE` record, after which `arobi_authorize` **DENIES** the grant (`GRANT_REVOKED`). A grant that is unsigned, signed by another key, sealed with `revocable: false`, expired or already revoked is **REFUSED** with a reason code, and nothing is sealed. |
| `arobi_authorize` | Yes | Yes | Verifies that the grant was sealed by this server and not revoked (an unsigned grant, one signed with any other key, or a revoked one is **DENIED**), then its expiry, action allowlist, category caps, and consequence-tier auth freshness before execution — returning **GRANTED**, **DENIED**, or **ESCALATED** with a hash-chained `AUTHORIZATION` record. |
| `arobi_classify_and_route` | Yes | Yes (`+ learned escalation 1.3.0+`) | Classifies prompt complexity, filters capable candidates, picks the lowest-cost capable model or applies an explicit `quality_exception` uplift rule, detects repeated work, and optionally seals a `ROUTING_DECISION` record. With `escalation` set (local `1.3.0+`), it pays for a dearer capable candidate only when the predicted chance it beats the cheapest capable one **on this request** reaches your cost threshold (learned escalation, below). |
| `arobi_verify_chain` | Yes | Yes | Re-derives canonical SHA-256 `prev_hash` / `record_hash` continuity and Ed25519 signatures across an ordered array of records, checks that they are plain data numbered from 1 with no gap, repeat or reordering, requires one signer for the whole chain (and, with `expected_signer_kid`, the signer you trust), and pinpoints the first broken index and the reason. |
| `arobi_list_records` | Yes (`1.4.0+`) | No | Lists your own workspace's sealed records, newest first (filter by `kind`, `from`/`to`, paged by `limit`/`cursor`): each record's id, kind, SHA-256 digest, when it was sealed and its block in the Arobi ledger. Digests and kinds only, never a record's content; read-only, and it verifies nothing (use `arobi_verify_chain` for that). |
| `arobi_record_route_outcome` | Planned | Yes (`1.3.0+`) | Teaches learned escalation: records how a routed request turned out (`quality` 0 to 1, or `ok`) and, optionally, how it compared with another candidate on the same request. Seals a hash-chained `ROUTE_OUTCOME` record and returns the run's routing stats (escalated share, mean quality per candidate). |
| `arobi_begin_effect` | Planned | Yes (`1.5.0+`) | Starts the effect a **GRANTED** authorization allows and seals `EFFECT_STARTED`. It names the steps, the postcondition a read-back must show, how the effect is undone, a deadline and the cleanup owner, and it returns the attempt number and a lease (partly-run actions, below). |
| `arobi_record_step` | Planned | Yes (`1.5.0+`) | Seals the receipt of one declared step under the attempt's lease: ok or failed, with an optional evidence digest. |
| `arobi_close_effect` | Planned | Yes (`1.5.0+`) | Settles an attempt on its read-back. The engine decides the outcome: **COMMITTED**, **ABORTED** or **PARTIAL** on evidence, **IN_DOUBT** without it. |
| `arobi_claim_effect` | Planned | Yes (`1.5.0+`) | Takes over an **IN_DOUBT** effect under a new lease, to read back its outcome and close it. |
| `arobi_list_open_effects` | Planned | Yes (`1.5.0+`) | Lists every open effect (started, **IN_DOUBT** or **PARTIAL**) with its owner, age, deadline, lease and the receipts that landed. |
| `arobi_compensate` | Planned | Yes (`1.5.0+`) | Starts the compensation of an effect: an authorized effect of its own, linked to the one it undoes, with its own attempt number and lease. |
| `arobi_accept_effect` | Planned | Yes (`1.5.0+`) | A person accepts an **IN_DOUBT** or **PARTIAL** effect as it stands, and `EFFECT_ACCEPTED` is sealed. |

### Learned escalation (after RouteLLM)

`arobi_classify_and_route` always starts from the cheapest capable candidate. With `escalation`, it may pay for a
dearer one, following RouteLLM (Ong et al., *RouteLLM: Learning to Route LLMs with Preference Data*, ICLR 2025,
[arXiv:2406.18665](https://arxiv.org/abs/2406.18665)):

- **Win prediction.** It estimates P(the dearer candidate's answer beats the cheapest capable one's on this request).
  The estimate comes from the evidence recorded with `arobi_record_route_outcome`, plus any `preference_history`
  you pass in, weighted by how similar each past request was. The weights follow the paper's similarity-weighted
  ranking, `10 * 10^(sim / max_sim)`.
  - Pairwise results (win, loss, tie) give a Bradley-Terry-style win share.
  - Single outcomes give `0.5 + (s_dearer - s_cheapest) / 2`, which is the win chance plus half the tie chance when
    the two outcomes are independent.
  - With no evidence about the pair, a stated prior by complexity answers instead (0.25, 0.5 or 0.75), and the result
    says it did.
- **Cost threshold (required).** Give `cost_threshold` or `target_strong_rate`; there is no default.
  - It escalates only when that probability is at least `cost_threshold`. A higher threshold escalates less and saves
    more.
  - Because P = 0.5 + (expected quality gain) / 2, `cost_threshold: 0.6` asks for an expected gain of 20 points on
    requests like this one. A threshold near 0.5 escalates whenever the dearer candidate is better at all, which on
    public benchmarks was 83-100% of requests. That is why 1.4.0 no longer supplies one.
  - Alternatively, give `target_strong_rate`, the share of requests you want escalated. The threshold is then
    calibrated to the `1 - rate` quantile of the run's past evidence-based win probabilities (per scope), as RouteLLM's
    `calibrate_threshold` does. Until there are 20 of them nothing is escalated, and estimates that rested on the
    stated prior never count.
- **Bounds.**
  - It never picks a candidate missing a `required_capabilities` entry.
  - It never exceeds `escalation.max_premium_usd`.
  - It only adds escalation: it never undoes an explicit `quality_exception`.
  - Every decision records the probability, its source, the threshold and its source in the sealed
    `ROUTING_DECISION`.
- **Scope.** Give `escalation.scope`, a short lowercase label for the population a request belongs to (a product
  surface, a workflow, a subject; for example `support:refunds`), and the estimate uses only the evidence recorded
  under that scope. Outcomes recorded for a scoped decision teach only that scope, `preference_history` items can
  carry their `scope`, and `target_strong_rate` calibrates each scope on its own past estimates. A scope with no
  evidence yet answers with the stated prior, never with another scope's evidence. Without a scope, evidence pools as
  in 1.3.0. A scope is a label you choose, never personal data.
- **No prompt text kept.** A request becomes sixteen content-free numbers.
  - 1.3.0's eight: length, code, math, deep-reasoning and task markers, structured output, several questions, and
    non-ASCII text.
  - 1.4.0's eight more counts and shares: numbers, sentences, negation wording, a lettered list of choices,
    long-word share, mean word length, capitals share and line breaks.
  - Only those numbers and the outcomes are remembered. The prompt itself is only hashed, as before.
  - An eight-number vector from 1.3.0 is a prefix of its sixteen-number successor, so 1.3.0 history still compares,
    on the first eight.
- **Measured.** The metric is RouteLLM's APGR (random routing is 0.5, higher is better), under 5-fold
  cross-validation with ties averaged. Each figure carries a 95% interval from a paired bootstrap over the test
  questions (10,000 resamples).
  - **Held out.** SPROUT test (Somerstep et al., [arXiv:2502.03261](https://arxiv.org/abs/2502.03261); 6,637 prompts
    from 20 sources, with judged scores for 13 models). It was fetched only after the sixteen features were frozen,
    and the features were checked byte for byte against the frozen definition. The card states no licence, so it is
    used for evaluation only and never redistributed. The scope is the SPROUT source dataset.

    | Pair (weak to strong) | 1.3.0: eight, pooled | 1.4.0: sixteen, pooled | 1.4.0 with scope | Strong calls for half the gap: 1.3.0 to 1.4.0 with scope |
    | --- | --- | --- | --- | --- |
    | Mixtral 8x7B to GPT-4o | 0.565 [0.550, 0.579] | 0.659 [0.646, 0.671] | 0.707 [0.696, 0.719] | 41.8% [39.1, 44.4] to 25.0% [22.9, 26.6] |
    | GPT-4o mini to GPT-4o | 0.501 [0.440, 0.559] | 0.700 [0.651, 0.751] | 0.812 [0.744, 0.897] | 52.6% [43.0, 62.7] to 11.7% [9.2, 16.1] |
    | Llama 3.1 8B to 70B | 0.527 [0.504, 0.550] | 0.621 [0.601, 0.641] | 0.643 [0.623, 0.663] | 46.2% [41.6, 50.8] to 32.0% [28.8, 34.5] |

    The sixteen features beat the eight on every held-out pair (paired differences +0.094 [0.080, 0.108],
    +0.199 [0.146, 0.260] and +0.094 [0.072, 0.116]), and the scope adds more.

  - **Design data.** `npm run bench:route-escalation` uses RouteLLM's published per-question outcomes: GPT-4 1106
    against Mixtral 8x7B, over MMLU (14,042 questions) and GSM8K (1,319). The eight new features were designed while
    looking at this MMLU data, so read these as in-sample.

    | Router | MMLU APGR | MMLU strong calls for half the gap | GSM8K APGR |
    | --- | --- | --- | --- |
    | Random | 0.500 | 50.0% | 0.500 |
    | 1.3.0: eight features, pooled | 0.496 [0.478, 0.514] | 50.6% [47.9, 53.3] | 0.503 [0.465, 0.541] |
    | 1.4.0: sixteen features, pooled | 0.601 [0.582, 0.620] | 34.2% [31.7, 37.1] | 0.522 [0.482, 0.562] |
    | 1.4.0 with `escalation.scope` = the subject | 0.680 [0.662, 0.701] | 26.3% [23.6, 29.3] | 0.522 [0.482, 0.562] |
    | Oracle (upper bound) | 1.285 [1.242, 1.334] | 6.3% [5.9, 6.6] | 1.125 [1.046, 1.226] |

  - **The reading.**
    - On RouteLLM's MMLU, 1.3.0's eight features route no better than chance; the interval includes 0.5. On held-out
      SPROUT they reach at most 0.565.
    - With a scope, half of MMLU's quality gap comes back with about a quarter of requests on the dearer model,
      instead of half.
    - On GSM8K (one scope), the sixteen features' gain over eight is within noise: the paired difference's interval
      is [-0.002, 0.041].
    - So give each population of requests its own `escalation.scope`.
  - These are in-distribution results. RouteLLM's own tables train on Chatbot Arena data and test out of
    distribution, so they are not directly comparable. `bench/route-escalation/results.json` has every router, metric
    and interval.
- **Across runs.** The evidence lasts for the run, like the signing key. To carry it across runs, keep the `features`
  each answer returns (and the request's `scope`) together with your outcomes, and pass them back as
  `preference_history`. Quality judgments are
  yours: the engine learns from what you record and makes no model calls of its own. Without `escalation`, routing
  and the sealed records are exactly as in 1.2.0, and an unscoped escalation is exactly as in 1.3.0.

### Partly-run actions (effects)

`arobi_authorize` decides before an action runs. The effect tools record what happened after it, in the same hash
chain, so an action that only partly ran is detected, has an owner and can be reversed:

```
AUTHORIZED -> STARTED -> (step receipts) -> COMMITTED | ABORTED | PARTIAL, or IN_DOUBT
                 |                                                      |
                 +-- deadline passes, no close -> IN_DOUBT              +--> COMPENSATED | ACCEPTED
```

**IN_DOUBT is the default.** An effect is COMMITTED, ABORTED or PARTIAL only on a read-back bound to its attempt.
Anything less leaves it IN_DOUBT: open, owned, and its key still fenced.

- **Detect.**
  - Every start names a deadline. An effect still open after it reads **IN_DOUBT** with no call from the executor.
    The sweep runs on every call and every 10 seconds on the server's timer, and the transition is sealed once.
  - Each step leaves its own receipt.
  - A close is checked, not asserted:
    - **COMMITTED** needs a read-back that shows the declared postcondition and an ok receipt for every step.
    - **PARTIAL**: the read-back shows the downstream changed without reaching the postcondition, or reached it
      without every step's receipt.
    - **ABORTED** needs a read-back that shows nothing changed *and* a fence showing the attempt can no longer land:
      - `CONSUMED_NOT_RELEASED`: the digest of the downstream's receipt that it took this attempt and will never
        apply it.
      - `EXPIRED_UNUSED`: its deadline has passed and the read-back was taken after it. This counts only if the start
        said `deadline_enforced_downstream: true`: the executor passes `deadline_at` to the downstream as the call's
        own expiry, and the downstream refuses the attempt after it. Otherwise (the default) the clock proves nothing,
        because a call already in flight to a downstream that never saw the deadline can land after it, and
        `EXPIRED_UNUSED` is refused (`FENCE_NOT_ENFORCED`).
    - **IN_DOUBT** otherwise. "Nothing seen" before the fence is not "nothing happened": a call that timed out may
      still land after the read, and a retry would then apply the effect twice. Without a read-back, an exit status
      or an ok receipt is never an outcome.
  - A read-back counts only if it was taken after the attempt started, not in the future, at most 5 minutes ago, and
    with an evidence digest. The close names the attempt, and the sealed close names the plan digest the start fixed.
- **Own.**
  - The start names the cleanup owner; by default that is the grant's issuer.
  - `arobi_list_open_effects` lists the obligations.
  - While an effect on a key is open, `arobi_authorize` with that `effect_key`, or a new start on it, is **DENIED**
    (`EFFECT_OPEN`) and names the open effect.
- **Attempts and leases.**
  - Each start is one attempt, numbered by the engine, with a lease: a token, a generation, and an end at the
    deadline. Every step receipt and close carries the attempt number and the lease token.
  - A write from an older attempt, under an expired lease or under a replaced lease is refused, never merged. After
    the deadline the executor records nothing more.
  - An IN_DOUBT effect is reconciled under a new lease from `arobi_claim_effect` (15 minutes, the next generation;
    one holder at a time; at most 5 claims, then a person decides). A reconciliation lease reads back and closes; it
    records no steps.
  - Give the downstream the `effect_id` as this attempt's request id, so its own records and a
    `CONSUMED_NOT_RELEASED` receipt name the attempt. Give it `deadline_at` as the call's expiry too, and say
    `deadline_enforced_downstream: true`, only if it refuses the attempt after that.
  - A retry with the same `idempotency_key` replays the start, without the lease, instead of applying it twice. Only
    after that attempt closed ABORTED does the same key start the next attempt, at most 3. A step already recorded ok
    is not recorded again.
- **Reverse.**
  - A start declares `REVERSIBLE` (naming the inverse), `COMPENSABLE` (naming the compensating action) or
    `IRREVERSIBLE`.
  - `arobi_authorize` with `reversal_class: IRREVERSIBLE` is DENIED unless `human_approval` names a person who
    approved it in the last 15 minutes. That is decided before the effect starts, and a held authorization starts
    nothing.
  - A compensation is itself an authorized effect on the same key, with its own attempt number, lease and deadline.
    Authorize it with `compensates_effect_id`, the one authorization an open effect admits on its key. When the
    compensation's read-back shows the earlier state, the original becomes **COMPENSATED**.
  - A compensation starts on the engine's own say-so only once the original can no longer land: every step has an
    ok receipt, or its deadline has passed and the downstream enforces it. While the original could still land
    (always, past the deadline, when the downstream does not enforce it), a compensation starts only with
    `human_approval` from a named person in the last 15 minutes, sealed as `compensating_while_landable` in the
    compensation's start and in `EFFECT_COMPENSATED`. A call of the original still in flight may land after the
    compensation; that is the risk the named person accepted. Never while the original holds a live lease.
  - A compensation that does not settle is IN_DOUBT like any effect. No other compensation of the same effect starts
    until it is settled, and there are at most 3 per effect.
  - No effect or compensation starts under a grant that was revoked or has expired; work already in flight is still
    recorded and read back. Revocation is the stop, and there is no resume: the local engine has no pause.
  - An IRREVERSIBLE effect cannot be compensated. A person may instead close an **IN_DOUBT** or **PARTIAL** effect as
    **ACCEPTED**, and that is sealed too.
  - Accepting closes the obligation, not the outcome. An accepted IN_DOUBT effect is still unknown, and a PARTIAL one
    keeps its receipts. The key stays fenced while the accepted attempt can still land: until its deadline if the
    downstream enforces it, otherwise for the rest of the run.
- **The chain.**
  - Records are plain data (no functions, getters or class instances), numbered from 1 and hash-chained from
    `genesis`. `arobi_verify_chain` refuses a gap, a repeated (forked) record or a reordered sequence.
  - Records that no call returned itself (the overdue sweep's) come back in `also_sealed` with the next result, so a
    client that keeps what it is given holds the whole chain.
  - Lease tokens are never sealed. The idempotency key is sealed only as its sha256.
- **What the local engine can and cannot know.**
  - It does not observe the downstream system. The read-backs, fences and human approvals are what the caller
    reports.
  - The engine checks that they were reported, that they are bound to the attempt and agree with what the start
    declared, and seals them, so a later reader sees exactly what was claimed and when.
  - For approvals and read-backs checked by someone other than the agent's operator, use the hosted service once it
    has these tools; it does not yet.

### The local engine and the hosted service

- **Two implementations.** The local engine is a separate, smaller implementation for offline development, testing and evaluation, and its rules are the ones above (see `src/engine.mjs`). The hosted service applies its own policy and records each decision to your workspace's ledger, so for the same input its verdict can differ from the local engine's.
- **Keys.** The local engine makes a new Ed25519 signing key each time it starts. Its grants are honoured only by the run that sealed them, and every record names its signer in `signer_kid`. A chain shows who signed it only when it is checked against a signer you trust (`expected_signer_kid`); without that, it shows that the chain is intact as signed.
- **Not an independent check.** Whoever runs the local server holds its key and controls what it is told. For decisions that must be checked by someone other than the agent's operator, use the hosted service.
- **Tools.** Both have `arobi_route_grant`, `arobi_revoke_grant`, `arobi_authorize`, `arobi_classify_and_route` and
  `arobi_verify_chain`. The hosted service added `arobi_revoke_grant` in its version 1.1.0 (2026-11-21) and the local
  engine in 1.2.0. The hosted service added `arobi_list_records` in 1.4.0: it lists your workspace's sealed records
  (digests and kinds, never content); the local engine has no list, since its records come back with each decision and
  last for the run. Learned escalation and `arobi_record_route_outcome` are in the local engine from 1.3.0 and not in
  the hosted service yet. The effect tools (partly-run actions) are in the local engine from 1.5.0 and not in the
  hosted service yet. A local revocation, like the local key, lasts for the run that made it:
  a local grant ends when it is revoked, when it expires, or when the run that sealed it stops.
- **Versions.** The two have their own version numbers.
  - `package.json` and the local engine's `serverInfo` carry the local engine's version.
  - `server.json` is the Official MCP Registry entry for the hosted endpoint. Its version is the one the hosted
    endpoint reports in its own `serverInfo`, and the publish workflow refuses any other.
  - The registry's 1.2.0 and 1.3.0 entries were published with local-engine releases while the hosted endpoint still
    reported 1.1.0. They describe the same endpoint, URL and header. The hosted endpoint now reports 1.4.0, and
    `server.json` says 1.4.0 to match; the registry shows 1.4.0 once that version is published.

---

## Run Locally (Node.js ≥ 18)

```bash
git clone https://github.com/Arobi-Technology-Alliance-Lab/immaculate-mcp.git
cd immaculate-mcp
npm test
npm start
```

### Stdio MCP Client Config (Claude Desktop, Cursor, Claude Code, Windsurf)

```json
{
  "mcpServers": {
    "arobi-immaculate": {
      "command": "node",
      "args": ["/absolute/path/to/immaculate-mcp/src/index.mjs"]
    }
  }
}
```

### Run via Docker

```bash
docker build -t arobi-immaculate-mcp .
docker run -i --rm arobi-immaculate-mcp
```

### Use with gnosh

[gnosh](https://github.com/gnosh-ai/gnosh) reads MCP servers in Claude Code's shape, so Immaculate needs no adapter. Add the local engine for every project (gnosh's user scope), then check that gnosh connects to it:

```bash
gnosh mcp add -s user arobi-immaculate -- node /absolute/path/to/immaculate-mcp/src/index.mjs
gnosh mcp list
```

`gnosh mcp list` shows the local engine (`1.5.0`) connected with **13 tools** (the 5 shared core tools plus `arobi_record_route_outcome` and the 7 partly-run effect tools), whereas the hosted connector (`https://aura-genesis.org/api/v1/mcp`, `1.4.0`) exposes **6 tools**: the 5 shared core tools plus `arobi_list_records`. Without `-s user` the server is added for the current folder only (gnosh's local scope). With `-s project` it goes into the project's `.mcp.json`, which gnosh reads once you trust the folder.

To use the hosted connector, pipe the entry in on standard input, so the key never appears on the command line:

```bash
echo '{"type": "http", "url": "https://aura-genesis.org/api/v1/mcp", "headers": {"X-Arobi-Tenant-Key": "${AROBI_TENANT_KEY}"}}' \
  | gnosh mcp add-json -s user arobi-immaculate-cloud -
```

The single quotes keep `${AROBI_TENANT_KEY}` as written. gnosh fills it in from your environment when it connects, so the key itself stays out of the file too.

In a gnosh session each tool is prefixed `mcp__arobi-immaculate__<tool_name>` (all 13 tools on the local engine, or the 6 hosted tools `arobi_authorize`, `arobi_route_grant`, `arobi_revoke_grant`, `arobi_classify_and_route`, `arobi_verify_chain` and `arobi_list_records` on `arobi-immaculate-cloud`). gnosh's `/mcp` shows each server's state.

Checked on 2026-11-21 with gnosh built from its main branch (`b09df22`) on Linux (Ubuntu 24.04) and updated through local engine `1.5.0` (13 tools; hosted connector at `1.1.0` with 5 tools), with gnosh's `mcp.json` keeping the key as `${AROBI_TENANT_KEY}`. gnosh runs on Linux and macOS.

---

## Sandboxes, OpenShell and SAFE

Immaculate MCP decides before an agent acts, so it pairs with sandboxes that run agents in isolation: containerized shells, NVIDIA OpenShell, and the `Ullumii` and `HUE` sandboxes.

1. **Pre-action authority that does not depend on a model (`arobi_route_grant` + `arobi_authorize`):** Authorization decisions are deterministic and independent of LLM reasoning. They separate advisory model output from execution authority, and `IRREVERSIBLE` effects require a person's recent approval.
2. **Content-free routing telemetry:** Routing features are reduced to 16 scalar structural counts and shares. Raw prompt text and lease tokens are never written into sealed records.
3. **Tamper evidence with a stated trust boundary:** Every grant, revocation, authorization, routing decision and effect transition is Ed25519-signed and SHA-256 hash-chained (`arobi_verify_chain`). The README states where the boundary lies: local signing keys belong to the operator's run, while the hosted service keeps records in each workspace's ledger.

### OpenShell supervisor middleware (`integrations/openshell`)

[`integrations/openshell`](integrations/openshell/README.md) runs the local engine as an [OpenShell](https://github.com/ai-openshell/openshell) supervisor middleware. Before a sandboxed agent's HTTP request leaves, and before OpenShell adds credentials, the gate does three things:
1. It classifies the request with the sandbox policy's rules, as an action and a consequence tier.
2. It authorizes the action against the operator's grant for that sandbox, and answers continue or deny. Critical actions are held for a person.
3. It seals every decision and writes it to disk before the answer goes back.

If the gate is down, OpenShell fails closed. The gate is its own package, with the gRPC dependencies, so the MCP server stays dependency-free. OpenShell's protocol files are not stored here: the gate fetches them at a pinned commit and checks each one by SHA-256.

### SAFE (Shared AI Findings Exchange)

[SAFE](https://github.com/OpenSecureAIAlliance/wg-safe/blob/main/SAFE.md) is the Open Secure AI Alliance working group's compact for reporting AI incidents and near misses (version 1.0, 2026-10-21). It sets out reporting duties, notification timelines, evidence preservation and a review framework.

SAFE is not a product certification. Immaculate reports nothing to SAFE on anyone's behalf. Here is where its grants and sealed records line up with what SAFE asks for:

- **Approved scope.** SAFE defines approved scope as the authorization an accountable principal gives: permitted actions, time limits and delegation limits, which neither a task request nor the agent's own interpretation can expand.
  - A route grant records the same things: `granted_by`, `delegated_to`, `scope.actions` and `expires_at`.
  - The server seals it, and `arobi_authorize` honours only grants this server sealed, so an agent cannot write its own grant or widen one.
- **Authorization at commitment.** SAFE's review checks that a consequential action "matches valid authorization at commitment, including delegation, expiry and revocation".
  - `arobi_authorize` checks the grant's signature, revocation, expiry and scope before the action, and seals the decision with the grant it checked.
  - It does not compare the caller with `delegated_to`. The OpenShell gate covers delegation by using only the grant made for the requesting sandbox.
- **Evidence preservation.** SAFE asks for evidence with stable identifiers, collection times, the actor, links to related events and integrity checks, and with no reusable secrets.
  - Every sealed record has its hash and sequence number, a timestamp, the previous record's hash and an Ed25519 signature. Authorization records name the principal and the grant.
  - The OpenShell gate also seals the request id, the sandbox and the originating process. It keeps only digests of paths and queries.
- **Near misses.** SAFE says "material attempts stopped by another control" are to be assessed as near misses.
  - The local engine and the OpenShell gate seal every denial and hold with its reason code, for example `ACTION_OUT_OF_SCOPE` or `immaculate_critical_requires_fresh_auth`.
  - So the operator has the record that assessment needs. Whether an event is reportable, and reporting it, stay the operator's decisions.

SAFE calls for a versioned, machine-readable minimum reporting record. The working group's repository does not publish a schema for it yet (checked 2026-11-28), so Immaculate's records are not in that format.

---

## Optional Managed Cloud Endpoint (Streamable HTTP)

Teams that want persistent multi-tenant cloud storage, dashboards, and hosted Streamable HTTP access can also connect directly to Arobi's hosted connector (`https://aura-genesis.org/api/v1/mcp`, free tier starts with 110 credits at [aura-genesis.org/immaculate/mcp](https://aura-genesis.org/immaculate/mcp/)):

```json
{
  "mcpServers": {
    "arobi-immaculate-cloud": {
      "url": "https://aura-genesis.org/api/v1/mcp",
      "headers": {
        "X-Arobi-Tenant-Key": "<your-arobi-tenant-key>"
      }
    }
  }
}
```

---

## Verification, Scope Boundary & License

Arobi provides technical verification, policy enforcement, and tamper-evident evidence tooling. Arobi is not an insurer or a certification body; licensed insurers, regulators, and independent reviewers retain their own decisions.

Everything in this repository (`src/engine.mjs`, `src/index.mjs`, `integrations/openshell`, tests, `Dockerfile`, manifest, and documentation) is proprietary to **Arobi Technology Alliance, Inc.** under the Arobi Proprietary License (see [LICENSE](./LICENSE)), as is the optional hosted service at `https://aura-genesis.org/api/v1/mcp`. Use is governed by the Arobi Terms of Service.
