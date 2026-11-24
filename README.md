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

## Included Tools (Local Execution)

| Tool | Purpose |
| :--- | :--- |
| `arobi_route_grant` | Seals WHO granted WHAT authority to WHICH workflow (`scope.actions`, `scope.category_caps`, `attenuation`, `expires_at`) with an Ed25519 signature and hash-chained `ROUTE_GRANT` record. |
| `arobi_revoke_grant` | Ends a grant this server sealed before it expires: seals a hash-chained `ROUTE_REVOKE` record, after which `arobi_authorize` **DENIES** the grant (`GRANT_REVOKED`). A grant that is unsigned, signed by another key, sealed with `revocable: false`, expired or already revoked is **REFUSED** with a reason code, and nothing is sealed. |
| `arobi_authorize` | Verifies that the grant was sealed by this server and not revoked (an unsigned grant, one signed with any other key, or a revoked one is **DENIED**), then its expiry, action allowlist, category caps, and consequence-tier auth freshness before execution — returning **GRANTED**, **DENIED**, or **ESCALATED** with a hash-chained `AUTHORIZATION` record. |
| `arobi_classify_and_route` | Classifies prompt complexity, filters capable candidates, picks the lowest-cost capable model or applies an explicit `quality_exception` uplift rule, detects repeated work, and optionally seals a `ROUTING_DECISION` record. With `escalation` set, it pays for a dearer capable candidate only when the predicted chance it beats the cheapest capable one **on this request** reaches your cost threshold (learned escalation, below). |
| `arobi_record_route_outcome` | Teaches learned escalation: records how a routed request turned out (`quality` 0 to 1, or `ok`) and, optionally, how it compared with another candidate on the same request. Seals a hash-chained `ROUTE_OUTCOME` record and returns the run's routing stats (escalated share, mean quality per candidate). |
| `arobi_verify_chain` | Re-derives canonical SHA-256 `prev_hash` / `record_hash` continuity and Ed25519 signatures across an ordered array of records, requires one signer for the whole chain (and, with `expected_signer_kid`, the signer you trust), and pinpoints the first broken index and the reason. |

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
- **Cost threshold.** It escalates only when that probability is at least `cost_threshold`. A higher threshold
  escalates less and saves more. Alternatively, give `target_strong_rate` (the share of requests you want escalated);
  after 20 decisions the threshold is calibrated to the `1 - rate` quantile of the run's past win probabilities, as
  RouteLLM's `calibrate_threshold` does.
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
- **No prompt text kept.** A request becomes eight content-free numbers: length, code, math, deep-reasoning and
  task markers, structured output, several questions, and non-ASCII text. Only those numbers and the outcomes are
  remembered. The prompt itself is only hashed, as before.
- **Measured.** `npm run bench:route-escalation` runs the rule on RouteLLM's published per-question outcomes. Those
  record whether each model answered correctly: GPT-4 1106 against Mixtral 8x7B, over MMLU (14,042 questions) and
  GSM8K (1,319). It uses RouteLLM's metric, APGR, where random routing is 0.5, under 5-fold cross-validation:

  | Router | MMLU APGR | MMLU strong calls for half the gap | GSM8K APGR |
  | --- | --- | --- | --- |
  | Random | 0.500 | 50.0% | 0.500 |
  | Learned, eight features, all evidence | 0.496 | 50.6% | 0.503 |
  | Learned, `escalation.scope` = the MMLU subject | 0.677 | 26.2% | 0.503 |
  | Oracle (upper bound) | 1.285 | 6.3% | 1.125 |

  The eight content-free features alone carry almost no signal on these benchmarks: pooled evidence routes no better
  than chance. Evidence scoped to a meaningful domain does: within an MMLU subject, half the quality gap comes back
  with 26% of requests on the dearer model instead of 50%. So give each domain its own `escalation.scope` rather than
  pooling everything. These are in-distribution results. RouteLLM's own tables test
  out of distribution, so the numbers are not directly comparable. `bench/route-escalation/results.json` has every
  router and metric.
- **Across runs.** The evidence lasts for the run, like the signing key. To carry it across runs, keep the `features`
  each answer returns (and the request's `scope`) together with your outcomes, and pass them back as
  `preference_history`. Quality judgments are
  yours: the engine learns from what you record and makes no model calls of its own. Without `escalation`, routing
  and the sealed records are exactly as in 1.2.0, and an unscoped escalation is exactly as in 1.3.0.

### The local engine and the hosted service

- **Two implementations.** The local engine is a separate, smaller implementation for offline development, testing and evaluation, and its rules are the ones above (see `src/engine.mjs`). The hosted service applies its own policy and records each decision to your workspace's ledger, so for the same input its verdict can differ from the local engine's.
- **Keys.** The local engine makes a new Ed25519 signing key each time it starts. Its grants are honoured only by the run that sealed them, and every record names its signer in `signer_kid`. A chain shows who signed it only when it is checked against a signer you trust (`expected_signer_kid`); without that, it shows that the chain is intact as signed.
- **Not an independent check.** Whoever runs the local server holds its key and controls what it is told. For decisions that must be checked by someone other than the agent's operator, use the hosted service.
- **Tools.** Both have `arobi_route_grant`, `arobi_revoke_grant`, `arobi_authorize`, `arobi_classify_and_route` and
  `arobi_verify_chain`. The hosted service added `arobi_revoke_grant` in its version 1.1.0 (2026-11-21) and the local
  engine in 1.2.0. Learned escalation and `arobi_record_route_outcome` are in the local engine from 1.3.0 and not in
  the hosted service yet. A local revocation, like the local key, lasts for the run that made it:
  a local grant ends when it is revoked, when it expires, or when the run that sealed it stops. Neither one lists or
  searches sealed records yet: records come back with each decision, and the hosted service keeps them in your
  workspace's ledger.

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

`gnosh mcp list` should show the server as connected with five tools. Without `-s user` the server is added for the current folder only (gnosh's local scope). With `-s project` it goes into the project's `.mcp.json`, which gnosh reads once you trust the folder.

To use the hosted connector, pipe the entry in on standard input, so the key never appears on the command line:

```bash
echo '{"type": "http", "url": "https://aura-genesis.org/api/v1/mcp", "headers": {"X-Arobi-Tenant-Key": "${AROBI_TENANT_KEY}"}}' \
  | gnosh mcp add-json -s user arobi-immaculate-cloud -
```

The single quotes keep `${AROBI_TENANT_KEY}` as written. gnosh fills it in from your environment when it connects, so the key itself stays out of the file too.

In a gnosh session the tools are named `mcp__arobi-immaculate__arobi_authorize`, `mcp__arobi-immaculate__arobi_route_grant`, `mcp__arobi-immaculate__arobi_revoke_grant`, `mcp__arobi-immaculate__arobi_classify_and_route` and `mcp__arobi-immaculate__arobi_verify_chain`. gnosh's `/mcp` shows each server's state.

Checked on 2026-11-21 with gnosh built from its main branch (`b09df22`) on Linux (Ubuntu 24.04): after the `add` above, `gnosh mcp list` showed `arobi-immaculate` as connected with its four tools (version 1.1.0; 1.2.0 adds `arobi_revoke_grant` as the fifth), and the hosted connector connected the same way, with gnosh's `mcp.json` keeping the key as `${AROBI_TENANT_KEY}`. gnosh runs on Linux and macOS.

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

Everything in this repository (`src/engine.mjs`, `src/index.mjs`, tests, `Dockerfile`, manifest, and documentation) is proprietary to **Arobi Technology Alliance, Inc.** under the Arobi Proprietary License (see [LICENSE](./LICENSE)), as is the optional hosted service at `https://aura-genesis.org/api/v1/mcp`. Use is governed by the Arobi Terms of Service.
