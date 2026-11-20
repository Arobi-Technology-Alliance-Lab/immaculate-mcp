# Arobi Immaculate MCP — Pre-Action AI Governance & Evidence Server

[![Arobi Immaculate MCP connector](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate/badges/score.svg)](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate)

**Official MCP Registry ID:** `io.github.Arobi-Technology-Alliance-Lab/immaculate` · **Glama Remote Connector:** [glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate)

[![Arobi Technology Alliance, Inc.](https://aura-genesis.org/brand/arobi-technology-alliance.jpeg)](https://aura-genesis.org/immaculate/mcp/)

**Arobi Immaculate MCP** is a self-contained, zero-dependency [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server (`stdio` / Docker) built by **[Arobi Technology Alliance, Inc.](https://aura-genesis.org/)**.

It executes **100% locally and offline** using Node.js built-in `node:crypto` (Ed25519 signatures + canonical SHA-256 hash chains) so MCP clients can issue bounded route grants, evaluate pre-action authority checks (**GRANTED**, **DENIED**, or **ESCALATED**), select policy-justified models, and check that a chain of sealed records is intact and who signed it, without an API key or external network calls.

- **Local Implementation:** `src/engine.mjs` + `src/index.mjs` (Node.js ≥ 18, zero external runtime dependencies, includes `Dockerfile` and `npm test`)
- **Hosted Cloud Option (`Streamable HTTP`):** `https://aura-genesis.org/api/v1/mcp` ([Documentation & 110 Free Credits](https://aura-genesis.org/immaculate/mcp/))
- **Published Benchmarks (SHA-256 verifiable):** https://aura-genesis.org/benchmarks/immaculate/
- **Live Service Status:** https://aura-genesis.org/status/

---

## Included Tools (Local Execution)

| Tool | Purpose |
| :--- | :--- |
| `arobi_route_grant` | Seals WHO granted WHAT authority to WHICH workflow (`scope.actions`, `scope.category_caps`, `attenuation`, `expires_at`) with an Ed25519 signature and hash-chained `ROUTE_GRANT` record. |
| `arobi_authorize` | Verifies that the grant was sealed by this server (an unsigned grant, or one signed with any other key, is **DENIED**), then its expiry, action allowlist, category caps, and consequence-tier auth freshness before execution — returning **GRANTED**, **DENIED**, or **ESCALATED** with a hash-chained `AUTHORIZATION` record. |
| `arobi_classify_and_route` | Classifies prompt complexity, filters capable candidates, picks the lowest-cost capable model or applies an explicit `quality_exception` uplift rule, detects repeated work, and optionally seals a `ROUTING_DECISION` record. |
| `arobi_verify_chain` | Re-derives canonical SHA-256 `prev_hash` / `record_hash` continuity and Ed25519 signatures across an ordered array of records, requires one signer for the whole chain (and, with `expected_signer_kid`, the signer you trust), and pinpoints the first broken index and the reason. |

### The local engine and the hosted service

- **Two implementations.** The local engine is a separate, smaller implementation for offline development, testing and evaluation, and its rules are the ones above (see `src/engine.mjs`). The hosted service applies its own policy and records each decision to your workspace's ledger, so for the same input its verdict can differ from the local engine's.
- **Keys.** The local engine makes a new Ed25519 signing key each time it starts. Its grants are honoured only by the run that sealed them, and every record names its signer in `signer_kid`. A chain shows who signed it only when it is checked against a signer you trust (`expected_signer_kid`); without that, it shows that the chain is intact as signed.
- **Not an independent check.** Whoever runs the local server holds its key and controls what it is told. For decisions that must be checked by someone other than the agent's operator, use the hosted service.

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
