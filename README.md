# Arobi Immaculate MCP — Pre-Action AI Governance & Evidence Server

[![Arobi Immaculate MCP connector](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate/badges/score.svg)](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate)

**Official MCP Registry ID:** `io.github.Arobi-Technology-Alliance-Lab/immaculate` · **Glama Remote Connector:** [glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate)

[![Arobi Technology Alliance, Inc.](https://aura-genesis.org/brand/arobi-technology-alliance.jpeg)](https://aura-genesis.org/immaculate/mcp/)

**Arobi Immaculate MCP** is a self-contained, zero-dependency [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server (`stdio` / Docker) built by **[Arobi Technology Alliance, Inc.](https://aura-genesis.org/)**.

It executes **100% locally and offline** using Node.js built-in `node:crypto` (Ed25519 signatures + canonical SHA-256 hash chains) so MCP clients can issue bounded route grants, evaluate pre-action authority checks (**GRANTED**, **DENIED**, or **ESCALATED**), select policy-justified models, and cryptographically verify tamper-evident evidence chains locally without an API key or external network calls.

- **Local Implementation:** `src/engine.mjs` + `src/index.mjs` (Node.js ≥ 18, zero external runtime dependencies, includes `Dockerfile` and `npm test`)
- **Hosted Cloud Option (`Streamable HTTP`):** `https://aura-genesis.org/api/v1/mcp` ([Documentation & 110 Free Credits](https://aura-genesis.org/immaculate/mcp/))
- **Published Benchmarks (SHA-256 verifiable):** https://aura-genesis.org/benchmarks/immaculate/
- **Live Service Status:** https://aura-genesis.org/status/

---

## Included Tools (Local Execution)

| Tool | Purpose |
| :--- | :--- |
| `arobi_route_grant` | Seals WHO granted WHAT authority to WHICH workflow (`scope.actions`, `scope.category_caps`, `attenuation`, `expires_at`) with an Ed25519 signature and hash-chained `ROUTE_GRANT` record. |
| `arobi_authorize` | Verifies grant signature, expiry, action allowlist, category caps, and consequence-tier auth freshness before execution — returning **GRANTED**, **DENIED**, or **ESCALATED** with a hash-chained `AUTHORIZATION` record. |
| `arobi_classify_and_route` | Classifies prompt complexity, filters capable candidates, picks the lowest-cost capable model or applies an explicit `quality_exception` uplift rule, detects repeated work, and optionally seals a `ROUTING_DECISION` record. |
| `arobi_verify_chain` | Re-derives canonical SHA-256 `prev_hash` / `record_hash` continuity and Ed25519 signatures across an ordered array of records, pinpointing the first broken index and mismatch reason. |

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
