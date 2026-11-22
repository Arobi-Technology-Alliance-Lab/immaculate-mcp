# Arobi Immaculate MCP — Pre-Action AI Governance & Evidence Server

[![Arobi Immaculate MCP connector](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate/badges/score.svg)](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate) [![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/arobi-technology-alliance-lab/immaculate-mcp)

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
| `arobi_classify_and_route` | Classifies prompt complexity, filters capable candidates, picks the lowest-cost capable model or applies an explicit `quality_exception` uplift rule, detects repeated work, and optionally seals a `ROUTING_DECISION` record. |
| `arobi_verify_chain` | Re-derives canonical SHA-256 `prev_hash` / `record_hash` continuity and Ed25519 signatures across an ordered array of records, requires one signer for the whole chain (and, with `expected_signer_kid`, the signer you trust), and pinpoints the first broken index and the reason. |

### The local engine and the hosted service

- **Two implementations.** The local engine is a separate, smaller implementation for offline development, testing and evaluation, and its rules are the ones above (see `src/engine.mjs`). The hosted service applies its own policy and records each decision to your workspace's ledger, so for the same input its verdict can differ from the local engine's.
- **Keys.** The local engine makes a new Ed25519 signing key each time it starts. Its grants are honoured only by the run that sealed them, and every record names its signer in `signer_kid`. A chain shows who signed it only when it is checked against a signer you trust (`expected_signer_kid`); without that, it shows that the chain is intact as signed.
- **Not an independent check.** Whoever runs the local server holds its key and controls what it is told. For decisions that must be checked by someone other than the agent's operator, use the hosted service.
- **Tools.** Both have the five tools above. The hosted service added `arobi_revoke_grant` in its version 1.1.0
  (2026-11-21) and the local engine in 1.2.0. A local revocation, like the local key, lasts for the run that made it:
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
