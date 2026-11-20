# Immaculate MCP — Pre-Action AI Governance & Evidence Server

[![Arobi Immaculate MCP connector](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate/badges/score.svg)](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate)

**Official MCP Registry ID:** `io.github.Arobi-Technology-Alliance-Lab/immaculate` · **Glama Connector:** [glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate](https://glama.ai/mcp/connectors/io.github.Arobi-Technology-Alliance-Lab/immaculate)


[![Arobi Technology Alliance, Inc.](https://aura-genesis.org/brand/arobi-technology-alliance.jpeg)](https://aura-genesis.org/immaculate/mcp/)

**Immaculate MCP** is a hosted [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server built by **[Arobi Technology Alliance, Inc.](https://aura-genesis.org/)** (`Streamable HTTP`). AI agents call Immaculate before consequential actions to receive a reasoned **GRANTED**, **DENIED**, or **ESCALATED** verdict, route work to the right model tier, and record verifiable evidence trails.

- **Hosted Endpoint:** `https://aura-genesis.org/api/v1/mcp` (discovery: `https://mcp.aura-genesis.org/`)
- **Transport:** `streamable-http` (`2024-11-05`, `2025-06-18`)
- **Documentation & Free Key (110 credits, no card):** https://aura-genesis.org/immaculate/mcp/
- **Published Benchmarks (SHA-256 verifiable):** https://aura-genesis.org/benchmarks/immaculate/
- **Live Service Status:** https://aura-genesis.org/status/
- **Founder Engineering Log:** https://possumx.dev/work/

---

## Exposed Tools

| Tool | Purpose |
| :--- | :--- |
| `arobi_authorize` | Evaluates a proposed consequential agent action against current identity, authority, and policy rules before execution. |
| `arobi_route_grant` | Issues scoped, policy-checked route grants for governed execution lanes. |
| `arobi_classify_and_route` | Classifies task complexity and routes work to the lowest-cost capable model tier under policy constraints. |
| `arobi_verify_chain` | Re-checks supported Arobi evidence records and identifies any integrity mismatch. |

---

## Quickstart (Claude Code, Codex, Cursor, Windsurf, Custom MCP Clients)

1. Create a free workspace (110 free credits, no card required) at [aura-genesis.org](https://aura-genesis.org/) and generate a tenant key under **Connections → Other systems → Create custom connection**.
2. Add the remote Streamable HTTP server to your MCP client configuration:

```json
{
  "mcpServers": {
    "arobi-immaculate": {
      "url": "https://aura-genesis.org/api/v1/mcp",
      "headers": {
        "X-Arobi-Tenant-Key": "<your-arobi-tenant-key>"
      }
    }
  }
}
```

Alternatively, pass `Authorization: Bearer <your-arobi-tenant-key>`.

---

## Local Stdio / Docker Bridge (for Stdio-Only MCP Clients)

This repository also includes a zero-dependency MIT-licensed Node.js stdio-to-Streamable-HTTP bridge (`src/index.mjs`) and `Dockerfile` for MCP clients that require a local stdio process:

```bash
# Run locally with Node.js >= 18
AROBI_TENANT_KEY=<your-arobi-tenant-key> node src/index.mjs

# Or run via Docker
docker build -t arobi-immaculate-mcp .
docker run -i --rm -e AROBI_TENANT_KEY=<your-arobi-tenant-key> arobi-immaculate-mcp
```

`initialize`, `ping`, and `tools/list` introspection work without a key; metered `tools/call` requests require `AROBI_TENANT_KEY`.

---

## Verification, Scope Boundary & License

Arobi provides technical verification, policy enforcement, and tamper-evident evidence tooling. Arobi is not an insurer or a certification body; licensed insurers, regulators, and independent reviewers retain their own decisions.

The client bridge, container configuration, manifest, and documentation in this repository are licensed under the **MIT License** (see [LICENSE](./LICENSE)). Arobi's hosted backend service at `https://aura-genesis.org/api/v1/mcp` remains proprietary to **Arobi Technology Alliance, Inc.**
