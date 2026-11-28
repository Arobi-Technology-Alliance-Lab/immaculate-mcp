# Immaculate gate for OpenShell

The Immaculate gate is an [OpenShell](https://github.com/ai-openshell/openshell) supervisor middleware. OpenShell runs
agents in sandboxes. Before a sandboxed agent's HTTP request leaves, and before OpenShell adds provider credentials,
OpenShell asks the gate. The gate has Immaculate's engine (`src/engine.mjs` in this repository) authorize the request
against the operator's grant for that sandbox:

- **GRANTED**: the request continues.
- **DENIED** or **ESCALATED**: OpenShell answers the sandbox `403 Forbidden` with `error: middleware_denied` and the
  gate's reason code.

Every decision is sealed in an Ed25519-signed, SHA-256-chained record and written to disk before the answer goes back.
If the gate is down, OpenShell blocks the traffic the gate governs: HTTP hooks always fail closed.

```
sandboxed agent ── request ──▶ OpenShell supervisor ── preflight (gRPC, HTTP hooks) ──▶ Immaculate gate
                                       ▲                                                  │ 1 who: sandbox_id (+ token)
                                       │                                                  │ 2 what: policy rules → action, tier
                                       └──── continue_without_body │ deny (reason code) ◀─┤ 3 allowed? engine.authorize(grant)
                                                                                          └ sealed records → records/*.jsonl
```

## How a request is decided

The gate answers at preflight (`HTTP_REQUEST`, `PRE_CREDENTIALS`) from the request head: method, host and path. It
never reads the body or header values. It advertises a zero payload limit, so OpenShell offers it no body.

1. **Who is asking.** The sandbox is the preflight's `context.sandbox_id`. With token checks on, the caller must be a
   sandbox supervisor whose token names the same sandbox.
2. **What the request is.** The sandbox policy entry's `config` maps the request to an Immaculate action and a
   consequence tier. Rules are tried in order and the first match wins.
3. **Whether it is allowed.** The engine authorizes the action against the grant that covers the sandbox. It checks the
   grant's signature, revocation, expiry and scope, then the tier policy.
   - A **critical** action needs a person's fresh authentication. A sandbox request carries none, so the engine
     escalates it and the gate denies it ("held").
   - A **high** action is allowed when it is in scope. The engine applies its authentication-age rule only when an age
     is known, and a sandbox request has none.

| Reason code | When |
| --- | --- |
| (none: the request continues) | the engine GRANTED the action |
| `immaculate_action_out_of_scope` | the grant does not cover the action |
| `immaculate_critical_requires_fresh_auth` | a critical action: held for a person |
| `immaculate_grant_expired` | the grant has expired |
| `immaculate_no_grant` | no grant covers this sandbox |
| `immaculate_unmatched_request` | no rule matches, and the policy denies unmatched requests |
| `immaculate_ambiguous_path` | servers could read the path more than one way (see below) |
| `immaculate_incomplete_target` | the request has no method or no host |
| `immaculate_sandbox_mismatch` | the caller's token names a different sandbox |
| `immaculate_caller_not_supervisor` | the call did not come from a sandbox supervisor |
| `immaculate_no_sandbox_id` | the request context names no sandbox |
| `immaculate_config_invalid` | the policy entry's `config` is not valid |
| `immaculate_unsupported_phase` | a preflight for any phase other than `PRE_CREDENTIALS` |
| `immaculate_record_write_failed` | the gate cannot write its records, so it allows nothing |

When the engine refuses with another reason, the code is `immaculate_` followed by the engine's code in lower case.

A call without a valid gateway token gets gRPC `UNAUTHENTICATED`, and OpenShell then fails the request closed
(`middleware_failed`). OpenShell never passes the gate's free-text reasons to the sandbox or to its logs. It logs the
middleware name and the reason code.

## Install

Node.js 20 or newer.

```sh
cd integrations/openshell
npm ci
npm run fetch-protocol   # OpenShell's protocol files, at a pinned commit, checked by SHA-256
npm test
```

The gate implements OpenShell's protocol from `supervisor_middleware.proto` and `extension.proto`. Those files are
OpenShell's (NVIDIA, Apache-2.0) and are not stored in this repository. `npm run fetch-protocol` downloads them, with
OpenShell's licence, from commit `659b45f3bed896897de20a8b67289916a3d9fffc` into `protocol/`. It keeps each file only if
its SHA-256 matches the value pinned in `src/protocol.mjs`. The gate checks the digests again every time it loads them.
`npm test` and `npm start` fetch them first.

## Configure the gate

`gate.json` belongs to the operator. Relative paths are read from the file's folder. See
[`examples/gate.example.json`](examples/gate.example.json).

| Field | Meaning |
| --- | --- |
| `listen` | `host:port`; default `127.0.0.1:50051` |
| `tls.cert_path`, `tls.key_path` | the gate's server certificate and key (PEM). Required unless `allow_insecure_transport` |
| `auth.gateway_id` | your gateway's id; tokens must be issued by `openshell-gateway:<gateway_id>` |
| `auth.audience` | the registration's audience, by default `urn:openshell:extension:middleware:<name>`. The gate returns it as `expected_audience`, so the gateway refuses to start if it differs |
| `auth.public_key_path` / `auth.jwks_path` | the gateway's Ed25519 signing key, as PEM or as a JWKS, from the gateway operator |
| `auth.openid_configuration_url` | optional: the gateway's `https://…/.well-known/openid-configuration`. The gate re-reads its JWKS (at most once a minute) when a token names a key it does not know |
| `auth.tls_ca_cert_path` | optional: the CA for that discovery fetch |
| `auth.clock_skew_sec` | allowance for `exp`, `nbf` and `iat`; default 30 |
| `records_dir` | where record files go; default `records` |
| `rotate_after_records` | start a new run after this many records; default 50,000 |
| `grants` | who allowed which sandboxes to do what, until when (below) |

Each grant:
- `granted_by`: who allowed it (a team or a person).
- `sandboxes`: sandbox ids as OpenShell reports `sandbox_id`, or `["*"]` for any sandbox.
- `actions`: actions, prefixes ending in `.*`, or `*`.
- `ttl_hours` or `expires_at`: when it ends.
- `route_id`: optional.

Each sandbox has at most one grant. A sandbox named in a grant uses that grant and never the `"*"` grant.

Token checks follow OpenShell's [extension authentication](https://github.com/ai-openshell/openshell/blob/main/docs/extensibility/overview.mdx):
- `typ` is `openshell-ext+jwt` and `alg` is `EdDSA`, both pinned.
- The signature, the expiry and the exact audience must all be valid.
- The issuer is `openshell-gateway:<gateway_id>`.
- `caller_kind` is `gateway` or `supervisor`, and a supervisor's token must name a `sandbox_id`.

Repeated `jti` values are accepted, because OpenShell reuses a token until it rotates.

**Local development only:** `"allow_insecure_transport": true` serves plaintext with no token checks, matching an
OpenShell registration with `allow_insecure_transport = true`. In that mode OpenShell sends no token, so the gate refuses
`auth` there instead of never checking it. See [`examples/gate.dev.json`](examples/gate.dev.json).

## Register it in OpenShell

In the gateway TOML ([`examples/gateway.toml`](examples/gateway.toml)), then restart the gateway:

```toml
[[openshell.supervisor.middleware]]
name = "immaculate"
grpc_endpoint = "https://immaculate-gate.internal:50051"
tls_ca_cert_path = "/etc/openshell/immaculate-gate-ca.pem"
max_payload_bytes = 0
binding_policy = "allowlist"
bindings = ["http_request_pre_credentials"]
timeout = "500ms"
```

At startup the gateway calls `Describe`. The gate's manifest declares one binding, `HTTP_REQUEST` at
`PRE_CREDENTIALS`, with a zero payload limit. It supports and requires `openshell.supervisor-middleware.http-hooks`, so
a gateway or supervisor without HTTP hooks refuses it instead of calling it the legacy way.

## Attach it in sandbox policy

Add a `network_middlewares` entry whose `config` holds the rules
([`examples/policy.yaml`](examples/policy.yaml)). OpenShell asks the gate to validate the `config` before it accepts
the policy.

```yaml
network_middlewares:
  immaculate:
    middleware: immaculate
    on_error: fail_closed
    endpoints:
      include: ["api.crm.example", "api.payments.example", "*.mail.example"]
    config:
      rules:
        - { id: crm-read, methods: [GET], hosts: ["api.crm.example"], paths: ["/v1/contacts/*"], action: crm.read.contacts, tier: low }
        - { id: refunds, methods: [POST], hosts: ["api.payments.example"], paths: ["/v1/refunds"], action: payments.refund, tier: critical }
      unmatched: deny
```

Only requests to hosts in `endpoints.include` reach the gate. List every host whose requests you want decided.

Rule matching:
- **hosts**: an exact host, `*.example.com` (subdomains, not the apex), or `*`.
- **methods**: optional; any method when omitted.
- **paths**: optional; an exact path, or a prefix ending in `*`. `/v1/files/*` does not match `/v1/filesystem`.
- **Case**: hosts and paths compare without case. An exact path matches with or without one trailing slash.
- **Query**: the query string is not matched.
- **Unknown fields** are refused, so a typo cannot change a rule silently.
- **`unmatched`**: `deny` (the default), or `{ action, tier }` to authorize unmatched requests under one action.

**Ambiguous paths are denied, whatever `unmatched` says.** Servers disagree about encoded slashes (`%2F`), dot segments,
empty segments (`//`), `;` path parameters and backslashes. A request using any of these could reach a different handler
than the rule it matched names, so the gate denies it rather than guess. Escaped unreserved characters (`%72` for `r`)
are decoded before matching.

To check a policy, and see how one request would be classified:

```sh
node src/cli.mjs check --policy examples/policy-config.json --request "POST https://api.payments.example/v1/refunds"
```

## Run it

```sh
node src/cli.mjs serve --config gate.json
```

Logs are JSON lines on stdout.
- The `serving` line gives the run's `signer_kid` and records file.
- Each `decision` line gives the request id, sandbox, verdict, reason code, action, tier, rule and record hash. It never
  includes the path or the query.

On SIGINT or SIGTERM the gate stops. Until it is back, OpenShell blocks the requests the gate governs. Stopping the
gate is therefore also the operator's stop switch for that traffic.

## Records and verification

Each run has its own Ed25519 key and its own file, `records/<start time>-<signer kid>-<run>.jsonl`. A run starts with
its grants sealed (`ROUTE_GRANT`). Then each decision adds:
- `AUTHORIZATION`: the engine's verdict, when the engine was asked;
- `OPENSHELL_GATE_DECISION`:
  - request id, sandbox id and name, workspace, the originating process's binary, caller kind;
  - method, scheme, host, port;
  - the matched rule, action and tier;
  - the verdict and reason code;
  - the hash of the `AUTHORIZATION` record.

Paths and query strings can carry personal data or secrets, so only their SHA-256 digests are sealed.

After `rotate_after_records` records, the gate starts a new run: a new key, a new file, and the same grants with the
same expiry, sealed again. Memory stays bounded on a long-lived service.

A decision whose records cannot be written is a denial. If a write fails, the gate denies everything and tries a new
run, at most every 5 seconds.

```sh
node src/cli.mjs verify records/<file>.jsonl --signer <signer_kid from the serving log line>
```

`verify` checks:
- the hash chain;
- every signature;
- one signer, the pinned one when `--signer` is given;
- that the file does not end in a partial line.

The same files can also be checked with `arobi_verify_chain` from the MCP server.

## Limits

- The gate decides on the request head only: method, host and path. It never reads bodies, so `category_caps` (amount
  limits) are not applied, and header values are not inspected.
- Critical actions are always held. Nothing yet carries a person's fresh authentication or approval from a sandbox to
  the gate.
- Grants come from `gate.json` at start. To change or end one, edit the file and restart the gate. A restart also
  invalidates every earlier grant, because each run's key is new. The gate has no runtime revocation call.
- It evaluates HTTP requests only. HTTP responses and WebSocket messages are not evaluated, and its manifest declares
  no binding for them.
- It was tested with gRPC calls through the real protocol files at the pinned OpenShell commit, and with a local smoke
  of `serve` over TLS with gateway tokens. It has not yet been run with a live OpenShell gateway and sandbox.

---

Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved. Proprietary; see [LICENSE](LICENSE). The
OpenShell protocol files that `npm run fetch-protocol` downloads remain OpenShell's, under the Apache License 2.0.
