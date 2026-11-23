# Security policy

Arobi Technology Alliance, Inc. takes reports about the security of our products and services seriously, and thanks
everyone who reports a problem responsibly.

This file is the security policy for the **Immaculate MCP** repository
(`Arobi-Technology-Alliance-Lab/immaculate-mcp`). The organization-wide policy is
[Arobi-Technology-Alliance-Lab/.github/SECURITY.md](https://github.com/Arobi-Technology-Alliance-Lab/.github/blob/main/SECURITY.md).
If the two ever differ, follow the organization file and
[security.txt](https://aura-genesis.org/.well-known/security.txt).

## Reporting a vulnerability

- Email **contact@aura-genesis.org** with "Security" in the subject. Our current contact and policy are always in
  [security.txt](https://aura-genesis.org/.well-known/security.txt).
- Include what you found, where (product, page, repository path or endpoint), how to reproduce it, and what an
  attacker could do with it.
- Please do not open a public issue, post details publicly, or share them with others until we have fixed the problem.

## What to expect

- We aim to acknowledge a report within three business days and to keep you updated until it is resolved.
- We investigate every report, fix confirmed problems as quickly as their severity requires, and tell you when a fix
  ships. We will credit you if you would like, once the fix is out.
- We do not take legal action against good-faith research that follows this policy.

## Please do not

- Access, change or delete data that is not yours, or keep any data you encounter.
- Degrade or disrupt our services (no denial-of-service testing, spam or automated scanning at volume).
- Use social engineering, phishing, or physical attacks against Arobi staff, offices or partners.
- Test systems that belong to our customers or vendors.

## Scope

This policy covers:

- The Immaculate MCP local engine and related files in this repository (`src/`, `test/`, `Dockerfile`, manifests and
  documentation).
- The hosted Immaculate MCP service and its documentation on aura-genesis.org, including `https://aura-genesis.org/api/v1/mcp`
  and `https://mcp.aura-genesis.org/`.

It also covers, as in the organization policy: aura-genesis.org and its subdomains, Ullumii Cloud, Ullumii Desktop,
HUE, and Arobi's public APIs.

Vulnerabilities in third-party services we use (for example our hosting, database or payment providers) should be
reported to them; we are glad to help route a report.

## Supported versions

Please report issues against the current source on `main` and the latest published version (`1.2.0` as of this file).
Older tagged versions may be assessed for impact, but fixes are made on the current line.
