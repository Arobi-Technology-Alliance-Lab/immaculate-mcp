# AGENTS.md

## Licensing (owner directive 2026-10-26, reaffirmed 2026-11-20)

Everything in this repository is proprietary to **Arobi Technology Alliance, Inc.** under `LICENSE` (the Arobi
Proprietary License, the same text as every Arobi repository).

- Never add, or switch to, MIT, Apache, BSD, ISC, GPL or any other open-source licence, here or in any Arobi repository.
- `package.json` keeps `"license": "SEE LICENSE IN LICENSE"`. Never set an open-source SPDX id.
- New source files carry `Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.`
- Directory listings (Glama, the MCP Registry) need a non-empty LICENSE file. This one satisfies that; no other licence
  is needed for a listing.

## Directory listings (2026-11-20)

- **Glama, two listings.** The Servers directory lists this repository: the local engine in `src/`. The Connectors
  directory lists the hosted endpoint, imported every hour from the Official MCP Registry entry (`server.json`). Glama
  refused this repository for the Servers directory while it held only a bridge to the hosted endpoint.
- **No internals of the hosted service go in this repository.** The local engine is its own implementation, written
  from the public tool descriptions, and the README says how it differs from the hosted service. Keep that section
  true whenever either one changes.
- **Never weaken the local checks.** `arobi_authorize` honours only grants this server sealed, and
  `arobi_verify_chain` requires one signer and reports whether it was pinned. The tests in `test/` hold both.

