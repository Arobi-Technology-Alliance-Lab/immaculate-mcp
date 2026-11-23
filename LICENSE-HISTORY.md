# License history — Immaculate MCP

Repository: https://github.com/Arobi-Technology-Alliance-Lab/immaculate-mcp  
Official MCP Registry name: `io.github.Arobi-Technology-Alliance-Lab/immaculate`  
Copyright holder: Arobi Technology Alliance, Inc.

This is the authoritative license history for this repository. Timestamps below are taken from `git` author/committer dates. America/New_York (ET) is Eastern Standard Time, UTC-5. UTC is also given.

## Current license

From commit `4c1d513ec0df50386d91e1da6afd71502bcf821d` onward, everything in this repository is licensed under the **Arobi Proprietary License**. The license text is in [`LICENSE`](./LICENSE) and begins with:

`SPDX-License-Identifier: LicenseRef-Arobi-Proprietary`

`package.json` identifies that file with `"license": "SEE LICENSE IN LICENSE"`.

This license applies to the current `main` branch, to Git tags `v1.1.0` and `v1.2.0`, and to all later releases unless a later commit says otherwise.

## MIT snapshot (one commit only)

One commit was published under the MIT license:

| Field | Value |
| --- | --- |
| Commit | `cc19cc7147494be0b3dd68191d6d2fde19416fd5` (short: `cc19cc71`) |
| Git author/committer date | 2026-11-19 22:31:17 America/New_York (2026-11-20 03:31:17 UTC) |
| Subject | Add MIT LICENSE, glama.json, Dockerfile, and zero-dependency stdio MCP bridge |
| License at that commit | MIT (the `LICENSE` file added in that commit) |

That snapshot remains available, under MIT, to the people who received it under that license. It was never given a Git tag or GitHub Release. It is not `v1.0.0`.

The `LICENSE` file currently in the repository refers to this snapshot as "commit cc19cc71, 2026-11-20". That calendar date is the UTC date of the commit. The same instant is 2026-11-19 22:31:17 in America/New_York.

## Switch to the Arobi Proprietary License

Five minutes later, commit `4c1d513ec0df50386d91e1da6afd71502bcf821d` (2026-11-19 22:36:34 America/New_York / 2026-11-20 03:36:34 UTC) replaced the MIT `LICENSE` with the Arobi Proprietary License, set `package.json` to `"license": "SEE LICENSE IN LICENSE"`, and recorded the MIT snapshot in the "EARLIER RELEASES" clause. Every subsequent commit, including `v1.1.0` and `v1.2.0`, carries that proprietary license.

## Tagged releases

| Tag | Commit | Tag / commit date (America/New_York) | License in the tagged tree |
| --- | --- | --- | --- |
| `v1.0.0` (lightweight tag) | `0fa0364f1ca06e236422504b5d8edc9e14b1d7f8` | 2026-11-19 21:30:03 | **No `LICENSE` file and no `package.json`.** The tree contains only `README.md` and `server.json`. This tag is earlier than the MIT snapshot. |
| `v1.1.0` (lightweight tag) | `0d72e3b3fb0efe3f9ccf72d969b09d32d34c2384` | 2026-11-21 09:50:04 | Arobi Proprietary License (`LicenseRef-Arobi-Proprietary`) |
| `v1.2.0` (annotated tag) | `f20119817ab8723cfe65a271029449c624b8b794` (tag object `e20fc4530a4b8d325b3b3125d7eebecd4e21cd8a`, tagged 2026-11-21 21:19:26) | 2026-11-21 21:19:06 | Arobi Proprietary License (`LicenseRef-Arobi-Proprietary`) |

A GitHub Release exists for each of those tags. The `v1.0.0` GitHub Release body says "Licence: the Arobi Proprietary License (see LICENSE)", but the `v1.0.0` tag itself does not contain a `LICENSE` file.

## What is not MIT

- The `v1.0.0` tag is not an MIT release. It predates the MIT `LICENSE` and contains no license file.
- `v1.1.0`, `v1.2.0`, and the current default branch are not MIT. They are under the Arobi Proprietary License.
- Only commit `cc19cc71` was made available under MIT.
