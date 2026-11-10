# OSV fixtures (real responses, captured 2026-11-10)

`querybatch` results are **positional**: `results[i]` answers `queries[i]`. Every response is stored
next to the request that produced it.

| Files | What it shows |
|---|---|
| `querybatch.request.json` / `.response.json` | Six npm queries: several advisories (lodash, axios), no fix (request), malicious (flatmap-stream), clean (left-pad → `{}`). Each vuln is only `{ id, modified }`. |
| `pagination.page1.*`, `pagination.page2.*` | Pagination. A query with more than 1000 vulns gets `next_page_token` on **its own result**; other queries in the same batch don't. Follow it by re-sending only that query with `page_token`. Pages don't overlap. Responses trimmed to 3 vulns per page (the real pages had 1000 each). OSV only paginates past 1000 vulns per query, so a non-npm ecosystem was used to trigger it. |
| `GHSA-29mw-wpgm-hmr9.json` | lodash: `affected` also lists other packages and a RubyGems package; `fixed` event. |
| `GHSA-wf5p-g6vw-rhxx.json` | axios: the same package in two `affected` entries with separate ranges (0.x and 1.x). |
| `GHSA-p8p7-x288-28g6.json` | request: `last_affected`, no fix. |
| `MAL-2025-20690.json` | OpenSSF malicious-package record: no severity, aliases or references; `introduced: 0`, no fix. |
| `GHSA-9x64-5r7x-2q53.json`, `GHSA-mh6f-8j2x-4483.json` | GitHub malware advisories for the same package (CRITICAL); one has no ranges. |

Advisory data changes over time; refresh with the same requests if a field shape is in doubt.
