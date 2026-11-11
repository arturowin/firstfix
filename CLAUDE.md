# FirstFix — project guide for Claude Code

A user submits a public GitHub repo URL, follows scan progress, and gets a prioritized, explained
dependency-security review with recommended next actions. Read `docs/ARCHITECTURE.md` and `docs/PLAN.md` before any work.

## Product in one line
Help a repository owner turn security findings into a prioritized next step, without needing
security expertise. Facts come from the scan; AI only explains them.

## Stack (decided — do not change without asking)
- Node.js 22 + TypeScript (strict), ESM
- HTTP: Fastify; validation: zod
- PostgreSQL via `pg` with explicit SQL (no ORM — the attempt-guarded queries must stay visible)
- Job queue: pg-boss (same database)
- Tests: Vitest; HTTP mocking: msw or nock
- `semver` for range matching and candidate selection
- `esbuild` to bundle the UI's TypeScript
- UI: static HTML + small vanilla TS bundle served by the API (no framework)
- Advisories: OSV.dev batch API (`/v1/querybatch`, then `/v1/vulns/{id}` for details)
- LLM: one provider behind the `Explainer` port; key in `LLM_API_KEY`; app must work without it
- GitHub: optional `GITHUB_TOKEN`; app must work without it

## Commands (keep these working)
- `docker compose up` — Postgres + api + worker
- `npm run api` / `npm run worker` — run against `DATABASE_URL`
- `npm run migrate`, `npm test`, `npm run lint`, `npm run typecheck`, `npm run eval`

## Layout
```
src/
  api/main.ts            composition root for the API process
  worker/main.ts         composition root for the worker process
  domain/                types, ranking policy, lockfile parser, fix-plan builder (pure, no I/O)
  application/           ScanService (API side), ScanPipeline (worker side)
  ports/                 ScanRepository, JobQueue, RepoSource, VulnDatabase, Explainer
  adapters/              postgres, pgboss, github, osv, llm, template-explainer
  web/                   static UI
migrations/              plain SQL, numbered
test/                    unit, integration, contract, fixtures
```

## Non-negotiable rules
1. Work on ONE milestone at a time from `docs/PLAN.md`. Do not start the next until its gate passes.
2. Milestone 1 (vertical slice) must work end to end before any AI/LLM code is written.
3. Plan before coding: list files to create/change and tests to add, then wait for approval.
4. Domain code is pure: no imports from `adapters/`, no I/O. Ports live in `src/ports/`; they are shaped by
   what `application/` needs, and only `adapters/` implement them. `application/` never imports `adapters/`.
5. Every scan-row write includes `WHERE id = $1 AND attempt = $2`. Findings + completion are written in
   one transaction that first locks the owned, non-terminal row (`SELECT ... FOR UPDATE`). See ARCHITECTURE.md.
6. Every repository file read for a scan is pinned to the resolved commit SHA (in the URL path or `ref`),
   never the default branch name.
7. Never present AI text as fact. Structured fields (IDs, versions, severity, ranges) are rendered from data.
8. Never claim a vulnerability is fixed; versions from advisories are "candidate" versions.
9. Do not add dependencies, endpoints, scanners or features not in the plan. Ask first.
10. Permanent failures (not found, forbidden, unsupported) are recorded and the handler returns normally.
    Only transient errors throw. Don't weaken or delete a failing test to make it pass. Report it.
11. Before finishing a task: `npm run typecheck && npm run lint && npm test` all green.
12. Commit after each green step with a clear message (the history should read as a record of decisions). Never commit `.env`.
13. After each milestone, append an entry to `docs/AGENT_LOG.md` (what you did, what you assumed,
    anything the human corrected). Keep entries short and factual.

## Verify, don't assume
- Check the INSTALLED pg-boss version's docs/types for: sending a job inside an existing transaction,
  retry/backoff/expiry options, crash recovery, dead-letter support, how job expiry interacts
  with retryLimit, job metadata (retryCount/retryLimit) on fetched jobs, looking up a job's state by id,
  and when jobs get archived or deleted. If transactional send isn't supported, stop and
  report — do not silently fall back.
- Check OSV response shapes against a real call or the official docs before writing types.
