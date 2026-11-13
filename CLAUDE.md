# FirstFix — project guide for Claude Code

A user submits a GitHub repo URL (public, or private after signing in with GitHub), follows scan progress, and
gets a prioritized, explained security review: dependency findings and targeted source checks, with recommended
next actions. Read `docs/ARCHITECTURE.md` and `docs/PLAN.md` before any work.

## Product in one line
Help application security managers decide what to fix first across their organization's repositories, and
hand clear, verifiable next steps to the teams that own them. Facts come from the scan; AI only explains them.

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
  domain/                types, ranking policy, lockfile parser, fix-plan builder, source rules and scanner,
                         access rules, agent prompt, report text (pure, no I/O)
  application/           ScanService and AccessService (API side), ScanPipeline and runSourceCheck (worker side),
                         report, explanations, retention
  ports/                 ScanRepository, ScanSubmission, JobQueue, RepoSource, VulnDatabase, Explainer,
                         GitHubAuth, SessionStore
  adapters/              postgres, pgboss, github (public reads, user sign-in, app tokens), osv, llm,
                         template-explainer, secret-box
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
12. Commit only when the human asks, with a clear message (the history should read as a record of decisions),
    on a branch from `main` with one PR per change. Never commit `.env` or other local env files (only
    `.env.example`).
13. After each milestone, append an entry to `docs/AGENT_LOG.md` (what you did, what you assumed,
    anything the human corrected). Keep entries short and factual.
14. Never print secrets or ask for them in chat. The human puts them in a git-ignored file, and you copy
    them where needed without showing their values.

## Security invariants
Keep these true; a change that weakens one needs the human's approval first.
- **Public scans never use credentials that can read private repositories.** File reads are anonymous. A
  public scan stops if GitHub reports the repository as private, also when it became private after submit.
  `GITHUB_TOKEN` is used only for metadata calls, and only after the worker's startup check finds no `repo`
  scope and no readable private repository. The check runs once per worker start.
- **GitHub decides who reads a private scan.** `GET /scans/:id` and `/report` require GitHub to list the scan's
  repository id, for the viewer's own token, in the scan's installation (cached per session for at most 5
  minutes). No session or no access → 404, the same as a missing scan. Expired session → 401. GitHub
  unavailable → 503, never an expired decision. These responses are `no-store` and vary by cookie.
- **Private reads are scoped to one repository.** The worker uses an installation token limited to the scan's
  repository id, with contents and metadata read-only. The repository is bound by id, not name.
- **Sessions and secrets at rest.** The session cookie is random; the database stores only its SHA-256.
  GitHub tokens and PKCE verifiers are AES-256-GCM encrypted with a key derived from `SESSION_SECRET`.
  Cookies are HttpOnly, Secure, SameSite=Lax. OAuth uses PKCE (S256) and a one-time state bound to the
  browser. Sign-ins last at most 8 hours. After sign-in, only `/` or a scan page is a valid return path.
- **Repository code is never executed or installed,** and complete files are never stored: at most
  200-character matched excerpts.
- **Untrusted text is data.** Repository, advisory and AI text is rendered with `textContent`, never
  `innerHTML`. AI text is used only if it passes the facts check; otherwise the template is shown.
- **The coding-agent prompt holds only validated fields** (package names, versions, advisory ids, paths and
  line numbers that match strict formats) and fixed text from this codebase. Code excerpts, advisory titles,
  and AI or template prose never go in. Anything that fails validation is replaced by a note.
- **What the LLM provider receives** (only with `LLM_API_KEY`, also for private repositories): the repository
  owner/name, dependency facts (package names, versions, advisory ids, severities, titles), and source rule
  ids and counts. Never source code, file paths or file contents. Advisory titles are external text and are
  framed as data in the prompt.
- **Logs never contain credentials or query strings** (OAuth codes arrive in one).
- **Only `github.com` repository URLs are accepted.** Outbound calls go only to GitHub, OSV.dev and the
  configured LLM provider.

## Verify, don't assume
- Check the INSTALLED pg-boss version's docs/types for: sending a job inside an existing transaction,
  retry/backoff/expiry options, crash recovery, dead-letter support, how job expiry interacts
  with retryLimit, job metadata (retryCount/retryLimit) on fetched jobs, looking up a job's state by id,
  and when jobs get archived or deleted. If transactional send isn't supported, stop and
  report — do not silently fall back.
- Check OSV response shapes against a real call or the official docs before writing types.
