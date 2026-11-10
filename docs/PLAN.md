# Implementation plan

Rule: one milestone at a time. A milestone is done only when its gate passes and
`npm run typecheck && npm run lint && npm test` are green. Milestone 1 before any AI code.

## M0 · Setup and verification (short)
- [x] `git init`; `.gitignore` (node_modules, dist, .env, .idea/, .DS_Store); commit the docs first
- [x] Repo skeleton per CLAUDE.md layout; strict tsconfig; ESLint; Vitest; docker-compose with Postgres
- [x] Demo fixture repo — https://github.com/arturowin/scan-review-demo (separate public GitHub repo, lockfile only, never meant to be installed) covering:
      direct vulnerable dep, transitive vulnerable dep, advisory with no fix, multi-advisory package needing a
      major jump, a `MAL-` package (version already removed from npm; use the real name/version from the advisory, never invent `resolved`/`integrity` values — omit them if unknown), a dev dep, a `link: true` workspace,
      a `git+` dependency. Use real OSV data to pick the packages; record which case each one covers.
- [x] Migration runner + first migration (tables from ARCHITECTURE.md)
- [x] Verify pg-boss (installed version): transactional send, retry/backoff/expiry, crash recovery, dead-letter support, expiry vs retryLimit, job metadata (retryCount/retryLimit), job state lookup by id, archive/deletion timing. Write findings to `docs/AGENT_LOG.md`
- [x] Verify OSV querybatch + vulns response shapes; save a real response as a test fixture
**Gate:** `docker compose up` starts Postgres; `npm run migrate` works; verification notes written.

## M1 · Vertical slice
- [x] API and worker run as separate processes against Postgres
- [x] `POST /scans`: malformed or non-github.com URL → 400 with clear message; else 202 `{ scanId }`
- [x] Scan row + pg-boss job in one transaction; job id = scan id
- [x] Idempotency-Key: same key + same request → same scan; same key + different request → 409
- [x] Worker: resolve commit SHA, read `package-lock.json` at that SHA via raw.githubusercontent.com, query OSV, save findings, mark completed
- [x] GitHub errors: 404 → "not found or private"; rate-limit 403/429 → transient; optional GITHUB_TOKEN
- [x] `GET /scans/:id` (status, stage, counts) and `GET /scans/:id/report` (findings)
- [x] Minimal page: submit URL, poll status, list findings
**Gate:** a real public repo with known vulnerable npm deps goes from submit to report.
Tests: URL normalization, idempotency (incl. 409), lockfile parser basics, one integration test with GitHub + OSV mocked.

## M2 · Actionable report
- [ ] Only lockfileVersion 2/3 supported; others → `unsupported` with reason
- [ ] Lockfile parsing rules from ARCHITECTURE.md (link, sources, dev/optional/devOptional, direct, dedupe, path aggregation)
- [ ] OSV chunking (≤1000), pagination, detail fetch deduped with a concurrency limit, failed-lookup accounting
- [ ] Counts: checked, unsupported-source entries, failed lookups; zero-dependency lockfile handled
- [ ] Ranking policy as documented (malicious first, then severity, runtime/dev, direct/transitive)
- [ ] Malicious packages (`MAL-`) as a separate category with "remove + rotate secrets" action
- [ ] Recommended next actions grouped by package; candidate version labelled; direct parent named for transitive; "no fixed version published" guidance; major-version jumps flagged
- [ ] Deterministic summary line at the top
- [ ] Coding-agent prompt from template; preview before copy
- [ ] Clean result screen as documented; never "secure"
- [ ] Report follows the frozen layout; coverage beside the summary
**Gate:** someone reading the report knows what to do first and what was checked.
Tests: lockfile parser (each rule), ranking policy, candidate-version selection (multiple ranges, no fix,
several advisories on one package, major jump), grouping, malicious path, prompt template snapshot.

## If time runs short — cut in this order
1. Shrink `npm run eval` to 3 fixtures
2. Visual polish beyond clear states
3. Prompt preview (keep copy button)
Never cut a test while keeping the claim it proves. If a guarantee isn't tested, remove it from the README.

## M3 · AI explanation
- [ ] `Explainer` port; `LlmExplainer` with timeout → zod check (structure + allowed finding IDs) → `TemplateExplainer` fallback
- [ ] Works with no `LLM_API_KEY`
- [ ] `explanation_source` stored and shown
- [ ] AI text never overwrites structured facts
- [ ] `npm run eval`: small fixture set, checks IDs referenced exist, no invented versions, length limits
**Gate:** report is complete when the LLM call fails, times out, returns garbage, or there is no key.

## M4 · Failure behavior (all REQUIRED)
- [ ] Some OSV lookups fail → completed, partial, unchecked listed
- [ ] All lookups fail → failed with reason
- [ ] Attempt guard on every write; findings + completion in one locked transaction; stale attempt or duplicate job changes nothing
- [ ] Restart test: stop worker mid-scan, start again, scan completes
- [ ] Transient error: worker writes `retrying` + reason, retried, scan recovers; UI shows retrying
- [ ] Exhausted retries end in `failed` (final-attempt check and dead letter if available)
- [ ] Sweeper: fails a scan only when its pg-boss job is finished or missing; leaves queued/retrying/active jobs alone (test with a backlog and a stopped worker); a zombie worker's later writes change nothing
- [ ] Permanent failures (404, other 403, unsupported) are recorded and not retried
- [ ] Restart test also covers a crash on the last attempt (scan ends `failed`, not stuck)
**Gate:** every outcome in ARCHITECTURE.md lifecycle is reachable and tested.

## M5 · Polish and release
- [ ] UI states: input, progress, retrying, completed, partial, clean, unsupported, failed
- [ ] Unit + integration + adapter contract tests complete
- [ ] README: Product interpretation → Assumptions → Quick start (Docker and non-Docker) → Demo repo → Architecture → Decisions → Failure behavior → Limits → Next steps → How I used coding agents (from AGENT_LOG)
- [ ] Demo fixture repo linked, with a warning not to `npm install` it; tested end to end; one real popular repo also tried
- [ ] README Limits: no rate limit on POST /scans, worker concurrency, idempotency key retention, GHSA-only severity
- [ ] Usability check: show the report to someone unfamiliar; ask what they'd do first and why, what was checked, what's uncertain. Fix confusion.
