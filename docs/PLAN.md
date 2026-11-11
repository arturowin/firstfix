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
- [x] First: ecosystem seams (ARCHITECTURE.md "Ecosystems"; npm stays the only implementation, ~half a day)
      - migration `002_ecosystem.sql`: `ecosystem text NOT NULL DEFAULT 'npm'` on `findings` and `unchecked_deps`
        (in `findings_unique`), `scans.lockfile_path`; repository reads/writes both
      - ports: `RepoSource.readFile(repo, sha, path)` replaces `readLockfile`; `VulnDatabase.lookup` takes
        `{ ecosystem, name, version }`, key `ecosystem:name@version`
      - OSV adapter: ecosystem passed through in queries and `affected` filtering (no hardcoded `'npm'`)
      - `src/domain/ecosystems/`: lockfile-format registry; current parser becomes the npm `package-lock.json` format
      - pipeline: try registered formats in order, store `lockfile_path`; error/UI copy derived from the registry
      - candidate selection, major-jump flag, agent-prompt command and clean-result CI hint (below) are written
        against the npm `VersionScheme` / remediation hints from the start
- [x] Then: provider-neutral advisory source (ARCHITECTURE.md "Advisory source"; OSV stays the only adapter, ~1 h)
      - `AffectedRange` in `src/domain/advisory.ts` replaces raw `affectedRanges: unknown[]`; the OSV adapter converts
        `introduced`/`fixed`/`last_affected` events into it; `findings.affected_ranges` stores the neutral shape
      - the OSV adapter sets `isMalicious`; the domain no longer inspects `MAL-` ids
      - shared `VulnDatabase` contract suite (`test/contract/vuln-database.contract.ts`), run by the OSV adapter test
      - report names the advisory data source next to coverage
- [x] Only lockfileVersion 2/3 supported; others → `unsupported` with reason
- [x] Lockfile parsing rules from ARCHITECTURE.md (link, sources, dev/optional/devOptional, direct, dedupe, path aggregation)
- [x] OSV chunking (≤1000), pagination, detail fetch deduped with a concurrency limit
- [x] Failed-lookup accounting (done in M4: partial coverage, `lookup_failed`, `failed_lookups`)
- [x] Counts: checked, unsupported-source entries; zero-dependency lockfile handled; zero *checked* deps get
      "No dependencies could be checked", never a clean result (failed-lookup count: M4)
- [x] Ranking policy as documented (malicious first, then severity, runtime/dev, direct/transitive)
- [x] Malicious packages (`MAL-`) as a separate category with "remove + rotate secrets" action
- [x] Recommended next actions grouped by package; candidate version labelled; direct parent named for transitive; "no fixed version published" guidance; major-version jumps flagged
- [x] Deterministic summary line at the top
- [x] Coding-agent prompt from template; preview before copy
- [x] Clean result screen as documented; never "secure"
- [x] Report follows the frozen layout; coverage beside the summary
**Gate:** someone reading the report knows what to do first and what was checked.
Tests: lockfile parser (each rule), ranking policy, candidate-version selection (multiple ranges, no fix,
several advisories on one package, major jump), grouping, malicious path, prompt template snapshot.
Ecosystem seams: a test-only fake ecosystem through the pipeline (GitHub + OSV mocked) with nothing outside the
registry changed; OSV adapter passes the ecosystem through and filters `affected` by it; migration 002 keeps
existing rows as `npm` and the unique key includes the ecosystem; all existing npm tests unchanged.
Advisory source: OSV events → `AffectedRange` (fixed, last_affected, `introduced: 0`, versions-only entries);
the OSV adapter passes the shared contract suite; candidate selection tests use only `AffectedRange`.

## If time runs short — cut in this order
1. Shrink `npm run eval` to 3 fixtures
2. Visual polish beyond clear states
3. Prompt preview (keep copy button)
Never cut a test while keeping the claim it proves. If a guarantee isn't tested, remove it from the README.

## M3 · AI explanation
- [x] `Explainer` port; `LlmExplainer` with timeout → zod check (structure + allowed finding IDs) → `TemplateExplainer` fallback
- [x] Works with no `LLM_API_KEY`
- [x] `explanation_source` stored and shown
- [x] AI text never overwrites structured facts
- [x] `npm run eval`: small fixture set, checks IDs referenced exist, no invented versions, length limits
**Gate:** report is complete when the LLM call fails, times out, returns garbage, or there is no key.
      Status: gate covered by tests (fails, times out, garbage, refusal, injected title, no key) and live runs
      with and without a key (with the key, demo scans got AI explanations that passed the facts check).
      Pending: `npm run eval` with the key (reads it from the shell, not `.env`).
- [x] Provider seam (user request): `LlmClient` + registry; Anthropic is the first provider

## M4 · Failure behavior (all REQUIRED)
- [x] Some OSV lookups fail → completed, partial, unchecked listed
- [x] All lookups fail → failed with reason
- [x] Attempt guard on every write; findings + completion in one locked transaction; stale attempt or duplicate job changes nothing
- [x] Restart test: stop worker mid-scan, start again, scan completes
- [x] Transient error: worker writes `retrying` + reason, retried, scan recovers; UI shows retrying
- [x] Exhausted retries end in `failed` (final-attempt check and dead letter if available)
- [x] Sweeper: fails a scan only when its pg-boss job is finished or missing; leaves queued/retrying/active jobs alone (test with a backlog and a stopped worker); a zombie worker's later writes change nothing
- [x] Permanent failures (404, other 403, unsupported) are recorded and not retried
- [x] Restart test also covers a crash on the last attempt (scan ends `failed`, not stuck)
**Gate:** every outcome in ARCHITECTURE.md lifecycle is reachable and tested.
      Status: passed; outcome → test map in ARCHITECTURE.md "Lifecycle".

## M5 · Polish and release
- [x] UI states: input, progress, retrying, completed, partial, clean, unsupported, failed (each checked at desktop and phone width)
- [x] Unit + integration + adapter contract tests complete
- [x] README: Quick start (Docker) → Demo repo → Product interpretation → Architecture (with the key decisions) → Failure behaviour → Limits and next steps → Checks (host setup for tests) → How I used coding agents (from AGENT_LOG)
- [x] Demo fixture repo linked, with a warning not to `npm install` it; tested end to end; one real popular repo also tried
- [x] README Limits: GHSA-only severity, npm only (ecosystem seams ready; lockfile ecosystems vs resolve-first
      ones), one lockfile per scan, one advisory source (OSV; provider contract ready), per-process rate limit,
      worker concurrency and retention. (Rate limiting and key retention were limits here; both are now
      implemented, see "After M5".)

## After M5 · Review hardening and demo readiness
Found by external reviews after M5; each fix has a regression test (details in ARCHITECTURE.md and AGENT_LOG).
- [x] Admission control: per-client limit on `POST /scans` (429), exact outstanding-scan cap (503), key
      re-checked under the admission lock so concurrent replays get their scan
- [x] Retention: finished scans and idempotency keys deleted on a schedule
- [x] Lockfile input hardening: npm name/alias validation before any command; bounded, regex-free workspace
      matching (budget charged before allocation); only clean, existing, declared workspace links skipped;
      malformed strings stored safely, never dropped
- [x] Bounded graph work and memory (path copies, deep chains), with `context_truncated` made explicit
- [x] OSV correctness: events in version order, range-wide limits and `"*"`, explicit version lists kept,
      partial pages and details keep confirmed findings (`incomplete`)
- [x] Plan correctness: candidates checked against every advisory's ranges and lists; never an upgrade that
      addresses zero advisories; what a partial fix leaves is named
- [x] Agent prompt built only from validated fields (no titles or prose), also for older stored scans
- [x] Browser: one idempotency key per intended scan; submit controls locked until the scan settles
- [x] Compose: worker `restart: unless-stopped`, crash recovery verified in a disposable environment
- [x] `npm run eval` with an LLM key
- [x] Dependency audit: runtime dependencies clean; 10 moderate findings remain in the dev-only lint toolchain
      (one minimatch advisory via eslint/typescript-eslint; npm's suggested fix is a breaking downgrade)
