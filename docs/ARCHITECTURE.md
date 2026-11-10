# Architecture

## Product interpretation
Goal: help a repository owner turn security findings into a prioritized next step.
Assumptions: the user shouldn't need security expertise to understand the
report, and many will apply fixes through a coding agent, given the product space.

- "connect my repo" → paste a public GitHub URL, no setup
- "AI-assisted" → AI explains; facts come from the scan
- "code or dependencies" → npm dependencies, deliberately: findings are verifiable
- "not a raw report" → summary + up to three next actions, not a list
- "what I should do next" → recommended next actions grouped by package + a coding-agent handoff prompt
- "product, not an API" → real UI states, live progress, shareable report URL

Out of scope (stated in README): private repos (next: GitHub App), SAST, secrets, reachability analysis.

## Components
Two processes share one PostgreSQL database.

- **API** (`src/api/main.ts`): HTTP routes (zod, Idempotency-Key), `ScanService`, static UI.
  Uses ports `ScanRepository`, `JobQueue`.
- **Worker** (`src/worker/main.ts`): `ScanPipeline` = claim → resolve SHA → read lockfile @SHA →
  OSV lookup → rank → build actions → explain → save. Uses ports `RepoSource`, `VulnDatabase`,
  `Explainer`, `ScanRepository`.
- **Adapters**: GitHub REST API, OSV.dev, LLM (+ template fallback), Postgres, pg-boss.
- Plain composition root per process; no DI framework. Contract tests show adapters are substitutable.

## Data model (sketch — refine in M1)
```
scans(id uuid pk, job_id,    -- pg-boss job id, stored at submission (same tx)
      repo_owner, repo_name, repo_url_normalized, commit_sha null,
      status, stage null, attempt int default 0,
      total_deps int, checked_deps int, unsupported_deps int, failed_lookups int,
      coverage null,              -- 'full' | 'partial'
      explanation_source null,    -- 'ai' | 'template'
      summary_line text null, error_code null, error_message null,
      created_at, updated_at, completed_at null)

findings(id pk, scan_id fk, package, installed_version,
         scope,                    -- 'runtime' | 'optional' | 'dev' (most exposed path)
         is_direct bool,           -- true if any install path is direct
         direct_parents text[],    -- all direct deps that pull it in (empty if direct)
         install_paths jsonb,      -- e.g. [["express","body-parser","qs"]], capped
         advisory_id, aliases text[], severity, is_malicious bool,
         title, affected_ranges jsonb, candidate_version null, references jsonb,
         explanation null)

unchecked_deps(scan_id fk, package, version null, reason)   -- 'unsupported_source' | 'lookup_failed'

idempotency_keys(key pk, request_hash, scan_id fk, created_at)
```
Store `package` and `candidate_version` on findings so grouping into actions is a query, not a migration.

## Lifecycle
`queued → running(stage: fetching → scanning → analyzing) → completed`
Other outcomes: `unsupported` (no supported lockfile, reason stored), `failed` (unrecoverable or
retries exhausted). `retrying` while a transient error is being retried.
Terminal: `completed`, `unsupported`, `failed`.
Progress is persisted on the scan row; the UI polls `GET /scans/:id`. Stage labels use real counts
("checked 80 of 142").

## Contracts

### Request idempotency
- Same `Idempotency-Key` + same normalized request → same scan (200/202 with existing id).
- Same key + different request → 409.
- Rescan = new key = fresh lookup. Completed scans are never reused automatically.
- Normalize URL: lowercase owner/repo, strip `.git`, trailing slash; only `github.com`.

### Submission
Scan row + pg-boss job created in ONE transaction. Verified in M0 (pg-boss 12.38): `send(..., { db })`
with `db.executeSql` bound to our transaction's client joins that transaction; rollback leaves no job.
`send` returns `null` only when it dedupes (duplicate `id` or singleton options); treat `null` as an error
and roll back, so a scan never exists without a job.

### Attempt ownership
- Claim: increment `attempt`, skip if terminal (duplicate delivery is a no-op).
- Every scan-row write: `WHERE id = $1 AND attempt = $2`; 0 rows → stale, stop quietly.
- Status changes set only `status` (+ outcome fields). A `BEFORE UPDATE` trigger on `scans` does the
  bookkeeping: sets `updated_at`, clears `stage` unless `running`, stamps `completed_at` on entering a terminal
  state, and refuses to leave a terminal state (a rescan is a new scan). So the minimal failure updates below
  can never be rejected on a side field, which would leave a scan stuck. In M1 every status change still goes
  through one repository helper.
- Findings + completion:
```sql
BEGIN;
SELECT 1 FROM scans
 WHERE id = $1 AND attempt = $2
   AND status NOT IN ('completed','failed','unsupported')
 FOR UPDATE;            -- no row → ROLLBACK, stop
DELETE FROM findings WHERE scan_id = $1;
DELETE FROM unchecked_deps WHERE scan_id = $1;
INSERT INTO findings ...;
INSERT INTO unchecked_deps ...;
UPDATE scans SET status = 'completed', coverage = $3, ... WHERE id = $1 AND attempt = $2;
COMMIT;
```

### Failures
- Transient (timeouts, 5xx, rate limits): the worker writes `status = 'retrying'` + `error_message`
  (attempt-guarded), then throws so pg-boss retries with backoff. The next claim sets `running` again.
- Unrecoverable (repo not found/private, other 403) and `unsupported`: mark the scan (attempt-guarded),
  then **return normally — do not throw**, or pg-boss will retry a permanent failure.
- Some OSV lookups fail → `completed`, coverage `partial`, failed ones in `unchecked_deps`.
- All lookups fail → `failed`.
- AI failure never fails a scan and never affects coverage.

### Retries exhausted / stuck scans (no code runs when pg-boss gives up)
- **Last attempt throws:** the worker compares `job.retryCount` with `retryLimit` (`work(..., { includeMetadata: true })`,
  verified in M0); on the final attempt it marks the scan `failed` ("retries exhausted: <reason>") instead of
  `retrying`, then throws.
- **Dead letter (supported, verified in M0):** the scan queue has `deadLetter` set. pg-boss copies the job's
  data to the dead-letter queue when retries are exhausted, both after a throw and after the final attempt
  expires or misses its heartbeat (worker crash). Its handler marks the scan `failed` only if still
  non-terminal. It does not check `attempt` (the attempt that died never finished).
- **Sweeper (safety net for crashes/hangs):** pg-boss decides, time only narrows the search.
  It selects non-terminal scans whose `updated_at` is older than job expiry + margin, looks up each
  scan's `job_id` in pg-boss (`findJobs(queue, { id })`), and fails the scan only if the job is finished
  (failed/completed/cancelled) or missing. pg-boss 12 has no archive table: jobs are deleted after
  `deleteAfterSeconds` (finished, default 7 days) or `retentionSeconds` (never started, default 14 days).
  With dead-lettering covering crashes, the sweeper is defence in depth (DLQ handler down, job deleted). A job that is still queued, retrying or active is left alone, so queue
  backlog, backoff and worker downtime never fail a healthy scan.
- Dead-letter handler and sweeper both do
  `UPDATE scans SET status='failed', attempt = attempt + 1, ... WHERE id = $1 AND status NOT IN (terminal)`.
  Bumping `attempt` fences any zombie worker: its later writes match 0 rows and it stops.

### Queue settings (pg-boss 12, verified in M0 — see `test/contract/pgboss.test.ts`)
Everything below is tested there unless marked as read from the source or as a proposal.
- `heartbeatSeconds` (min 10): a worker that stops heartbeating (crash, kill -9) has its job retried after
  about that long. Without it, a crashed job only comes back after `expireInSeconds` (default 15 min).
  `work()` refreshes the heartbeat every `heartbeatSeconds / 2` while the handler runs, so a healthy
  attempt longer than `heartbeatSeconds` is not retried or run twice (tested with a 25 s handler, 10 s heartbeat).
  Proposed: `heartbeatSeconds: 30`, `expireInSeconds: 300` (upper bound on one scan attempt).
- Missed heartbeat on the last attempt → job `failed` and dead-lettered, same as expiry.
- `job.signal` is aborted when the job expires (tested) and, per the 12.38 source (`manager.js`
  `#processJobs`), when a heartbeat refresh finds the claim gone. Either way the attempt no longer owns the
  job; the pipeline passes the signal to its HTTP calls so it stops doing work.
- `retryCount` identifies the attempt; `complete` and `fail` given `{ id, retryCount }` are ignored for a
  stale attempt (both tested). This fences pg-boss's job row only; our `scans.attempt` guard is still what
  fences scan rows.
- Backoff: with `retryBackoff: true` the delay before retry n is about `retryDelay × 2^(n-1)` (with jitter),
  capped by `retryDelayMax`. Proposed for scans: `retryLimit: 3`, `retryDelay: 5`, `retryBackoff: true`,
  `retryDelayMax: 60`.
- `send` accepts a caller-chosen `id`, so the job id can be the scan id (one id to trace).

### Supported input
- `package-lock.json` at repo root, `lockfileVersion` 2 or 3. Otherwise `unsupported` with reason
  (e.g. only `yarn.lock`, lockfile v1).
- Entries with local/git/tarball sources → `unchecked_deps` reason `unsupported_source`.
- Valid lockfile with zero deps → `completed`, "no dependencies to check".
- `full` coverage = every supported dependency in the root lockfile was checked. Says nothing about the
  rest of the repository.

### GitHub fetching
- Resolve SHA (two calls): `GET /repos/{owner}/{repo}` for the default branch (also detects not found/private),
  then `GET /repos/{owner}/{repo}/commits/{default_branch}` for its SHA.
- Read the lockfile by SHA from `https://raw.githubusercontent.com/{owner}/{repo}/{sha}/package-lock.json`
  (the contents API won't inline files over 1 MB). Still follows the pinned-SHA rule.
- Optional `GITHUB_TOKEN` (unauthenticated limit is 60 requests/hour/IP). Works without it.
- 404 → `failed`, message "repository not found or private" (GitHub returns 404 for both).
- 403/429 with rate-limit headers (`x-ratelimit-remaining: 0`, `retry-after`) → transient, retry.
  Other 403 → unrecoverable.
- Lockfile 404 at that SHA → `unsupported` ("no package-lock.json at the repository root").

### Lockfile parsing rules
- Only `packages` keys containing a `node_modules/` segment are dependencies; the package name is the part
  after the last `node_modules/` (e.g. `node_modules/a/node_modules/@s/b` → `@s/b`). The root `""` entry is the
  project itself, and other keys (e.g. `packages/internal-utils`) are workspace folders: neither is checked or
  counted. Their dependencies already appear as `node_modules/...` keys.
- Entries with `link: true` (workspace packages, local code) are skipped entirely: not counted as checked
  or unchecked. Their own dependencies are already in the root lockfile.
- `resolved` starting with `file:`, `git+`, or a tarball URL that isn't the npm registry → `unchecked_deps`,
  reason `unsupported_source`.
- Scope: `dev: true` or `devOptional: true` → dev; `optional: true` → optional (runtime); neither → runtime.
- Direct = listed in the root package's `dependencies` / `devDependencies` / `optionalDependencies`.
- Dedupe by `name@version` before querying OSV.
- Tolerate entries without `resolved`/`integrity`.
- Finding granularity: one finding per `package@version` × advisory. Install paths are aggregated onto it
  (list of direct parents, `is_direct` true if any path is direct, scope = most exposed path).

### OSV usage
- `POST /v1/querybatch`: max 1000 queries per call → chunk. Results contain only `{ id, modified }` per vuln
  and may be paginated per query (`next_page_token`) → follow it. A package with no vulns returns `{}`.
  Pagination (verified, fixtures `pagination.*`): only a query with more than 1000 vulns gets a token, on its
  own result. Re-send just that query with `page_token: <token>`; pages don't overlap.
- Details: `GET /v1/vulns/{id}` once per unique advisory ID (dedupe across packages), concurrency limit
  (e.g. 8), timeout + retry per call.
- Shapes verified in M0 (fixtures in `test/fixtures/osv/`):
  - One advisory lists many `affected` entries: other packages and other ecosystems (e.g. lodash advisory
    also covers `lodash-es`, `lodash-rails`/RubyGems). Use only entries with `ecosystem: npm` and the exact name.
  - The same package can appear in several `affected` entries with different ranges (axios: `0.8.1–0.28.0`
    and `1.0.0–1.6.0`). Candidate selection looks at every matching entry and picks the range that
    contains the installed version.
  - Range events are `introduced` (may be `"0"`), `fixed`, or `last_affected`. `last_affected` or a
    missing `fixed` means no fix published. Some entries have only an explicit `versions` list and no ranges.
  - Severity label: `database_specific.severity` = `CRITICAL | HIGH | MODERATE | LOW` (MODERATE → medium).
    `severity[]` holds CVSS vectors only.
  - `MAL-` records (OpenSSF malicious-packages) have no `severity`, `aliases` or `references`, and a range
    `introduced: 0` with no fix. GitHub also publishes malware as `GHSA-*` ("Malicious Package in …",
    CRITICAL), often alongside the `MAL-` record for the same package; grouping by package keeps them in
    one malicious action.
  - Unknown id → HTTP 404.
- A package counts as `lookup_failed` if its batch query failed, or any of its advisory details couldn't
  be fetched. These feed `failed_lookups` and `unchecked_deps`.
- Severity: GHSA label from `database_specific.severity` when present; otherwise `unknown` (labelled).
  No CVSS parsing in this version (stated as next step).

### Ranking policy (deterministic)
1. Known malicious packages first (OSV `MAL-` advisories). Action: remove and rotate secrets, not upgrade.
2. Severity: critical › high › medium › low › unknown (labelled, never hidden).
3. Tie-breakers: runtime before dev; direct before transitive.
Fix information shapes the action, not the rank.

### Recommended next actions
- Group by package. At most three on the summary; the rest below.
- Candidate version = the fix event in the affected range that contains the installed version.
  Labelled "candidate"; compatibility, resolution and tests still to verify. Flag major-version jumps.
- Transitive package → name the direct parent that pulls it in.
- No fix event → "no fixed version published: review the advisory and upstream guidance, assess exposure".
- Counts say "addresses N advisories according to advisory data"; only a rescan confirms.
- Several advisories on one package@version: candidate = the highest per-advisory candidate. If that
  crosses a major version while a lower candidate would fix some advisories, show both ("4.x fixes 2 of 3;
  5.x needed for the third") and flag the major jump. Advisories with no fix are listed in the action
  as unresolved by any upgrade.
- Malicious (`MAL-`) entries usually have no ranges or fix: separate path, action "remove the package,
  check how it got in, rotate secrets that were available where it was installed".

### Evidence vs AI text
- AI writes only the summary paragraph and per-action "why it matters".
- Output validated with zod: structure + only known finding IDs. Prose truth can't be validated (stated in README).
- Timeout / invalid / no key → `TemplateExplainer`. `explanation_source` stored and shown.
- Small fixture-based eval: `npm run eval`.

### Coding-agent handoff prompt
Built from a template (no AI). Includes: repo, commit, packages with evidence; candidate changes
separated from facts; instructions to inspect the dependency graph first, keep unrelated changes,
use `npm install <pkg>@<version>`, stop and report on major-version jumps, run tests, rescan, report
unresolved items. User sees a preview before copying.

## Report layout (frozen order)
1. Summary line + scan date + commit + coverage (coverage always beside the summary)
2. Up to three recommended next actions: what, why first, how to verify
3. Evidence: expandable per action
4. All findings + unchecked dependencies
5. Copy coding-agent prompt (preview) / Scan again

Clean result: "No known vulnerabilities in N of M dependencies checked at commit X on <date>", what
wasn't checked, advisories change over time → rescan, suggest Dependabot / `npm audit` in CI.
Never says "secure". Partial clean is never shown as clean overall.

## API (sketch)
- `POST /scans` `{ repoUrl }` + `Idempotency-Key` → `202 { scanId }` | 400 | 409
- `GET /scans/:id` → status, stage, counts, coverage, error
- `GET /scans/:id/report` → summary, actions, findings, unchecked, agentPrompt, explanationSource
- `GET /` → UI; `/scans/:id` route in UI is shareable
- `GET /health/live`, `GET /health/ready`

## Known limits (state in README)
- No rate limiting on `POST /scans`; worker concurrency set via pg-boss options only.
- Idempotency keys are kept indefinitely (no retention job).
- Public github.com repos only; root `package-lock.json` only.
