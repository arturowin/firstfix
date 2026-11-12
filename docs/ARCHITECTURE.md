# Architecture

FirstFix reviews the npm dependencies of a GitHub repository at a specific commit: public repositories
anonymously, private ones after GitHub sign-in (see [Private repositories](#private-repositories-m6)). See the
[README](../README.md) for the product goals, setup, and demo.

## Components
The Fastify API and background worker share one PostgreSQL database. GitHub and OSV requests can take
time or fail temporarily, so the API returns a scan ID after recording the job. The worker controls
scan concurrency and handles retries. Using PostgreSQL for both scan data and the queue lets the API
create the scan and enqueue its job in one transaction.

- **API** (`src/api/main.ts`): HTTP routes (zod, Idempotency-Key), `ScanService`, static UI.
  Uses the submission and scan repository ports.
- **Worker** (`src/worker/main.ts`): `ScanPipeline` = claim → resolve SHA → find a supported lockfile @SHA →
  parse with its ecosystem's format → advisory lookup (OSV) → rank → build actions → source checks → explain → save. Uses ports `RepoSource`, `VulnDatabase`,
  `Explainer`, `ScanRepository`.
- **Adapters**: GitHub REST API, OSV.dev (the advisory source; see "Advisory source"), LLM (+ template fallback), Postgres, pg-boss.
- Plain composition root per process; no DI framework. Contract tests show adapters are substitutable.
- **Private repositories (M6, optional):** GitHub sign-in and a FirstFix GitHub App. The API resolves sessions
  and repository access through `AccessService` (ports `GitHubAuth`, `SessionStore`); the worker reads private
  repositories with a per-scan installation token through the same `RepoSource` port. See
  [Private repositories](#private-repositories-m6).
- **Source checks (M7):** two targeted JavaScript/TypeScript checks for disabled TLS verification, in the same
  worker and job, after the dependency check. See [Source checks](#source-checks-m7).

## Project layout

```text
src/api/           HTTP routes and API entry point
src/worker/        Queue handlers and worker entry point
src/application/   Scan orchestration and report assembly
src/domain/        Lockfile parsing, ranking, and remediation rules
src/ports/         Interfaces for application dependencies
src/adapters/      GitHub, OSV, Postgres, pg-boss, and explainers
src/web/           Browser UI
migrations/        PostgreSQL schema migrations
test/              Unit, integration, and contract tests
```

## Data model (current: migrations 001-010)
Migration 011 (private repositories) is described under
[Private repositories](#private-repositories-m6), and migration 012 (source checks: per-check outcomes and
`source_findings`) under [Source checks](#source-checks-m7).
```
scans(id uuid pk,            -- also the pg-boss job id (send({ id })), same submission tx
      repo_owner, repo_name, repo_url_normalized, commit_sha null,
      lockfile_path null,         -- which lockfile was scanned, e.g. 'package-lock.json' (002)
      status, stage null, attempt int default 0,
      total_deps int, checked_deps int, unsupported_deps int, failed_lookups int,
      coverage null,              -- 'full' | 'partial'
      advisory_source null,       -- e.g. 'OSV.dev', named in the report (003)
      explanation jsonb null,     -- { source, summary, actions: { "<eco>:<pkg>": { text, source } }, fallbackReason? } (007)
      explanation_source null,    -- 'ai' | 'template'
      summary_line text null, error_code null, error_message null,
      created_at, updated_at, completed_at null)   -- index on completed_at for retention (009)

findings(id pk, scan_id fk,
         ecosystem,                -- canonical ecosystem id (OSV's naming), 'npm' (002; in the unique key)
         package, installed_version,   -- package = the real name advisories use
         installed_as text[],      -- every install name when an npm alias differs (005)
         direct_as text[],         -- names the project declares it under directly; each needs updating (006)
         scope,                    -- 'runtime' | 'optional' | 'dev' (most exposed path)
         is_direct bool,           -- true if any install path is direct
         direct_parents text[],    -- all direct deps that pull it in (empty if direct)
         install_paths jsonb,      -- e.g. [["express","body-parser","qs"]], capped; deep ones abbreviated around "…"
         context_truncated bool,   -- parents/paths were cut to bound work; the finding itself is complete (010)
         advisory_id, aliases text[], severity, is_malicious bool,
         title, affected_ranges jsonb,   -- neutral AffectedRange[] (see "Advisory source"), not provider JSON
         candidate_version null, fix_status,   -- 'candidate' | 'no_fix' | 'unknown', kept consistent (004)
         references jsonb)

unchecked_deps(scan_id fk, ecosystem, package, version null,
               reason)   -- 'unsupported_source' | 'lookup_failed' | 'invalid_name' (008)

idempotency_keys(key pk, request_hash, scan_id fk, created_at)   -- index on created_at for retention (009)
```
Every string written to jsonb is made storable first (`src/domain/text.ts`): PostgreSQL rejects `\u0000` and
unpaired surrogates, which would otherwise abort a report transaction.
Store `package` and `candidate_version` on findings so grouping into actions is a query, not a migration.

## Lifecycle
`queued → running(stage: fetching → scanning → analyzing) → completed`
Other outcomes: `unsupported` (no supported lockfile, reason stored), `failed` (unrecoverable or
retries exhausted). `retrying` while a transient error is being retried.
Terminal: `completed`, `unsupported`, `failed`.
**Scan outcomes and test coverage**

| Outcome | How it is reached | Test |
|---|---|---|
| `queued` | submission: scan row + job in one transaction | `integration/submission`, `integration/api` |
| `running` (fetching → scanning → analyzing) | claim, then stage writes | `integration/pipeline`, `integration/failures` (mid-scan) |
| `completed`, coverage `full` | all supported deps checked | `integration/end-to-end`, `integration/pipeline` |
| `completed`, coverage `partial` | one or more advisory lookups failed or were incomplete, and at least one package returned evidence | `integration/pipeline`, `contract/osv`, `contract/vuln-database.contract` |
| `completed`, nothing checkable | all deps from unsupported sources | `integration/pipeline` |
| `unsupported` | no lockfile, lockfile v1, invalid JSON, empty repo, too large | `integration/pipeline`, `contract/github` |
| `retrying` | transient error (or bug) on a non-final attempt | `integration/pipeline`, `integration/failures` |
| `failed`: not found / private / bad token | permanent error, not retried | `integration/pipeline`, `integration/end-to-end` |
| `failed`: retries exhausted | transient error on the last attempt (incl. every lookup failing) | `integration/pipeline`, `integration/failures` |
| `failed`: last attempt crashed | dead-letter handler | `integration/failures` |
| `failed`: job finished or missing | sweeper | `integration/failures` |
| stale attempt / duplicate job / zombie | attempt guard, `failIfOpen` bumps attempt | `integration/scan-repository`, `integration/pipeline`, `integration/failures` |

The browser polls `GET /scans/:id` for persisted progress. During advisory lookup, the UI shows
how many dependencies it is checking.

## Contracts

### Request idempotency
- Same `Idempotency-Key` + same normalized request → same scan (200/202 with existing id).
- Same key + different request → 409.
- Rescan = new key = fresh lookup. Completed scans are never reused automatically.
- Browser (`src/web/submission.ts`): one key per intended submission, reused when retrying after a network
  error, a lost response, 429 or 503; cleared by a successful answer (the next deliberate scan gets a new key)
  or a non-retryable 4xx. One shared guard for the button, Enter and "Scan again": locked while submitting and
  while the page follows an unfinished scan (also after reloading its page); only the followed scan's terminal
  state unlocks it, so a late answer about an older scan can't. A polling error keeps the lock and offers
  "Check again", which never resubmits.
- Normalize URL: lowercase owner/repo, strip `.git`, trailing slash; only `github.com`.

### Submission
The scan row and pg-boss job are created in one transaction. With pg-boss 12.38, `send(..., { db })`
with `db.executeSql` bound to our transaction's client joins that transaction; rollback leaves no job.
`send` returns `null` only when it dedupes (duplicate `id` or singleton options); treat `null` as an error
and roll back the submission.
Admission control in the same transaction: a transaction-scoped advisory lock serializes an exact count of
outstanding scans against `MAX_OUTSTANDING_SCANS`; the Idempotency-Key is checked again under that lock, so a
concurrent replay of the request that took the last slot gets its scan (or 409), never 503. The API also has a
fixed one-minute per-client limit on `POST /scans` (`SUBMIT_RATE_PER_MINUTE`, 429). Each API instance
keeps its own rate-limit counters in memory.

### Attempt ownership
- Claim: increment `attempt`, skip if terminal (duplicate delivery is a no-op).
- Worker progress and outcome writes match `id` and `attempt`; 0 matching rows means the worker no
  longer owns the scan. The claim and recovery paths advance the attempt as described below.
- Status changes set only `status` (+ outcome fields). A `BEFORE UPDATE` trigger on `scans` does the
  bookkeeping: sets `updated_at`, clears `stage` unless `running`, stamps `completed_at` on entering a terminal
  state, and prevents terminal scans from reopening. A rescan creates a new scan.
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
- Transient (timeouts, 5xx, rate limits, and unexpected errors with a generic message): the worker writes
  `status = 'retrying'` + reason (attempt-guarded), then throws so pg-boss retries with backoff. The next claim
  sets `running` again. On the last attempt (`retryCount === retryLimit`) it writes `failed`
  ("Retries exhausted: <reason>") instead. A job whose signal aborted (expired, stopped) writes nothing.
- Unrecoverable (repo not found/private, other 403) and `unsupported`: mark the scan (attempt-guarded),
  then **return normally — do not throw**, or pg-boss will retry a permanent failure.
- Failed or incomplete lookups produce a partial report when at least one package lookup succeeds or
  returns partial evidence. Both outcomes are listed in `unchecked_deps`.
- If every queryable package's lookup fails outright, retry with backoff and mark the scan `failed` when
  attempts run out.
- AI failure never fails a scan and never affects coverage.

### Exhausted retries and lost jobs
- **Dead letter.** the scan queue has `deadLetter` set. pg-boss copies the job's
  data to the dead-letter queue when retries are exhausted, both after a throw and after the final attempt
  expires or misses its heartbeat (worker crash). Its handler marks the scan `failed` only if still
  non-terminal. It does not check `attempt` (the attempt that died never finished).
- **Sweeper (safety net for crashes/hangs):** pg-boss decides, time only narrows the search.
  It selects non-terminal scans whose `updated_at` is older than job expiry + margin, looks up each
  scan's id in pg-boss (`findJobs(queue, { id })`, job id = scan id), and fails the scan only if the job is finished
  (failed/completed/cancelled) or missing. pg-boss 12 has no archive table: jobs are deleted after
  `deleteAfterSeconds` (finished, default 7 days) or `retentionSeconds` (never started, default 14 days).
  With dead-lettering covering crashes, the sweeper is defence in depth (DLQ handler down, job deleted). A job that is still queued, retrying or active is left alone, so queue
  backlog, backoff and worker downtime never fail a healthy scan.
- The sweeper (`src/application/lost-scans.ts`, wired in `src/worker/scan-worker.ts`) runs in every
  worker every 60 s (`SWEEP_INTERVAL_MS`) with staleness 600 s (`SWEEP_STALE_AFTER_SECONDS`: expiry 300 s +
  backoff + margin); several workers sweeping at once is harmless (the update only matches open scans).
  Each sweep checks at most 500 stale scans in pages of 100, resuming from where the last sweep stopped (keyset
  cursor on `(updated_at, id)`, kept in memory) and wrapping at the end, so a backlog of healthy stale scans
  can't hide a lost one.
- Dead-letter handler and sweeper both do
  `UPDATE scans SET status='failed', attempt = attempt + 1, ... WHERE id = $1 AND status NOT IN (terminal)`.
  Bumping `attempt` fences any zombie worker: its later writes match 0 rows and it stops.

### Worker restarts (Compose)
The worker service has `restart: unless-stopped`. A worker that exits unexpectedly is brought back, and its
unfinished job (kept in Postgres by pg-boss) is retried once the heartbeat lapses, with no new submission.
Verified in a disposable Compose project: the worker process exited abruptly mid-scan (code 1, no shutdown
handling); Docker restarted it and the same scan id completed ~71 s later (attempt 2, job retry_count 1), one
scan and one job in the database. `docker kill` is not a crash for this purpose: Docker treats it as a manual
stop and `unless-stopped` leaves the container down; `docker compose stop` stops it as intended.

### Queue settings
See `test/contract/pgboss.test.ts` for the pg-boss 12 contract checks.
- `heartbeatSeconds` (min 10): a worker that stops heartbeating (crash, kill -9) has its job retried after
  about that long. Without it, a crashed job only comes back after `expireInSeconds` (default 15 min).
  `work()` refreshes the heartbeat every `heartbeatSeconds / 2` while the handler runs, so a healthy
  attempt longer than `heartbeatSeconds` is not retried or run twice (tested with a 25 s handler, 10 s heartbeat).
  The scan queue uses `heartbeatSeconds: 30` and `expireInSeconds: 300` (upper bound on one scan attempt).
- Missed heartbeat on the last attempt → job `failed` and dead-lettered, same as expiry.
- `job.signal` is aborted when the job expires (tested) and, per the 12.38 source (`manager.js`
  `#processJobs`), when a heartbeat refresh finds the claim gone. Either way the attempt no longer owns the
  job; the pipeline passes the signal to its HTTP calls so it stops doing work.
- `retryCount` identifies the attempt; `complete` and `fail` given `{ id, retryCount }` are ignored for a
  stale attempt (both tested). This fences pg-boss's job row only; our `scans.attempt` guard is still what
  fences scan rows.
- Backoff: with `retryBackoff: true` the delay before retry n is about `retryDelay × 2^(n-1)` (with jitter),
  capped by `retryDelayMax`. The scan queue uses `retryLimit: 3`, `retryDelay: 5`, `retryBackoff: true`,
  `retryDelayMax: 60`.
- `send` accepts a caller-chosen `id`: the job id **is** the scan id (one ID to trace).

### Supported input
- `package-lock.json` at repo root, `lockfileVersion` 2 or 3. Otherwise `unsupported` with reason
  (e.g. only `yarn.lock`, lockfile v1).
- Entries with local/git/tarball sources → `unchecked_deps` reason `unsupported_source`.
- Valid lockfile with zero deps → `completed`, "no dependencies to check".
- `full` coverage = every supported dependency in the root lockfile was checked. Says nothing about the
  rest of the repository.

### Ecosystem extension points
npm is the implemented ecosystem. Format parsing, version comparisons, and remediation guidance are
registered separately from the scan lifecycle, ranking, and attempt-guarded writes.

- **Ecosystem id:** we use OSV's ecosystem names as our canonical ids (`npm`, later e.g. `PyPI`, `crates.io`,
  `RubyGems`, `Go`, `Packagist`, `NuGet`). A naming choice, not a dependency: the OSV adapter passes them
  through; another advisory source's adapter maps its own names.
- **Lockfile format** (pure, `src/domain/ecosystems/`): `{ ecosystem, fileNames, parse(text) }`, returning the
  existing `ParseLockfileResult` (`ok` | `unsupported` | `invalid`). The ecosystem is the format's, attached by
  the pipeline to every package, so a parser cannot mislabel one. A registry lists the supported formats in
  priority order; today only `package-lock.json`. A second format for the same ecosystem (`yarn.lock`,
  `pnpm-lock.yaml`) is another entry. Parsing does no I/O, so formats live in `domain/`, not behind a port.
- **Version scheme** per ecosystem: `compare`, `isMajorJump`, `inRange(version, range: AffectedRange)`. npm uses `semver`.
  An ecosystem without a scheme still reports findings, but with no candidate version and no major-jump
  flag ("see the advisory for fixed versions"); never a guessed version.
- **Remediation hints** per ecosystem (pure): the upgrade command for the agent prompt
  (`npm install <pkg>@<version>`) and the CI tool for the clean result (Dependabot / `npm audit`).
- **Ports are ecosystem-neutral:** `RepoSource.readFile(repo, sha, path)` (pinned to the SHA, replaces
  `readLockfile`); `VulnDatabase.lookup` takes `{ ecosystem, name, version }`, keyed `ecosystem:name@version`
  so ecosystems can't collide.
- **Detection:** the pipeline tries each registered format's `fileNames` at the repo root, in registry order,
  and scans the first found. None found → `unsupported` naming the supported files. The scanned path is
  stored in `scans.lockfile_path` and shown beside coverage.
- **One lockfile per scan.** Scanning several (e.g. npm + Python in one repo) needs per-lockfile coverage;
  out of scope, stated in README.
- **Lockfile ecosystems only.** Advisory lookups need exact versions. Ecosystems with lockfiles (Cargo.lock, poetry.lock /
  uv.lock, Gemfile.lock, composer.lock, packages.lock.json, go.mod) fit these seams. Manifests with ranges and
  no lock (plain `requirements.txt`, Maven `pom.xml`) need dependency resolution first: a different problem.
- **Proof:** a test-only fake ecosystem (own file name, parser, version scheme) goes through the pipeline with
  GitHub and OSV mocked; nothing outside the registry changes.

### GitHub fetching
- Resolve SHA (two calls): `GET /repos/{owner}/{repo}` for the default branch (also detects not found/private),
  then `GET /repos/{owner}/{repo}/commits/{default_branch}` for its SHA.
- Read the lockfile by SHA from `https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}`, where `path`
  comes from the lockfile-format registry (the contents API won't inline files over 1 MB). Still follows the
  pinned-SHA rule.
- Optional `GITHUB_TOKEN` (unauthenticated limit is 60 requests/hour/IP), used for public API calls only after
  the worker verifies it can't read private repositories. Lockfiles of public scans are read without
  credentials. Works without it. Private scans: see [Private repositories](#private-repositories-m6).
- 404 → `failed`, message "repository not found or private" (GitHub returns 404 for both).
- 403/429 with rate-limit headers (`x-ratelimit-remaining: 0`, `retry-after`) → transient, retry.
  Other 403 → unrecoverable.
- Lockfile 404 at that SHA → `unsupported` ("no package-lock.json at the repository root").

### Private repositories (M6)
Sign-in and private scanning are on only when the GitHub App settings are configured; without them FirstFix
behaves exactly as before (public repositories, no sign-in).

**Who can use it.** Any GitHub user, including an ordinary organization member, signs in with GitHub and scans
the repositories that **both** they and the FirstFix GitHub App can access. GitHub decides: the app must be
installed for the repository (by its owner, or approved by an organization owner), and the user must have read
access to it (owner, collaborator or through organization membership). Being an organization member, or having
access to an installation, is not enough on its own. FirstFix keeps no organizations, memberships, invitations
or roles.

**Flow.**
1. **Sign in** (`/auth/login` → GitHub → `/auth/callback`): OAuth for the GitHub App's user tokens with `state`
   and PKCE (S256). The state is stored server-side (`oauth_states`), bound to the browser by a random nonce in
   a short-lived `__Host-firstfix_oauth` cookie (only its hash is stored), expires after 10 minutes and is
   consumed exactly once (`DELETE … RETURNING`). The only accepted return paths are `/` and `/scans/<uuid>`.
2. **Discover installations**: `GET /user/installations` with the user's token (all pages) lists the app's
   installations the user can access, including organization installations installed by someone else.
3. **Connect GitHub** (when needed): `/github/connect` sends the user to the app's install page. GitHub's
   setup-URL redirect carries an `installation_id`; it is trusted only if that id is among the user's
   installations, fetched fresh (GitHub warns the parameter can be spoofed). A member who can't install the
   app can request it from an organization owner; GitHub's docs don't describe the redirect for a request, so
   FirstFix tracks no pending state. A return without a verifiable installation shows a truthful message: if
   approval was requested, an owner must approve it on GitHub, and the organization appears here once approved.
4. **Pick a repository**: `GET /user/installations/{id}/repositories` (all pages, 100 per page) lists the
   repositories both the user and the app can access, labelled by owner, with their visibility.
5. **Scan**: the picked repository is submitted like any URL. For a signed-in user the API looks it up among
   the repositories of the installation for its owner; a private match becomes a private scan bound to that
   repository id and installation id. Everything else is a public scan, exactly as before.

**Repository identity.** A private scan is bound to the GitHub repository id and installation id recorded at
submit, never to `owner/name`. A rename or transfer keeps the id; the worker and every access check use the
recorded ids.

**Who can view a scan.**
- Public-repository scans stay anonymous and link-shareable.
- A private-repository scan is visible only to a signed-in user whose repository list for the recorded
  installation contains the recorded repository id. The rule is pure (`src/domain/access.ts`); the GitHub
  answer is its input.
- The check runs on submit and on every status and report read.

| Request for a scan that is… | No session cookie | Expired or unknown session | Active session |
|---|---|---|---|
| public | 200 | 200 | 200 |
| private, viewer has access | 404 | 401 `session_expired` | 200 |
| private, no access | 404 | 401 `session_expired` | 404 |
| missing | 404 | 401 `session_expired` | 404 |

So without a valid session, missing and private scans look the same.

**Sessions and the access cache.**
- A session lasts until its user token expires (8 hours, the GitHub default; capped at 8 hours if the app
  issues non-expiring tokens). Refresh tokens aren't stored. Session expiry is checked before any access
  check, cached or fresh.
- The user's installations, and each installation's repository list, are cached in memory per API instance,
  keyed by session (and installation), for a fixed 5 minutes from GitHub's answer. An expired entry is never
  reused; the cache is bounded in size.
- GitHub rejects the user token (`401`) → the session is deleted, its cache entries dropped, the client gets
  `401 session_expired`.
- GitHub unavailable (timeout, `5xx`, rate limit) and no live cache entry → `503 github_unavailable`; an outage
  never extends an earlier decision. Each check has its own deadline; when it expires, that is also
  "GitHub unavailable" (`503`, or `?auth_error=github_unavailable` during sign-in), never a server error or
  "no access".
- Logout deletes the session and its cache entries. Going to **Connect GitHub**, and returning through the
  setup URL, drop the session's cached lists too (GitHub may not redirect back after an access change), so
  the next look is fresh.
- Request logs record the path only, never the query string (the OAuth callback carries the code and state).

**Two kinds of token, kept apart.**
- The user's token stays in the API: AES-256-GCM encrypted at rest in `sessions` (key derived from
  `SESSION_SECRET`), used only for installation and repository listings, never in logs, responses, job
  payloads or the worker.
- The worker creates its own installation token per scan with the app's private key (RS256 JWT via
  `node:crypto`, `iss` = client id, `iat` 60 s in the past, 9-minute expiry), scoped with `repository_ids` to
  the recorded repository and `permissions: { contents: read, metadata: read }`, cached until 5 minutes
  before it expires. The job still carries only the scan id.

**Private pipeline path.** `RepoSource` takes an `access` argument: `public`, or `installation` (installation id
and repository id). For a private scan the worker mints the scoped token, lists `GET /installation/repositories`
(which can only contain that repository) and requires the recorded id, then resolves the default branch and
reads the lockfile through the contents API (`application/vnd.github.raw+json`) at the pinned SHA. Domain,
ranking and report are unchanged.

**Public and private paths never mix.**
- Visibility is fixed at submit and never changes for that scan, through retries and completion. A private
  scan stays private even if the repository later becomes public.
- A public scan never uses installation or user credentials, and its lockfile is always read without
  credentials.
- `GITHUB_TOKEN` (optional, for API rate limits) is used only if the worker verifies at startup that it
  can't read private repositories: a classic token with the `repo` scope, or any token that lists a private
  repository (`GET /user/repos?visibility=private`), is refused and the worker runs unauthenticated (logged).
- Every public attempt re-reads repository metadata without private access. A repository that became private
  (or is gone) answers `404`, and the scan ends permanently `failed` (`repo_not_found`) with no findings.

**Failures.**
- Submit: GitHub unavailable during the lookup → `503` (resending with the same Idempotency-Key is safe);
  expired session → `401`.
- Worker, private path: installation gone or suspended, or the repository no longer in it (`404`, `422`,
  `403` without rate-limit headers when minting, or an empty repository list) → permanent `failed`
  `app_access_revoked`; app credentials rejected (`401`) → permanent `failed` `github_app_auth`; app not
  configured in the worker → permanent `failed` `github_app_not_configured`. Timeouts, `5xx` and rate limits
  stay transient and are retried.
- A private file that answers `404` counts as missing only after the scoped listing confirms the repository is
  still accessible; otherwise it is `app_access_revoked`, never "no supported lockfile".

**Browser behaviour.**
- On `401` while following or viewing a scan, the page stops polling and offers "Sign in again to continue",
  returning to the same scan afterwards. On `404` it stops polling; when signed out it adds "If this is a
  private scan, sign in to view it". Neither is retried.
- Logout stops polling, clears any rendered results and returns to the start page.

**Responses.** `Cache-Control: no-store` on scan status and reports, `/me`, the repository picker, `/auth/*`
and `/github/*`; session-dependent answers also send `Vary: Cookie`. Session-authenticated POSTs must carry
an `Origin` equal to `PUBLIC_URL`'s origin (`403 bad_origin` otherwise); cookie-less API clients are unaffected.

**Data handling.** OSV receives package names and versions only, never code, as for public repositories.
AI explanations work as for public repositories: when `LLM_API_KEY` is set, the LLM provider receives the same
facts (the repository name and the report's structured findings: package names, versions, advisory ids),
never code.

**Data model (migration 011).** `scans.visibility` (`'public'` default), `github_repo_id`, `installation_id`,
`submitted_by` (a private scan must have both ids); `sessions(key_hash pk, github_user_id, github_login,
token_encrypted, expires_at, created_at)`; `oauth_states(state_hash pk, binding_hash, verifier_encrypted,
return_to, expires_at)`. Expired sessions and states are removed by the retention job. The idempotency request
hash includes the signed-in user, so the same key from another user gets `409`.

**Cookies and configuration.** Cookies are parsed and set with `@fastify/cookie`. The session cookie is
`__Host-firstfix_session`: HttpOnly, Secure, SameSite=Lax, Path=/. Settings: API: `GITHUB_APP_CLIENT_ID`,
`GITHUB_APP_CLIENT_SECRET`, `GITHUB_APP_SLUG`, `SESSION_SECRET`, `PUBLIC_URL` (https, or http on localhost);
worker: `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_PRIVATE_KEY`. Partly configured → the process refuses to start.

**Known limits.** No webhooks and no refresh tokens: users sign in again after at most 8 hours; revoked access
can still allow views for up to 5 minutes (the cache lifetime); a removed installation is noticed at the next
use. A repository list longer than 10,000 entries per installation is cut off (and reported as truncated);
repositories beyond it can't be picked or viewed through FirstFix.

### Source checks (M7)
Besides dependencies, FirstFix runs two targeted, heuristic checks of JavaScript/TypeScript source for disabled TLS
certificate verification. They are not general static analysis (SAST): a textual match doesn't prove that the code
runs, or that the application can be exploited.

**Shape.** The same worker, the same `scan` job and the same commit. No new queue, service, worker or external
scanner; no new parsing library; repository code is never executed and its dependencies are never installed.

```
claim → resolve commit (sha + tree sha) → dependency check → source check → prioritize + explain → complete (one locked tx)
```

**Rules** (`src/domain/source-rules.ts`, pure). Each has an id and a version; the explanation and next action are
deterministic text from the catalog, looked up by id and version at report time.

| Rule | Matches | Severity | Meaning |
|---|---|---|---|
| `FF-TLS-001` v1 | `process.env.NODE_TLS_REJECT_UNAUTHORIZED = <v>` and `process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = <v>` (any quotes), where `<v>` is `'0'`, `"0"`, `` `0` `` or the number `0` | high | Disables certificate verification for every TLS connection the Node.js process makes, if this line runs. |
| `FF-TLS-002` v1 | An object property `rejectUnauthorized: false` (identifier or quoted key, directly after `{` or `,`), or a member assignment `<expr>.rejectUnauthorized = false` / `<expr>['rejectUnauthorized'] = false` | medium | Turns off certificate verification for the client or agent it configures. Potentially insecure; needs context review (test-only code is common). |

**Detection** (`src/domain/source-scan.ts`, pure). A small error-tolerant JS/TS tokenizer, not a parser.
- **Tokens:** identifiers, punctuation, numbers, string literals (with their decoded value, `\x30` included) and
  template literals.
- **Skipped as code:** `//` and `/* */` comments. Templates with `${…}` substitutions and regular-expression literals
  are opaque (a `/` starts a regex by the usual previous-token heuristic).
- **Matching:** rules match token sequences, so whitespace, line breaks and quote style don't matter, and text
  inside comments, strings, templates and regexes never matches.
- **The value must be the whole assignment:** `= '0' + x`, `= '0' || y`, `=== '0'` and a ternary
  `a ? rejectUnauthorized : false` don't match.
- **Positions:** line and column are 1-based, in UTF-16 code units, as editors and GitHub count them; `\r\n` is one
  line ending.
- **Excerpt:** the matched tokens re-joined (no comments, no other string literals), at most 200 characters, so a
  credential on the same line is never stored.
- **Robustness:** unterminated strings end at the line break, unterminated comments at the end of the file.
  Template nesting (templates and `${…}` substitutions) is bounded at 64 levels. A file nested deeper is reported
  `unparsed` instead of exhausting the stack, and counted as not checked (`skippedParse`, partial coverage). The
  source check also catches any other error from the scanner per file, so no input can fail the job or discard
  the dependency results.
- **Counting vs. storing:** every match is counted per rule (`source_counts.rules`: matches, files, matches in test
  files). Only 500 examples are stored, chosen by priority, not by the order files were fetched:
  1. higher severity;
  2. code outside tests;
  3. path, line and column.

  A rule never reads as "no match" because its examples were dropped. Summaries, the report and explanations use
  the counts, and the report says when more were found than are shown. Dropped examples don't make coverage
  partial, since every file was checked.

Known limits (also in the README):
- **False negatives:**
  - aliases (`const env = process.env; env.X = '0'`), keys built at runtime, `Object.assign(process.env, …)`,
    `??=`/`||=`, computed property keys;
  - values computed at runtime (`rejectUnauthorized: !verify`), `0` written another way (`!1`, `"0".trim()`);
  - code inside `${…}`, cross-file flows, `.mjs`/`.cjs`/`.mts`/`.cts`, and files outside the limits below.
- **False positives:**
  - a literal object type `{ rejectUnauthorized: false }` in a TypeScript type position;
  - quotes inside JSX text that the tokenizer reads as strings (rare);
  - dead code and test-only code, which are reported as found. Findings in test paths (`test/`, `tests/`,
    `__tests__/`, `__mocks__/`, `*.test.*`, `*.spec.*`) are labelled "test file".

**Source acquisition** (`RepoSource.listTree` / `readSourceFile`; pinned to the commit; the M6 credential rules).
- **Listing:** `GET /repos/{o}/{r}/git/trees/{tree_sha}?recursive=1`, with the tree SHA from the commit response
  already fetched (the trees API documents tree SHAs). Checked live on a public repository: `commit.tree.sha`, and
  entries with `mode`/`type`/`size` and `truncated`.
  - Public scans use the verified public-only `GITHUB_TOKEN` or none; private scans use the repository-scoped
    installation token.
  - `truncated: true` makes coverage partial.
  - Symlinks (mode `120000`) and submodules (mode `160000`, type `commit`) are counted, never followed.
- **Reading files:**
  - public: `raw.githubusercontent.com/{o}/{r}/{commit_sha}/{path}` without credentials, as for lockfiles;
  - private: the contents API at the commit SHA with the raw media type and the installation token. This is the
    path already proven live for lockfiles; the blobs API was not needed, and GitHub doesn't document its
    installation-token permissions.
  - A `404` while access holds counts as a fetch failure; lost access is `app_access_revoked`.
- **Eligible files:** `.js`, `.jsx`, `.ts`, `.tsx`.
  - Not eligible: `.d.ts`, `*.min.js`, `*.bundle.js`.
  - Excluded anywhere in the path: `node_modules/`, `bower_components/`, `jspm_packages/`, `vendor/`, `dist/`,
    `build/`, `out/`, `coverage/`, `.next/`, `.nuxt/`, `.svelte-kit/`, `.output/`, `.vercel/`, `.turbo/`,
    `.cache/`, `.yarn/`, `storybook-static/`, `generated/`, `__generated__/`.
- **Limits** (worker env):
  - `SOURCE_MAX_FILES` 200, `SOURCE_MAX_FILE_BYTES` 262144, `SOURCE_MAX_TOTAL_BYTES` 10485760;
  - 8 fetches at a time;
  - a 60-second budget for the whole check.
  - Files over the per-file limit are skipped from the tree's `size` (or while reading) without being stored.
  - Eligible files are taken in path order until a limit is reached; the rest are counted.
- **Nothing is kept:** file contents live only in memory during the check.

**Storage (migration 012).**
- `source_findings(scan_id fk on delete cascade, rule_id, rule_version, severity, path, start_line, start_col,
  end_line, end_col, excerpt ≤ 200)`.
- `scans` gains:
  - `source_status` (`complete` | `partial` | `no_files` | `failed`);
  - `source_counts jsonb` (`eligible`, `checked`, `skippedLimit`, `skippedSize`, `skippedLinks`, `skippedTime`,
    `fetchFailed`, `skippedParse`, `listingTruncated`, `findingsTruncated`, and `rules`: per-rule match counts);
  - `source_error_code`/`message`;
  - `dependency_status` (`complete` | `unsupported` | `failed`) with its error code and message.
  - All of these are NULL on older scans.
- The `stage` check gains `'source'`. `completed_has_coverage` allows a completed scan without dependency coverage
  only when its dependency check was `unsupported` or `failed`.
- Source findings never enter `findings`, the fix plan, upgrade counts or the dependency summary line.
- Both checks are written by `complete()` in the one transaction that locks the owned, non-terminal row; a stale
  attempt writes nothing. `finish()` also records both checks' outcomes when neither was usable.

**Overall status.** Each check is usable (`complete`, or `partial` with at least one file checked), has nothing to
check (`unsupported`, `no_files`), or `failed`.

| Case | Dependency check | Source check | Scan status | Report |
|---|---|---|---|---|
| a | complete | complete | `completed` | both sections |
| b | unsupported (no lockfile…) | usable | `completed` | "Dependencies were not checked" with the reason, then source checks |
| c | complete | partial | `completed` | partial source coverage, with counts |
| d | complete / failed | failed / usable | `completed` | the failed check shown as failed with its reason, never as clean |
| e | failed, or unsupported with source failed | not usable | `failed` | the dependency reason first; otherwise "Source checks failed: …. Dependencies: …" |
| e′ | unsupported | no_files | `unsupported` | the dependency reason (as before source checks) |
| f | any | no_files | from the dependency check | "Source checks: no JavaScript/TypeScript files to check." |

**Retries without child jobs.**
- **Earlier attempts:** a transient error in either check throws, and pg-boss retries the whole job. Nothing is
  saved halfway.
- **The last attempt:** each check catches its own transient error and ends `failed` ("Retries exhausted: …").
  - If the other check is usable, the scan completes with it.
  - If not (case e), the outcome is recorded and the original error is rethrown, so the queue records the job as
    failed, as before.
- **Some files fail to fetch:** `partial`, listing how many. All of them failing is transient.
- **Shared failures** keep their current semantics: repository not found, access revoked, app not configured,
  empty repository, cancellation.
- **AI failures** stay separate.

**Progress.** Stages run in this order: `fetching` (read dependencies) → `scanning` (check advisories) → `source`
(check source code) → `analyzing` (prioritize and explain, once both checks are in). A repository without a usable
lockfile goes from `fetching` straight to `source`.

**Explanations.**
- Source issues are explained like dependency actions. The summary paragraph covers both checks, and each matched
  rule gets a "why it matters" text (`StoredExplanation.sourceRules`), labelled AI or Template.
- What explainers receive about source checks (`SourceFacts`): per rule, the id, title, severity, the number of
  matches and files, and how many are in test files. They never receive file paths or code excerpts: both come
  from the repository and could carry instructions.
- `checkExplanation` requires exactly one entry per matched rule, and applies the same limits and bans as for
  actions. Source text may name no versions or advisory IDs.
- Without a usable dependency check the explainers are told so (`dependenciesChecked: false`) and say nothing
  about dependency vulnerabilities.
- When no AI is configured, or its reply fails the check, the template's text is used. The template uses the rule
  catalog's explanation plus where the matches are ("83 of 86 matches are in test files").
- The coding-agent prompt is unchanged.

**Report and UI.**
- When the dependency check didn't complete, the top card leads with the source result. It then shows both checks
  side by side ("Dependencies: not checked, <reason>" / "Source code: checked, N of M files"), so an unsupported
  lockfile doesn't read as if the scan stopped. Otherwise the dependency summary card also carries the source
  summary line.
- A "Source checks" section follows the dependency actions and findings, with one card per rule (most severe
  first):
  - severity, title, the number of matches and how many are in test files;
  - the "why it matters" text and the next action, once;
  - then every location: `path:line:column` linked to
    `https://github.com/{o}/{r}/blob/{sha}/{path}#L{start}[-L{end}]` at the scanned commit, a "test file" label,
    and the excerpt. The first 10 are shown, the rest under "N more".
- Coverage notes list what was skipped and why.
- Wording:
  - "No issues found by the 2 supported checks in N of M JavaScript/TypeScript files", never "secure";
  - older scans: "Source checks were not run for this scan".
- The API exposes `checks` on scan JSON, and `source` and `dependencyNotChecked` on reports.
- Private reports, source section included, follow the access rules in "Private repositories".

### Lockfile parsing rules
- Only `packages` keys containing a `node_modules/` segment are dependencies; the package name is the part
  after the last `node_modules/` (e.g. `node_modules/a/node_modules/@s/b` → `@s/b`). The root `""` entry is the
  project itself, and other keys (e.g. `packages/internal-utils`) are workspace folders: neither is checked or
  counted. Their dependencies already appear as `node_modules/...` keys.
- `link: true` entries are skipped as project code only when the target is a clean repo-relative path (no
  leading `/`, `./`, `..`, empty segments, backslashes or drive letters), exists in the lockfile, and matches a
  root `workspaces` glob (array or `{ packages }`). Every other link (e.g. `file:../local`, absolute paths,
  missing targets) is an unchecked dependency (`unsupported_source`), never hidden.
- Workspace globs come from an untrusted file, so matching uses no regexes (`workspaces.ts`): `*` within a
  segment, a whole `**` segment for zero or more segments. One 1,000,000-step budget per lockfile covers all
  patterns and locations; a match's full cost is charged before anything is allocated and only two rows of
  working memory are kept; results are cached per location. Out of budget means "not a workspace", so the link
  is reported, not hidden.
- `resolved` starting with `file:`, `git+`, or a tarball URL that isn't the npm registry → `unchecked_deps`,
  reason `unsupported_source`.
- Scope: `dev: true` or `devOptional: true` → dev; `optional: true` → optional (runtime); neither → runtime.
- Direct = declared by the project: the root package's or a workspace folder's `dependencies` /
  `devDependencies` / `optionalDependencies`, at the location that declaration resolves to.
- Graph (`src/domain/ecosystems/npm/graph.ts`): names resolve like Node (`<dir>/node_modules/<name>`, then
  upwards); installed packages contribute `dependencies`, `optionalDependencies`, `peerDependencies` (not
  `devDependencies`); links into workspace folders end a walk. Breadth-first from each direct dependency gives
  every direct parent and the shortest path from each; paths are capped at 5 per package version.
  Traversal bounds: predecessor pointers instead of path copies, at most 5 paths built
  per location, and a 5,000,000-step budget past which parents/paths are left empty (never partly filled);
  a 42 KB worst-case lockfile went from ~185 MiB / 1.2 s to ~24 MiB / 0.1 s. Paths are built from at most 12
  predecessor pointers (deeper ones keep the root, "…" and the last 10), so deep chains stay bounded too
  (a 3,999-edge chain: ~8,000,000 path entries / ~273 MiB → ~48,000 / ~12 MiB). Whenever context is cut,
  `context_truncated` is set and the report says so; findings are always kept.
- Dedupe by `name@version` before the advisory lookup.
- Tolerate entries without `resolved`/`integrity`.
- Package names and aliases must be valid npm names (`src/domain/ecosystems/npm/name.ts`): they come from a
  repository-controlled file and end up in suggested commands. Invalid ones are set aside as `invalid_name`
  (migration 008): not looked up, not a parent, not in paths, no command. Command builders validate names and
  versions again and omit the command if validation fails.
- Names or versions with control characters or invalid Unicode are also `invalid_name`, shown in a storable,
  visible form (control characters as the text `\uXXXX`, unpaired surrogates as U+FFFD); nothing is dropped.
- Finding granularity: one finding per `package@version` × advisory. Install paths are aggregated onto it
  (list of direct parents, `is_direct` true if any path is direct, scope = most exposed path).

### Advisory source (OSV implemented; provider-neutral contract)
OSV.dev is the only advisory source implemented. It sits behind the `VulnDatabase` port, so another provider
(GitHub Advisory Database, OSS Index, Snyk, deps.dev, …) is a new adapter plus one line in
`src/worker/main.ts`. Nothing outside `src/adapters/<provider>/` knows provider formats.

- **Contract:** for each `{ ecosystem, name, version }` the source returns its advisories, each with:
  `id`, `aliases`, `title`, `severity` (`critical|high|medium|low|unknown`), `isMalicious`, `affectedRanges`
  (neutral type below), `references`. Packages it could not check are reported per package
  (`lookup` → `{ advisories, failed, incomplete }`), so coverage can be partial; it rejects only when the job's signal
  aborts, never with provider HTTP errors. The OSV adapter retries each call once; a failed batch fails its
  packages. A failed detail fetch makes the packages citing that advisory incomplete. Responses are validated inside the
  same boundary: a malformed batch entry fails its package, a malformed record counts as a failed fetch, and
  translation is isolated per package.
- Pipeline: some failed → `completed`, `partial`, `lookup_failed` rows, `failed_lookups`, said in the summary
  line; all failed → `TransientError` (retried; `failed` with the reason once retries run out).
- **Neutral range type** (`src/domain/advisory.ts`, replaces the raw `affectedRanges: unknown[]`):
  `AffectedRange = { kind: 'range'; introduced; fixed | null; lastAffected | null } | { kind: 'versions'; versions }`.
  `introduced: '0'` = all earlier versions; `fixed: null` = no fix published; both `fixed` and `lastAffected`
  null = every later version affected. `versions` is for provider entries that list versions and no range.
  Candidate selection, the major-jump flag and the stored `findings.affected_ranges` use only this type.
- **The adapter owns all translation:** ecosystem names (ours are OSV's names; another adapter maps), range
  syntax (e.g. GitHub's `vulnerableVersionRange: "< 4.17.21"` + `firstPatchedVersion` → `AffectedRange`),
  severity labels (no label → `unknown`, shown, never hidden), and the malicious flag. The domain reads
  `isMalicious`; it never inspects id prefixes from a provider.
- **Shared contract tests:** one suite every `VulnDatabase` adapter must pass, run against recorded responses:
  ranges normalised, malicious flagged, no-fix represented, unknown id handled, transient vs permanent errors
  classified, and filtering by ecosystem and exact name.
- **Data source is named in the report** (e.g. "Advisory data: OSV.dev, fetched <date>"): providers differ in
  coverage (another source may lack OpenSSF malicious-package records) and in severity labels.

### OSV adapter (the current advisory source)
- `POST /v1/querybatch`: max 1000 queries per call → chunk. Results contain only `{ id, modified }` per vuln
  and may be paginated per query (`next_page_token`) → follow it. A package with no vulns returns `{}`.
  Pagination (verified, fixtures `pagination.*`): only a query with more than 1000 vulns gets a token, on its
  own result. Re-send just that query with `page_token: <token>`; pages don't overlap.
- Details: `GET /v1/vulns/{id}` once per unique advisory ID (dedupe across packages), concurrency limit
  (e.g. 8), timeout + retry per call.
- Response shapes covered by fixtures in `test/fixtures/osv/`:
  - One advisory lists many `affected` entries: other packages and other ecosystems (e.g. lodash advisory
    also covers `lodash-es`, `lodash-rails`/RubyGems). Use only entries with the scanned package's ecosystem
    and the exact name.
  - The same package can appear in several `affected` entries with different ranges (axios: `0.8.1–0.28.0`
    and `1.0.0–1.6.0`). Candidate selection looks at every matching entry and picks the range that
    contains the installed version.
  - Range events are `introduced` (may be `"0"`), `fixed`, or `last_affected`. `last_affected` or a
    missing `fixed` means no fix published. Some entries have only an explicit `versions` list and no ranges.
    The adapter turns each introduced/fixed or introduced/last_affected pair into one `AffectedRange`.
  - Severity label: `database_specific.severity` = `CRITICAL | HIGH | MODERATE | LOW` (MODERATE → medium).
    `severity[]` holds CVSS vectors only.
  - `MAL-` records (OpenSSF malicious-packages) have no `severity`, `aliases` or `references`, and a range
    `introduced: 0` with no fix. GitHub also publishes malware as `GHSA-*` ("Malicious Package in …",
    CRITICAL), often alongside the `MAL-` record for the same package; grouping by package keeps them in
    one malicious action. The adapter sets `isMalicious` for `MAL-` ids and for advisories whose
    `database_specific.cwe_ids` contains `CWE-506` (Embedded Malicious Code), which is how the recorded GitHub
    malware advisories are tagged. Never from title text.
  - The adapter first sorts a range's events with the ecosystem's version ordering ("0" lowest, ties
    stable; unorderable → listed order kept), then each `introduced` opens an interval and the next `fixed` /
    `last_affected` closes it; one left open affects all later versions. `limit` events apply to every
    interval of their range (affected only below some limit; `"*"` = unlimited) and are never a fix. Explicit
    `versions` lists are kept next to ranges (affected if in either). GIT ranges are skipped. Severity labels
    are translated in the adapter (`src/adapters/osv/translate.ts`).
  - Unknown id → HTTP 404.
- Records and batch entries are validated inside the retry/failure boundary. A package whose first batch page
  failed is `failed` (no evidence). A package with some evidence but not all of it (a detail fetch failed or was
  malformed, or a later results page failed) is `incomplete`: its confirmed advisories are kept as findings and
  it still counts as not fully checked. Both feed `failed_lookups`, `unchecked_deps` (`lookup_failed`) and
  `coverage: partial`.
- Severity: GHSA label from `database_specific.severity` when present; otherwise `unknown` (labelled).
  CVSS vectors are outside the current severity calculation.

### Ranking policy (deterministic)
1. Known malicious packages first (advisories with `isMalicious`; with OSV, the `MAL-` records). Action: remove and rotate secrets, not upgrade.
2. Severity: critical › high › medium › low › unknown (labelled, never hidden).
3. Tie-breakers: runtime before optional before dev, direct before transitive, then package name.
   Individual findings tied on those fields are sorted by installed version and advisory ID.
Fix information shapes the action, not the rank.

### Recommended next actions
- Group by package name (one action across all installed versions, a line per version). At most three on the
  summary; the rest below. Built on read from stored findings (`src/application/report.ts`, pure domain
  functions); `summary_line` is stored at completion. Each finding stores `candidate_version` and `fix_status`
  (`candidate` | `no_fix` | `unknown`).
- Action kinds: `remove_malicious`, `upgrade` (some version has a candidate), `no_fix`, `review` (ranges don't
  place the version, or no version scheme). Each action has deterministic what / why first / how to verify.
- Major jump (npm): the candidate leaves `^installed`, so on 0.x the leftmost non-zero part changing counts
  (0.3 → 0.4). Downgrades are never jumps.
- Candidate version = the fix event in the affected range that contains the installed version, using the
  ecosystem's version scheme. Labelled "candidate"; compatibility, resolution and tests still to verify.
  Flag major-version jumps. No version scheme for the ecosystem → no candidate (see [Ecosystem extension points](#ecosystem-extension-points)).
- Transitive package → name the direct parent that pulls it in.
- No fix event → "no fixed version published: review the advisory and upstream guidance, assess exposure".
- Counts say "addresses N advisories according to advisory data"; only a rescan confirms.
- For several advisories on the same installed version, the planner starts from the highest candidate and
  advances to a known fix when the proposed version still falls in an affected interval. It scores versions
  using the available ranges and explicit version lists for advisories with candidates. Missing ranges do
  not count as verified improvements. Advisories without a published fix are shown separately.
- If the proposed version addresses zero verified advisories, the planner checks alternatives and selects the
  one that addresses the most, preferring the lower version on a tie. If none qualifies, the action requires
  review. The report and agent prompt explain that no upgrade could be verified and omit the package-specific
  install command. The report and prompt name advisories that still affect a suggested version. The report
  can also show a lower candidate that addresses some advisories without a major jump.
- Recommendations are rebuilt when the report is read. Older findings can lack the stored range data needed
  to verify a candidate. Pre-migration 003 rows with raw OSV range data read back as null. The same guard
  applies to these older reports.
- Malicious entries usually have no ranges or fix: separate path, action "remove the package,
  check how it got in, rotate secrets that were available where it was installed".

### Evidence vs AI text
- AI writes only the summary paragraph, per-action "why it matters" (top 10 actions; the rest get template
  text) and per-source-rule "why it matters" (see "Source checks"). Each piece is labelled AI or Template in the
  UI; facts never come from it.
- Every explainer's output, the template's included, passes `checkExplanation` (`src/domain/explanation.ts`):
  exactly the expected action IDs (`<ecosystem>:<package>`); each action's text may use only **that action's**
  versions and advisory IDs (the summary may use any action's); length limits; no "secure"/"safe"/"guarantee"/
  "fixed" ("no fixed version published" allowed); no links, domains or commands; nothing asking to send, upload
  or share secrets, tokens or environment data. Package names are masked before checking, so `safe-buffer` is
  an identifier, not a claim. Prose truth can't be validated (stated in README).
- AI prose stays in the human-facing report. The coding-agent prompt is template-only: an agent acts on it,
  so it uses validated structured data for instructions the agent will act on.
- The template bounds its own length (package names are unbounded) and describes lockfile scope only: "Marked as
  a runtime/development dependency in the lockfile; … wasn't assessed". If the template still fails the check
  or throws, fixed minimal sentences that name nothing stand in, with the reason stored. Explanation problems
  never fail a scan.
- `application/explain.ts`: template for everything, AI for the summary + top actions only if it answers within
  `LLM_TIMEOUT_MS` (enforced even if the call ignores its abort signal) and passes the check. A stopped job
  propagates instead of falling back. Stored on `scans.explanation` (jsonb, with the fallback reason, not shown)
  and `explanation_source`.
- **Switching LLM providers** (`src/adapters/llm/`): `LlmExplainer` owns the prompt and the output schema and
  talks to a narrow `LlmClient` (`generate` → schema-valid JSON; errors as neutral `LlmError` kinds). One adapter
  per provider (`anthropic.ts` is the only file importing its SDK, enforced by lint); `registry.ts` picks it from
  `LLM_PROVIDER` (default `anthropic`) with `LLM_API_KEY`, `LLM_MODEL` (default per provider: `claude-opus-5-5`),
  `LLM_TIMEOUT_MS`. A new provider = an adapter + a registry line + passing `test/contract/llm-client.contract.ts`.
- Anthropic adapter: structured output (`messages.parse` + zod format), effort `low`, server-side refusal
  fallback on, no SDK retries; refusal / cut-off / unparseable → template.
- Advisory titles are external text: they reach the model only inside a JSON data block marked as data, and the
  check catches invented values regardless (tested with an injected title).
- `npm run eval`: fixtures in `test/fixtures/eval/` (real demo findings, clean, malicious-only, major jump with an
  injected title); hard checks = the facts check + provider errors; soft signals reported. Template only without
  a key.

### Coding-agent handoff prompt
Built from a template (no AI), from validated structured fields only, because an agent acts on it: package
names, aliases and parents pass the ecosystem's name rules (`RemediationHints.isValidPackageName`), versions its
version scheme; advisory IDs, severities, scopes, the repository URL, commit and lockfile path match fixed
formats. Advisory titles and all prose (AI or template) are left out. Anything failing validation is omitted
with a note, which also covers scans stored before validation existed. Includes repo,
commit, packages with evidence; candidate changes separated from facts; instructions to inspect the dependency
graph first, keep unrelated changes, use the ecosystem's upgrade command, stop and report on major-version
jumps, run tests, rescan, report unresolved items. User sees a preview before copying.

Source findings are part of the same prompt (and give a prompt on their own when dependencies are clean or
weren't checked): grouped by rule, most severe first, with the rule id, severity, title and next action from the
rule catalog, and each location as a validated path and line, labelled when it is a test file. The matched
excerpt is repository code, so it is never included; the agent opens the file. At most 20 locations. The prompt
then says how many more locations the report lists, and separately how many matches were only counted (past the
stored-examples limit), since no report has a location for those. Findings for a rule this version doesn't know
are counted, not listed.

## Report layout
1. Summary line + scan date + commit + coverage + advisory data source (coverage always beside the summary)
2. Up to three recommended next actions: what, why first, how to verify
3. Evidence: expandable per action
4. All findings + unchecked dependencies
5. Copy coding-agent prompt (preview) / Scan again

Clean result: "No known vulnerabilities in N of M dependencies checked at commit X on <date>", what
wasn't checked, advisories change over time → rescan, suggest the ecosystem's CI check (npm: Dependabot /
`npm audit`).
Never says "secure". Partial clean is never shown as clean overall.

## API reference

| Endpoint | Behavior |
|---|---|
| `POST /scans` | Accepts JSON with `repoUrl` and an optional `Idempotency-Key`. Returns `202` for a new scan or `200` for a replay, with `{ scanId }` and a `Location` header. Invalid input returns `400`, a conflicting key returns `409`, and rate or backlog limits return `429` or `503` with `Retry-After`. |
| `GET /scans/:id` | Returns status, stage, counts, coverage, and error details. Browser requests for HTML open the shareable scan page. The JSON endpoint returns `404` for a missing or expired scan. |
| `GET /scans/:id/report` | Returns scan metadata, summary, explanation, CI checks, actions, findings, unchecked dependencies, and the agent prompt once the scan is terminal. Returns `409` while unfinished and `404` for a missing or expired scan. |
| `GET /` | Serves the web UI. |
| `GET /health/live` | Checks that the API responds. |
| `GET /health/ready` | Checks database access from the API. Returns `503` when the database is unavailable. |

Private repositories (M6, only when the GitHub App is configured). Session-dependent answers send
`Cache-Control: no-store` and `Vary: Cookie`.

| Endpoint | Behavior |
|---|---|
| `GET /me` | `{ signInEnabled, session: 'none' \| 'expired' \| 'active', user, installations, installUrl }`; installations only for an active session. `503` when GitHub is unavailable. |
| `GET /auth/login` | Stores a one-time state, sets the browser-binding cookie, redirects to GitHub (state + PKCE). Optional `return_to`: `/` or `/scans/<uuid>`. |
| `GET /auth/callback` | Consumes the state (same browser, unexpired, once), exchanges the code with the PKCE verifier, creates the session, redirects to `return_to`. Failures redirect to `/?auth_error=<code>`. |
| `POST /auth/logout` | Deletes the session and its cached access; clears the cookie. `204`. |
| `GET /github/connect` | Redirects to the app's install page (to sign-in first when there is no session). |
| `GET /github/setup` | GitHub's setup URL. Redirects to `/?connect=installed` only if `installation_id` is among the user's installations (fetched fresh), otherwise to `/?connect=unverified`. |
| `GET /installations/:id/repos` | Repositories both the user and the app can access through that installation, all pages: `{ repositories: [{ id, owner, name, fullName, private }], truncated }`. `401` without an active session, `404` if the installation isn't the user's. |
| `POST /scans` (changed) | Signed in and the repository is a private one the user can access through the owner's installation → private scan bound to its ids. Otherwise a public scan, as before. `401 session_expired` with an expired session; `503` when GitHub is unavailable. |
| `GET /scans/:id`, `GET /scans/:id/report` (changed) | Private scans follow the table under [Private repositories](#private-repositories-m6). Scan JSON gains `visibility`. |

## Operations

- Worker concurrency is per process. The shared backlog cap and per-instance submission limits are described
  under [Submission](#submission). API readiness checks Postgres, so an available API can still accept jobs
  while the worker is stopped.
- The worker deletes finished scans after `SCAN_RETENTION_DAYS` (30 by default) and idempotency keys after
  `IDEMPOTENCY_KEY_TTL_HOURS` (24 by default). Cleanup runs hourly in batches. Deleting a scan also deletes
  its findings, unchecked dependencies, and associated keys. Unfinished scans are excluded.
