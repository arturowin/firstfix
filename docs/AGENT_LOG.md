# How coding agents were used

Raw log, kept during the build. The README section "How I used coding agents" is written from this.
One entry per milestone (or per notable session). Keep it factual.

## Template
### <date> · <milestone / task>
- **Agent did:**
- **Assumptions it made:**
- **I corrected / rejected:** (what, and why)
- **Verified by:** (tests, manual run, docs check)

---

### Before coding · design
- **Agent did:** helped turn the product requirements into a product interpretation, architecture and milestone plan; several external review rounds.
- **I corrected / rejected:** overclaims ("swap one file", "fixes 11 of 14"), conflating idempotency with result reuse, SSE as source of truth, scope creep into extra scanners.
- **Verified by:** re-reading the requirements; independent model reviews.

### 2026-11-10 · M0 setup and verification
- **Agent did:** git + skeleton (Node 22 runs `.ts` directly via type stripping, strict tsconfig, typescript-eslint
  strict-type-checked with domain/application import boundaries, Vitest, Postgres in compose); migration runner
  (advisory lock, one transaction per file) + `001_init.sql`; pg-boss and OSV verification.
- **Found in verification:**
  - Toolchain: shell Node was 21 (pg-boss 12 / Vitest 5 need ≥22.12) → `.nvmrc` 22. TypeScript 7 isn't supported
    by typescript-eslint → pinned 6.0.3. Installed pg-boss is 12.38, not v10 as the docs assumed.
  - pg-boss 12 (contract tests in `test/contract/pgboss.test.ts`): transactional `send` via `{ db }` works;
    `includeMetadata` exposes `retryCount`/`retryLimit`; dead-lettering fires after a throw on the last
    attempt AND after the last attempt expires (crash); `heartbeatSeconds` detects a dead worker in ~10 s vs
    15 min default expiry; stale `complete()` is fenced by `retryCount`; `job.signal` aborts on expiry;
    no archive table (jobs are deleted after retention); `send` returns `null` only on dedupe.
  - OSV: advisories list other packages/ecosystems in `affected`; one package can have several affected
    entries; `last_affected` = no fix; some entries have only a `versions` list; severity label is
    `database_specific.severity` with `MODERATE`; malware appears as both `MAL-` and `GHSA-*`.
- **Assumptions it made:** proposed `heartbeatSeconds: 30`, `expireInSeconds: 300` and job id = scan id (not yet applied).
- **I corrected / rejected:** chose running `.ts` directly over `tsx`; `PROMPTS.md` kept out of git.
- **Verified by:** contract tests run against Postgres 17 (one deliberately broken to confirm they can fail);
  real OSV responses saved as fixtures; `typecheck`, `lint`, `test` green.

### 2026-11-10 · M0 review fixes
- **Review found (external review of the M0 commits), all confirmed:** docs claimed behaviour with no test
  (dead-letter after a missed heartbeat, `fail()` fencing, backoff; a live handler staying alive past
  `heartbeatSeconds` was assumed, not pinned); lint boundaries let `fs` (bare) into domain and `pg`/`pg-boss`
  into application; the OSV batch fixture had no request, so positional results couldn't be mapped; pagination
  unverified; migration runner lost the original error if ROLLBACK failed, returned broken clients to the pool,
  and had no checksums; no `updated_at` trigger; `stage` not tied to `running`; demo repo not logged.
- **Agent did:** added those contract tests (each new one shown able to fail, e.g. raising the backoff cap
  fails the test); moved boundaries to `eslint.boundaries.js` with a test per rule; saved OSV request/response
  pairs and real pagination pages (triggered with a >1000-vuln query); migration checksums, `release(err)`,
  original error kept; trigger + `stage_only_while_running`; Node version guard; clear "Postgres not running"
  test error.
- **Agent corrected the review:** `engine-strict=true` only guards `npm install`, not `npm run`; added
  `scripts/check-node.mjs` as pre-scripts instead. The heartbeat test's flake risk was lower than stated
  (~10 s of 30 s); margin widened anyway.
- **Demo fixture repo:** prepared locally in `../scan-review-demo` (lockfile v3, cases from real OSV data,
  warning README, `.npmrc ignore-scripts`). First lockfile picked up an internal company registry from the
  user's npm config; regenerated against registry.npmjs.org. Not committed or published yet (my call).
- **I corrected / rejected:** no commits until the git author email is decided (global email is a work address).
- **Verified by:** `typecheck`, `lint`, `test` (33 tests) green on Node 22.23 against Postgres 17.

### 2026-11-10 · M0 second review
- **Review found, both confirmed:** (1) `stage_only_while_running` / `terminal_has_completed_at` would reject the
  documented dead-letter/sweeper update (`SET status='failed'` only), leaving the scan stuck in `running`;
  (2) the demo lockfile's `packages/internal-utils` key (workspace folder, no `link`, no `resolved`) would be
  treated as a registry dependency.
- **Agent did:** a `BEFORE UPDATE` trigger now clears `stage`, stamps `completed_at` and refuses leaving a
  terminal state; a test runs the exact documented failure update. Parsing rule added: only `node_modules/`
  keys are dependencies.

### 2026-11-10 · Git history reset
- The repo's original 4 M0 commits (authored with a work email) were removed outside the agent session
  (~13:50). The working tree was intact. History was restarted as one M0 commit with the personal email,
  rather than recreating step commits whose intermediate states were lost. Commits from M1 on are per green step.

### 2026-11-10 · M1 vertical slice
- **Agent did:** domain (URL normalization, lockfile parser basics, severity mapping); transactional submission
  with idempotency (job id = scan id) and attempt-guarded repository; Fastify API; GitHub + OSV adapters
  (OSV chunking and pagination done here rather than M2); pipeline + worker; minimal UI; compose with a
  one-shot migrate service. One commit per green step.
- **Assumptions it made:** Idempotency-Key optional (agreed); `/scans/:id` serves the page to browser
  navigation and JSON to fetch (content negotiation); private repos visible through a token are refused as
  "not found or private"; empty repo and >50 MB lockfile are `unsupported`; report endpoint is 409 until terminal.
- **Found along the way:** msw 3 renamed `onUnhandledRequest` → `onUnhandledFrame` (the old option was silently
  ignored, so unmocked calls wouldn't have failed tests); the project lockfile had 299 internal-registry URLs
  from the machine's npm config → `.npmrc` pins registry.npmjs.org, M0 commit amended before any push;
  Node type stripping forbids constructor parameter properties; Alpine `localhost` resolves to IPv6 (healthcheck).
- **I corrected / rejected:** git author set to personal email for this repo; history restart (see above).
- **Verified by:** 145 tests green; gate run on the live stack against real GitHub and OSV: the published demo
  repo completed in ~5 s at its pinned commit (107 deps, 106 checked, 1 git dep unchecked, 39 advisories in
  16 package versions incl. the MAL- record); Idempotency-Key replay → 200; nonexistent repo → failed
  "not found or private" without retry. UI routes served; not yet clicked through in a browser.
