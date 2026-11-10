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

### 2026-11-10 · M2 actionable report
- **Agent did:** ecosystem seams (format registry, `readFile`, ecosystem-keyed lookups, migration 002, a
  test-only ecosystem through the real pipeline); provider-neutral advisory source (`AffectedRange`, OSV
  translation in the adapter, shared contract suite, data source stored per scan); npm version scheme
  (`semver`) and candidate selection; npm install graph (direct parents, ≤5 shortest paths); ranking, fix
  plan, summary line, agent prompt (snapshot); report API; UI in the frozen layout with clean result and
  prompt preview. One commit per green step.
- **Decisions agreed before coding:** workspace declarations count as direct; 0.x major jump = leftmost
  non-zero part changes; actions built on read from stored findings, summary line stored; one action per
  package name; malicious detection only from structured data.
- **Found along the way:** GitHub's malware advisories carry `cwe_ids: ["CWE-506"]` (verified on the recorded
  fixtures), so the OSV adapter flags them without title matching. The prompt snapshot caught a downgrade
  counted as a major jump and package names being capitalized in headlines; both fixed.
- **Deviations from the written plan:** the ecosystem is attached per format rather than per parsed package;
  a parse result can be `invalid` (unreadable) besides `unsupported`; `fix_status` column (migration 004) so
  "no fixed version published" and "see the advisory" are told apart; severity labels moved from the domain
  into the OSV adapter.
- **Verified by:** 208 tests green (typecheck, lint); live stack against real GitHub and OSV: demo repo →
  "1 known malicious package and 14 packages with known vulnerabilities (2 critical, 5 high, 4 medium,
  3 low) in 106 of 107 dependencies checked. Start with: remove flatmap-stream", 15 ranked actions, major
  jumps flagged with a compatible alternative (postcss 7.0.36 vs 8.5.23). UI bundle served; not yet clicked
  through in a browser.

### 2026-11-10 · M2 review fixes
- **Review found (all confirmed against the code before fixing):**
  - P1: an advisory counted as addressed when its first candidate was ≤ the proposed version, which is wrong
    when it affects separate intervals.
  - P1: npm aliases were queried under the install-folder name, which could produce a false clean result.
  - P2: the browser could stall if the final report request failed.
  - P2: zero checked dependencies were worded like a clean result.
  - PLAN overclaimed failed-lookup accounting.
- **Agent did:**
  - Range-aware planning: the proposed version is checked against every advisory's stored ranges and moved
    past any interval with a fix.
  - Aliases: the real name comes from the lockfile entry's `name`, which I confirmed by generating a real npm
    10 lockfile; it's kept as a fixture. The alias is kept in `installed_as` (migration 005) and in the upgrade
    command.
  - Browser: a report-fetch retry loop with a visible message. Polling also survives non-200 and non-JSON
    answers, a gap the review didn't list.
  - Zero checked: "No dependencies could be checked" headline.
  - PLAN corrected: failed-lookup accounting is M4.
- **Note:** migration 003's comment ("the report never reads affected_ranges") is now out of date; applied
  migrations aren't edited, so ARCHITECTURE records it.
- **Verified by:** 218 tests green (typecheck, lint). UI fixes are not covered by tests (no DOM test setup)
  and not yet checked in a browser.
