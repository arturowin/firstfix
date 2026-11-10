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

### 2026-11-10 · M2 second review fixes
- **Review found (both confirmed):**
  - P2: two direct aliases of one vulnerable version were offered as alternatives ("`…first…` or `…second…`").
  - P2: transitive guidance said "candidate or later", which range-aware planning can't back.
- **Agent did:**
  - Each install name now keeps whether it is a direct declaration (`direct_as`, migration 006). Remediation
    lists every route that has to change: each direct declaration, all required ("Update every declaration
    …: A and B"), and each parent ("update X so it resolves to <pkg> <candidate>, or to another version
    checked against these advisories").
  - A transitive alias gets no install command.
  - Broader than the review: a version installed both directly and through a parent now gets both routes
    (before, only the direct one). The malicious path got the same "every route" treatment.
- **Verified by:** 221 tests green (typecheck, lint); prompt snapshot diff reviewed (route moved to its own
  line, "or later" gone). UI evidence line updated; not browser-checked.

### 2026-11-10 · M3 AI explanation
- **Agent did:**
  - Explainer port, a facts check that every explainer must pass, a template explainer, and AI-with-fallback
    in the application layer. The AI's deadline is enforced even if the provider call ignores its abort signal.
  - Migration 007: `scans.explanation`; drops the unused `findings.explanation` column.
  - Prose is labelled AI or Template in the UI.
  - A provider-neutral LLM layer with Anthropic as the first adapter, a shared LLM-client contract suite, and
    `npm run eval` over 4 fixtures.
- **Human asked:** make providers easy to switch. Agent added the `LlmClient` seam and registry, and a lint
  boundary so only the provider adapter imports its SDK.
- **Assumptions:**
  - Anthropic SDK pinned to 1.3.0, the newest release older than two weeks; 1.7.0 was one day old.
  - Model `claude-opus-5-5` at effort low (configurable through `LLM_MODEL`).
  - Top 10 actions get AI text.
  - Server-side refusal fallback on.
  - AI is skipped when there is nothing to explain.
- **Found along the way:**
  - I committed step 2 with lint errors (the command chain didn't stop on them), then fixed and amended it
    before moving on.
  - The eval's soft signal caught that the template summary didn't name the malicious package; it does now.
- **Verified by:** 267 tests green, typecheck, lint; `npm run eval` (template) 4/4; a live no-key demo scan
  gave a complete report with template prose. Not yet verified: a live run with a real Anthropic key.

### 2026-11-10 · M3 review fixes
- **Review found (all confirmed):**
  - P1: the template could fail the scan. A package named `safe-buffer` tripped the "safe" claim check, and
    long parent names pushed the text past 300 characters; both threw with no AI configured.
  - P2: each action's text was checked against every action's versions and IDs pooled together.
  - P2: the template said dev dependencies run "rather than in production" and runtime ones "ship with the
    application", which the scan can't know.
- **Agent did:**
  - The check masks package names (real, alias, parent) before the claim and version checks, and checks each
    action against its own evidence.
  - The template bounds its length and uses lockfile-scope wording.
  - If the template still fails or throws, minimal fixed sentences stand in and the reason is stored; the
    scan completes.
  - The AI prompt gained the same two rules (scope is a classification; only the action's own evidence).
- **Verified by:** 274 tests green (including both reproductions at the unit and pipeline level), lint,
  typecheck; eval 4/4 with the template. A live AI run and a browser walkthrough are still pending.

### 2026-11-10 · M4 failure behaviour
- **Agent did:**
  - Partial advisory lookups. `lookup` returns `{ advisories, failed }`; OSV retries each call once, and a
    failed batch or detail fetch fails only the packages it affects. A scan with some lookups failed completes
    as `partial`; if all fail, the attempt is treated as transient.
  - `retrying` with a reason; the last attempt ends `failed`.
  - The `JobQueue` port and the pg-boss job-state adapter; `failIfOpen` with an attempt bump.
  - A dead-letter handler and a sweeper in the worker.
  - Queue wiring shared by the worker and the tests (`worker/scan-worker.ts`).
  - Failure tests through real pg-boss: transient retry, retries exhausted, a worker stopped mid-scan, a crash
    with no heartbeat, a crash on the last attempt, and the sweeper with a backlog and a zombie worker.
- **Decisions agreed before coding:**
  - Every lookup failing → retry, then `failed`.
  - Some lookups failing → report as partial right away.
  - The sweeper runs inside the worker every 60 s.
- **Found along the way:**
  - pg-boss `stop()` fails in-flight jobs ("pg-boss shut down while active") and aborts them, so a stopped
    worker's scan is retried at once; only a real crash waits for the heartbeat (10 s minimum).
  - The pipeline writes nothing on abort, so the retry claims a clean row.
  - `retryDelayMax` can't be combined with `retryBackoff: false`, so the tests keep backoff on with a 0 delay.
- **Verified by:** 290 tests green (typecheck, lint); the failure suite passed 3 out of 3 runs, about 33 s each;
  each lifecycle outcome is mapped to its test in ARCHITECTURE.md.
