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
  warning README, `.npmrc ignore-scripts`), resolved against registry.npmjs.org. Not committed or published yet
  (my call).
- **Verified by:** `typecheck`, `lint`, `test` (33 tests) green on Node 22.23 against Postgres 17.

### 2026-11-10 · M0 second review
- **Review found, both confirmed:** (1) `stage_only_while_running` / `terminal_has_completed_at` would reject the
  documented dead-letter/sweeper update (`SET status='failed'` only), leaving the scan stuck in `running`;
  (2) the demo lockfile's `packages/internal-utils` key (workspace folder, no `link`, no `resolved`) would be
  treated as a registry dependency.
- **Agent did:** a `BEFORE UPDATE` trigger now clears `stage`, stamps `completed_at` and refuses leaving a
  terminal state; a test runs the exact documented failure update. Parsing rule added: only `node_modules/`
  keys are dependencies.

### 2026-11-10 · M1 vertical slice
- **Agent did:** domain (URL normalization, lockfile parser basics, severity mapping); transactional submission
  with idempotency (job id = scan id) and attempt-guarded repository; Fastify API; GitHub + OSV adapters
  (OSV chunking and pagination done here rather than M2); pipeline + worker; minimal UI; compose with a
  one-shot migrate service. One commit per green step.
- **Assumptions it made:** Idempotency-Key optional (agreed); `/scans/:id` serves the page to browser
  navigation and JSON to fetch (content negotiation); private repos visible through a token are refused as
  "not found or private"; empty repo and >50 MB lockfile are `unsupported`; report endpoint is 409 until terminal.
- **Found along the way:** msw 3 renamed `onUnhandledRequest` → `onUnhandledFrame` (the old option was silently
  ignored, so unmocked calls wouldn't have failed tests); the project lockfile picked up registry URLs from
  the machine's npm config → `.npmrc` pins registry.npmjs.org, M0 commit amended before any push;
  Node type stripping forbids constructor parameter properties; Alpine `localhost` resolves to IPv6 (healthcheck).
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

### 2026-11-10 · M4 review fixes
- **Review found (all confirmed):**
  - P2: the sweeper always inspected the same oldest 100 stale scans, so a lost scan behind a queued backlog
    was never reached.
  - P2: a malformed `200` OSV record threw during translation and rejected the whole lookup.
  - P2: the report listed failed lookups under "non-registry source".
- **Agent did:**
  - Keyset-paginated sweeps (at most 500 per sweep, pages of 100) that resume from an in-memory cursor and
    wrap at the end. It doesn't touch `updated_at`.
  - OSV record and batch-entry validation inside the retry/failure boundary, plus per-package isolation of
    translation. A test confirms every recorded real record still validates.
  - The UI groups unchecked dependencies by reason, each with its own advice; failed lookups say to scan again.
- **Verified by:** the full suite green (typecheck, lint), including the review's backlog reproduction through
  real pg-boss, and malformed-record and batch-entry tests. UI change not browser-checked.

### 2026-11-10 · M5 polish and release
- **Agent did:**
  - A pass over every UI state at desktop and phone width.
  - API tests for retrying scans, a partial report over HTTP, and reports for unsupported scans.
  - Live scans of real repositories; the README.
  - A release check from a fresh clone: `npm ci`, typecheck, lint, tests, eval, the non-Docker
    migrate/api/worker path, and `npm audit` on runtime dependencies (0 vulnerabilities).
- **Found along the way:**
  - "Why first" still said "not shipped at runtime" / "installed at runtime", the same deployment claim
    fixed in the M3 template; it now states the lockfile classification.
  - A clean but partial result led with "No known vulnerabilities"; it now leads with "Partial result".
  - The findings table was unreadable at 375 px; it now scrolls inside its box.
  - The malicious card repeated its label.
  - `microsoft/vscode` has no root `package-lock.json` (reported as unsupported). `nestjs/nest` (1425
    dependencies) and `npm/cli` (993, workspaces) each completed in 8 s.
- **Verified by:** 303 tests green (typecheck, lint), eval 4/4, clean-clone run.

### 2026-11-11 · Live eval
- **Verified by:** `npm run eval` with a real `LLM_API_KEY` (run by me): passed.

### 2026-11-11 · M6 private repositories
- **Human decided:** GitHub sign-in plus a GitHub App, with GitHub as the only source of permissions. An
  ordinary organization member can use an existing installation; membership or installation access alone
  is not enough. Anonymous public scans stay. The repository picker is required. AI explanations work as
  for public scans. `@fastify/cookie` approved. No webhooks, refresh tokens, onboarding or roles.
- **Human corrected (review of the M6 plan):**
  - bind access to the recorded repository id and installation id, not `owner/name`;
  - public scans must never use privileged credentials;
  - define the cache and session-expiry rules;
  - add connection states;
  - add `no-store` and logout cleanup;
  - make expired-session answers the same for missing and private scans;
  - track pending approval only if GitHub supports it reliably.
- **Verified in GitHub's docs (not yet with a real app):**
  - User tokens: PKCE S256 recommended, 8-hour expiry, the user's and the app's access combined.
  - `GET /user/installations` and `/user/installations/{id}/repositories`: explicit permission, including
    through organization membership; 100 per page.
  - Setup URL: only `installation_id` is documented, and it must be verified against the user's
    installations. The redirect after an approval *request* is not documented, so FirstFix tracks no pending
    state and shows a "check GitHub" message.
  - Installation tokens: `repository_ids` and `permissions`, 1-hour expiry, 404/422/403 errors.
  - App JWT: RS256, `iss` = client id, at most 10 minutes.
  - Contents API raw media type: up to 100 MB.
- **Agent did:**
  - Migration 011: scan visibility and ids (fixed by a trigger), `sessions`, `oauth_states`.
  - Pure read gate in `domain/access.ts`; `AccessService` with a bounded 5-minute cache.
  - Postgres session store: AES-256-GCM, hashed cookie and state, one-time browser-bound state.
  - GitHub adapters: user auth with same-origin pagination; app tokens scoped to one repository; private
    reads by repository id through the contents API.
  - Public path: lockfiles read without credentials, and `GITHUB_TOKEN` used only after a startup check
    that it can't read private repositories.
  - API routes, the `Origin` check and `no-store`.
  - UI: sign-in, installations, picker grouped by owner, `401`/`404` handling without retry loops, logout
    cleanup.
  - README setup, `.env.example`, Compose.
- **Found along the way:**
  - A test sharing one worker across cases exposed the "access revoked while a token is cached" path. It
    now has its own test: GitHub refuses the token, the retry mints again, and the scan fails permanently.
  - The browser check found a race: the "sign in to view it" hint could be missing before `/me` answered.
    The page now waits for `/me`.
- **Verified by:**
  - Typecheck, lint, and 549 tests (431 before).
  - What is mocked: GitHub through msw (adapters, pipeline) and a fake `GitHubAuth` port (API rules, with
    real PKCE hashing); Postgres, sessions, storage and the pipeline are real.
  - A mutation check: weakening the access rule fails three tests.
  - A browser check on a throwaway database with a dummy app (signed out, expired session, phone width).
- **First live run (by the human, a real GitHub App, locally):** sign-in, Connect GitHub and the verified setup
  redirect worked. It found two problems, both fixed with tests (551 tests):
  - Repository access changed on GitHub didn't show for up to 5 minutes (cached list; GitHub didn't redirect
    back). Connect GitHub and the setup URL now drop the session's cached lists.
  - Fastify's request log wrote the OAuth `code` and `state` from the callback URL. Logs now keep the path
    only.
- **Second live finding:** after signing out, every scan answered "session expired", even public ones. A
  `__Host-` cookie can only be deleted with `Secure` and `Path=/`, and logout deleted it without them, so
  browsers kept the dead cookie. Now every deletion repeats the cookie's attributes. A dead cookie is also
  dropped wherever FirstFix notices it (`/me`, submit, reads), and a held-down Enter no longer fires a
  burst of submits. The tests check the `Set-Cookie` headers (554 tests); the old deletion fails them.
- **Still to verify live:** a private scan end to end, and a second account without access. Needed:
  - a GitHub App configured as in the README, installed on a test organization with a private repository
    that has a root `package-lock.json`;
  - two GitHub accounts: a member with access to that repository and a member without it;
  - the settings in `.env`.
  - Then check: sign in as the member, pick the repository, scan, read the report; the second account gets
    `404`; requesting the app as a non-owner shows the "check GitHub" message.

### 2026-11-12 · M6 review fixes
- **Human (review) found, both reproduced:**
  - A GitHub call that hit the access check's own deadline surfaced as a raw `TimeoutError`, so the API
    answered 500 instead of 503, and sign-in could skip the friendly error page.
  - On the private path, a lockfile `404` after access was revoked mid-scan was read as "file absent", so
    the scan could end `unsupported` with "no supported lockfile".
- **Agent did:**
  - An expired deadline now becomes "GitHub unavailable" at the `AccessService` boundary, including the code
    exchange and user lookup.
  - A private-file `404` is checked against the installation token's repository list first: missing only
    if the repository is still accessible, otherwise `app_access_revoked`.
- **Verified by:**
  - Typecheck, lint, and 563 tests including the Postgres suite.
  - The new tests let a real deadline expire (msw handlers that never answer) and revoke access between the
    commit and the lockfile, both in the adapter and through the pipeline.
  - Undoing either fix fails its tests (5 and 3).
- **Live so far (by the human, real GitHub App, local):**
  - private scans completed for `arturowin/glamping-hub` and `arturowin/greenhouse-bot`;
  - the same private repository scanned while signed out failed as "not found or private", with no
    credentialed read;
  - the `devslaw` organization installation is listed.
- **Still required before M6 is complete:**
  - a private scan of an **organization** repository;
  - a second GitHub account without access getting `404` for that scan's status and report.

### 2026-11-12 · M7 JavaScript/TypeScript source checks
- **Human decided:**
  - two targeted checks for disabled TLS verification (`FF-TLS-001`, `FF-TLS-002`) in the existing worker and
    job, sequential after the dependency check, on one commit;
  - no new worker, queue, service, scanner or parsing library;
  - the six proposed defaults: test code labelled, not excluded; the member-assignment form in scope;
    high/medium severity; the status table; path order; AI unchanged.
  - M6 stays staged for its own commit: M7 edits are left unstaged.
- **Agent did:**
  - A pure tokenizer and rule matcher (`domain/source-scan.ts`), the rule catalog and summary text
    (`source-rules.ts`), and file selection (`source-files.ts`).
  - `application/source-check.ts`: 8 fetches at a time, a 60-second budget, cancellation checked per file, and
    shared failures propagated.
  - `RepoSource.listTree`/`readSourceFile` and the tree SHA from the commit response.
  - Migration 012: per-check outcomes, `source_findings`, stage `source`, and a relaxed `completed_has_coverage`.
  - The pipeline: a missing lockfile is now the dependency check's outcome, not the scan's.
  - Report, API and UI source section; README, `.env.example` and Compose limits.
- **Verified live (by the agent, local stack, public repository, no credentials for file reads):**
  - `GET …/commits/{branch}` returns `commit.tree.sha`, and the recursive trees API returns `mode`/`type`/`size`
    and `truncated` (checked on `arturowin/scan-review-demo`).
  - A scan of `sindresorhus/got` (no `package-lock.json`) completed on its source checks (case b): 96 of 96
    files read, 0 fetch failures, real `FF-TLS-002` matches with exact locations, test files labelled, and
    links pinned to the commit.
- **Found along the way:**
  - That live scan showed the per-file match cap (50) making a fully checked repository read "Partial". Matches
    over the cap no longer make coverage partial; the summary says more were found than are shown.
  - Restored a semantic from before M7: when neither check is usable on the last attempt, the transient error
    is rethrown after recording, so the queue records the job as failed.
  - A cancellation test hung when the job was cancelled before the first read. The check now looks for
    cancellation before each file.
- **Verified by:**
  - Typecheck, lint, 685 tests, eval 4/4.
  - Mocked: GitHub through msw (tree and file reads, public/private credentials, revocation) and fake ports for
    pipeline cases a–f, stale attempts, retention, older scans and private-report access to source excerpts.
  - Undoing "missing lockfile doesn't stop source checks" fails 3 tests.
- **Not verified live:** a private organization-repository scan. Needed: sign in, pick a private `devslaw`
  repository with `.js`/`.ts` files, scan it, and check the source section. That scan reads the private files
  through the contents API with the installation token.

### 2026-11-12 · M7 follow-up after first use
- **Human found** on `arturowin/typescript-node.js-rest-example` (lockfileVersion 1):
  - the report led with "Dependencies were not checked", so the scan looked stopped, although the source check had
    run (12 of 12 files);
  - "Prioritize findings" ran before "Check source code";
  - source issues weren't explained.
- **Agent did:**
  - The top card now leads with the source result and shows both checks side by side.
  - Stage `analyzing` now runs after the source check, so prioritizing and explaining see both checks.
  - Explanations cover source rules: summary paragraph plus a per-rule "why it matters", template or AI.
    - The AI gets rule IDs, titles, severity and counts, never paths or excerpts.
    - `checkExplanation` requires one entry per matched rule, with the same bans.
    - `sourceRules` is optional in the LLM schema, so dependency-only replies stay valid.
  - Source findings are grouped by rule in the UI (the same text was repeated 86 times on `sindresorhus/got`).
  - Two eval fixtures with source facts.
- **Verified by:**
  - Typecheck, lint, 704 tests, template eval 6/6.
  - Live on the local stack: the rescan shows the new top card; `got` showed the stages
    `fetching → source → analyzing` and template explanations ("83 of 86 matches are in test files").
- **Not verified:** the AI explanations. The eval with `LLM_API_KEY` was rejected by Anthropic: the credit
  balance is too low. Scans fall back to the template by design.

### 2026-11-12 · M7 review fixes
- **Human (review) found, both reproduced here first:**
  - A file with 50 `rejectUnauthorized: false` matches followed by a process-wide
    `NODE_TLS_REJECT_UNAUTHORIZED = '0'` lost the high-severity finding: only the first 50 matches per file were
    kept. The scan-wide cap also kept findings in fetch order.
  - About 15 KB of nested templates threw `RangeError: Maximum call stack size exceeded` in the tokenizer, which
    could fail the whole job and lose dependency results.
- **Agent did:**
  - Detection now counts every match per rule (`source_counts.rules`). Stored examples (500) are chosen by
    priority: severity, then non-test code, then path, line and column, independent of fetch order. The summary,
    report, explanations and UI use the counts ("31 findings (1 high, 30 medium) … more than are shown"; "30
    matches (4 shown)").
  - Template nesting is bounded at 64. A deeper file is `unparsed` and counted as `skippedParse` (partial coverage).
  - The source check also catches any scanner error per file, so the job and its dependency results are never
    lost.
- **Verified by:**
  - Typecheck, lint, the full suite including Postgres, template eval.
  - Regression tests: high severity kept after 50 medium; order-independence across fetch orders; nested input
    unparsed, not thrown; an unparsable file next to a lockfile still completes with dependency findings.
  - Undoing the nesting bound fails 1 test; undoing the priority sort fails 3.
- **Still open:** the live private organization-repository scan (needs a human with access).

### 2026-11-12 · Action card review (minimatch under eslint)
- **Human asked** to check a real card on this repository: upgrade minimatch 10.2.6 → 11.0.1 (GHSA-g3hv-75wg-m249).
- **Checked against the data:**
  - The candidate and the major-jump flag are correct (OSV: affected from 7.0.0, fixed only in 11.0.1).
  - The AI text matches the advisory.
- **Agent fixed:**
  - **@eslint/js listed as a parent.** It has no dependencies; its *peer* eslint was followed as an edge.
    `graph.ts` now skips a peer edge when the peer resolves to one of the project's own direct dependencies;
    peers npm auto-installed for a package still count.
  - **Verify said "shows only the candidate version".** That's wrong when other versions legitimately remain;
    it now says "no longer shows 10.2.6".
  - **Transitive major jump with the override route.** The step now warns that forcing a new major can break the
    packages that depend on it. The lockfile shows eslint, @eslint/config-array and typescript-estree all
    require `^10.x`; npm shows their latest releases do too.
  - **"1 advisory records"** plural fixed.
- **Verified by:**
  - Typecheck, lint, 719 tests, template eval.
  - Undoing the peer rule fails its test.
  - A live rescan of this repository shows the corrected card (AI text included: the Anthropic credit works
    again).

### 2026-11-12 · minimatch override for the lint toolchain
- **Human asked** for the fix FirstFix suggested on its own repository (minimatch 10.2.6, GHSA-g3hv-75wg-m249),
  applied only if it was tested and worked.
- **Agent checked first:**
  - The latest eslint, @eslint/config-array, typescript-estree and typescript-eslint all still require
    `minimatch ^10`, so no upgrade of the lint tools clears it, and `npm audit fix --force` would downgrade eslint
    to 9.
  - minimatch is used only by the lint tools; `npm audit --omit=dev` was already clean.
- **Agent changed:** `package.json` `overrides.minimatch: "^11.0.1"` (resolves to 11.0.8). Remove it once the lint
  tools depend on minimatch 11 themselves.
- **Verified by:**
  - Clean `npm ci`: typecheck, lint, 719 tests, eval, UI build and the Docker image all pass; `npm audit` reports 0.
  - ESLint still lints the same 126 files and still skips `dist/` and `node_modules/`; a file with a planted
    error is still reported, so the major version didn't silently change which files match.

### 2026-11-12 · Report wording after scanning FirstFix itself
- **Human asked**, after a scan of this repository: dependencies were clean, but the headline read as an all-clear
  above three source findings, and the badge didn't say that all three are in test files.
- **Agent changed:**
  - **Headline.** Dependency headlines (clean, partial, with actions, nothing checkable) now add the source result
    when it found something, e.g. "Source checks: 3 findings, all in test files." Nothing is added when the check
    found nothing, had no files, failed or didn't run (the source card says why).
  - **Badge.** "3 findings · all in tests" or "· 2 in tests". Severity still sets the colour.
  - **Review follow-up.** The badge is green only for a complete check with no matches: a partial check with no
    matches says "No findings in checked files" (warning), and a check that read no files says "No files
    checked" (warning). When no dependency could be checked, the card now says "no dependency assessment was
    possible" instead of "no security assessment", since the source check may still have found something.
  - The wording lives in `src/web/source-text.ts`, which is pure and unit-tested.
  - **Fixtures.** `test/fixtures/source/{flagged,safe}.ts` are now `.ts.txt`: tests only ever read them as text
    and pass them to the scanner under a `.ts` path, so the insecure patterns are test data, not code in this
    repository. The demo repository gets its own file with these patterns instead.
- **Verified by:** typecheck, lint, 746 tests (27 new), eval, UI build.

### 2026-11-12 · Coding-agent handoff covers source findings
- **Human noticed** that "Hand off to a coding agent" said nothing about the source findings, and a report with
  only source findings (clean or unchecked dependencies) had no prompt at all.
- **Agent changed:**
  - `buildAgentPrompt` adds a "Source findings" section: per rule, most severe first, the catalog's id, severity,
    title and next action, and each location as a validated path and line (code outside tests first, test files
    labelled). Two source-specific working rules: open each location first and keep verification on (trust the
    CA instead); in test files keep the change inside the tests.
  - Same safety rule as for dependencies: only validated, structured fields. The matched excerpt is repository
    code and is never included; unsafe paths and lines are replaced with a note; unknown rules are counted.
  - At most 20 locations, with a count of the rest.
  - The report builds the prompt for any completed scan with dependency actions or source findings, and the UI
    shows it on clean and dependencies-not-checked reports too.
  - A dependency-only prompt is unchanged (the existing snapshot still matches).
- **Verified by:** 8 new unit tests (including injection through a path and an excerpt), integration tests for
  a combined and a source-only report, and a mutation check: removing the path validation fails the injection
  test.
- **Review follow-up:**
  - The "more" note mixed two counts: with 100 matches found, 50 stored and 20 listed, it said "80 more are in
    the full report" although the report has only 30 more locations. It now says "30 more source locations are in
    the full report" and, separately, "50 more source matches were counted but not stored", with a rescan as
    the way to find them.
  - Reports with source findings but no dependency findings showed two "Scan again" buttons (summary card and
    handoff card). The handoff card now has one only on the layout whose summary card has none.

### 2026-11-14 · Audience: application security managers
- **Human noticed** that CLAUDE.md ("help a repository owner … without needing security expertise") and the AI
  system prompt ("the reader owns the repository and is not a security expert") didn't match the stakeholder's
  answer: the users are application security managers in organizations. The README already described that.
- **Agent changed:** CLAUDE.md's product line, and the system prompt's reader line: an application security
  manager who prioritizes the work and hands it to the repository's owners; precise and brief, no basic terms
  explained. All other prompt rules, the facts check and the template fallback are unchanged.
- **Verified by:** typecheck, lint, 756 tests, template eval; live-model eval twice (11/12, then 12/12) and the
  old prompt once (12/12). The one failure ("claims a fix" for express) is intermittent and also seen with the
  old prompt on the hosted demo. A side-by-side summary showed the new text ranking the work for a manager.
