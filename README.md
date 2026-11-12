# FirstFix

**Know what to fix first.**

FirstFix checks GitHub repositories for known security issues: public repositories anonymously, private ones after signing in with GitHub. Paste a repository URL (or pick one of yours), follow the scan, and get a report that explains what to address first, why it matters, and how to verify the change.

**Live demo:** <https://firstfix-35-233-9-207.sslip.io>. See [Try the demo](#try-the-demo) for a repository to scan.

### What it checks today

- **Dependencies:** npm projects with a root `package-lock.json` (v2 or v3), checked against OSV.dev advisory data.
- **Source code:** two targeted checks for disabled TLS certificate verification in JavaScript/TypeScript (`.js`, `.jsx`, `.ts`, `.tsx`).

More ecosystems and broader source-code checks are on the [roadmap](#roadmap).

## Quick start

You’ll need Docker with Compose, internet access, and ports `3000` and `5432` free.

~~~sh
cp -n .env.example .env
openssl rand -hex 24
~~~

Set `POSTGRES_PASSWORD` in `.env` to the generated value, then run:

~~~sh
docker compose up --build
~~~

Open `http://localhost:3000`. Compose starts Postgres, runs migrations, and starts the API and worker.

`GITHUB_TOKEN` is optional and raises GitHub’s rate limit for public scans. It must be a token that can't read private repositories (a fine-grained token with public read-only access); the worker checks this at startup and ignores any other token. `LLM_API_KEY` is optional and enables AI-written explanations. The default report uses template explanations. See [`.env.example`](.env.example) for other settings.

### Private repositories (optional)

Private scans need a GitHub App that you register once. Without it, sign-in is hidden and FirstFix scans public repositories only.

1. Create a GitHub App (GitHub → Settings → Developer settings → GitHub Apps → New GitHub App):
    - **Callback URL:** `<PUBLIC_URL>/auth/callback`. Leave "Request user authorization (OAuth) during installation" off.
    - **Setup URL:** `<PUBLIC_URL>/github/setup`, with "Redirect on update" on.
    - **Webhook:** off.
    - **Repository permissions:** Contents: Read-only (Metadata: Read-only is added automatically).
    - **Where can this GitHub App be installed:** any account, so organizations can install it.
2. On the app's page, generate a client secret and a private key.
3. Set in `.env`: `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET`, `GITHUB_APP_SLUG` (the app's URL name), `GITHUB_APP_PRIVATE_KEY` (the `.pem` contents; `\n` escapes are fine), `SESSION_SECRET` (`openssl rand -hex 32`) and `PUBLIC_URL` (https, or `http://localhost:3000` locally).
4. Restart with `docker compose up --build`.

Users see repositories that both they and the GitHub App can access, including organization repositories. Any signed-in user with the required repository access through the app installation can view a private scan’s report, including colleagues who did not submit it. Installing the app or adding organization repositories may require an organization owner’s approval.

### Try the demo

A hosted demo runs at <https://firstfix-35-233-9-207.sslip.io>, with GitHub sign-in for private repositories. It is a demo instance and may be taken down; running FirstFix locally (above) works the same way.

Paste `https://github.com/arturowin/scan-review-demo` into the hosted demo or your local FirstFix. Look for:

- **Dependencies:** the recommendation to remove `flatmap-stream`, the advisory evidence behind it, and the Git dependency the scanner couldn’t check.
- **Source code:** three TLS findings in `src/tls.ts` and `test/client.test.ts`, one of them labelled as a test file. The same setting in a comment and a string is not flagged.
- **Hand off to a coding agent:** one prompt covering both the dependency changes and the source locations.

The demo repository intentionally pins vulnerable and malicious package versions and contains insecure TLS settings. Scan it by URL; don't install its dependencies or run its code.

## Product interpretation

The report helps teams prioritize security work and hand clear next actions to repository maintainers. It groups dependency findings by package and source findings by rule, with supporting evidence and remediation guidance. A copyable coding-agent prompt covers both: dependency changes to verify, and source locations to review.

The scanner determines the findings, priorities, and suggested actions. AI can explain those results when configured.

## Architecture

~~~text
Browser ──▶ Fastify API ──▶ Postgres ◀── Scan worker ──▶ GitHub + OSV
                           scans, findings,             └──▶ optional LLM
                           pg-boss jobs
~~~

- **Queue and worker.** GitHub and OSV requests can be slow or fail temporarily. The API returns a scan ID once the job is saved, and the browser polls for progress while the worker runs. The worker limits concurrent scans. If it exits mid-scan, the job can be retried under the same scan ID once a worker is available and the queue detects the interruption.
- **One Postgres instance.** Using pg-boss keeps the deployment small and lets the API create the scan and enqueue its job in one transaction.
- **Explicit SQL for scan ownership.** The attempt check and completion transaction are visible in the queries. A stale worker cannot overwrite the result of a newer attempt.
- **Commit-pinned reads.** The worker resolves the default branch to a commit and checks both the lockfile and source files at that commit. The report identifies the snapshot it checked.
- **GitHub decides who sees private scans.** A private scan is bound to the repository's GitHub id and the app installation. Every status and report request checks, with the viewer's own GitHub token, that GitHub lists that repository for them (cached for at most 5 minutes). FirstFix relies on GitHub identities and permissions rather than maintaining its own organization membership or roles. The worker reads private repositories with a short-lived app token limited to that one repository. Public scans never use credentials that can read private repositories.

See the [architecture doc](docs/ARCHITECTURE.md) for the scan pipeline, failure handling, and extension points.

## Failure behaviour

- **Temporary failures:** GitHub and advisory-service timeouts, server errors, and rate limits trigger retries with backoff. On the final attempt, a check can fail while the scan still completes using the other check’s results.
- **Permanent failures:** unavailable repositories or revoked access can stop the scan. Missing, invalid, oversized, or unsupported lockfiles mark the dependency check unsupported; source checks still run. An empty repository is unsupported.
- **Incomplete advisory lookups:** available findings are retained, and dependencies that could not be fully checked are identified. If every lookup fails, the job retries; after retries are exhausted, dependency checking fails, but usable source results can still be returned.
- **Worker crash mid-scan:** pg-boss detects the missed heartbeat and retries the job under the same scan ID; Compose restarts the worker. A crash on the last attempt is caught by a dead-letter handler, which marks the scan `failed`. A periodic sweeper fails a scan only when its job has finished or disappeared, so a queue backlog or a stopped worker does not fail a healthy scan.
- **Stale or duplicate workers:** each attempt owns the scan through an attempt counter. Findings and completion are written in one transaction on the locked scan row, so an older attempt or a duplicate delivery changes nothing.
- **AI explanations** that time out, fail validation or have no API key fall back to template text. They never fail a scan or change its coverage.
- **Private repositories:**
    - The app was uninstalled, or the repository removed from it, before the scan ran: the scan ends `failed` ("FirstFix no longer has access…") and is not retried.
    - GitHub timeouts, server errors, and rate limits while reading are retried.
    - A public repository that becomes private while queued fails as "not found or private." The worker does not use private-repository credentials to read it.
    - Signed out, or without access: a private scan answers "not found", the same as a missing one.
    - An expired session (sign-ins last at most 8 hours) answers "sign in again."
    - GitHub unavailable while checking access answers 503 and is never served from an expired check.
- **Dependency and source checks** run sequentially in the same job, against the same commit. Each reports its own outcome and coverage. A failed check is never shown as clean; shared failures such as revoked repository access can stop the whole scan.
- **Overload:** `POST /scans` returns 429 above the per-client rate and 503 when too many scans are outstanding. Resending with the same `Idempotency-Key` is safe.

See [Lifecycle](docs/ARCHITECTURE.md#lifecycle) and [Source checks](docs/ARCHITECTURE.md#source-checks-m7) for detailed outcomes.

## Limits

- **Scope:** dependency scanning checks one root npm `package-lock.json` (v2 or v3). Source scanning runs the two checks below, including when no supported lockfile exists. Both use the default-branch commit of a github.com repository. No general source-code analysis, secrets scanning or reachability analysis.
- **Dependency ecosystems:** npm only. Lockfile parsing, version rules and upgrade commands are registered per ecosystem, so other lockfile ecosystems (Cargo, Poetry, Bundler, Composer) fit the same seams. Manifests without exact versions would need dependency resolution first.
- **Advisory data:** OSV.dev only, behind a provider-neutral contract. Findings reflect its coverage. Severity uses GitHub's advisory label; advisories without one show `unknown` (no CVSS scoring yet).
- **Not checked:** Git, local and non-registry tarball dependencies are listed as unchecked.
- **Candidate versions** come from advisory data and are never claimed as fixes. After applying a suggested upgrade, run the project's tests for compatibility and rescan the resulting lockfile to see whether the advisories still match.
- **Private repositories:** no webhooks and no refresh tokens. Users sign in again after at most 8 hours, and revoked access can still allow viewing a report for up to 5 minutes. An installation's repository list is read up to 10,000 entries. FirstFix does not track pending organization approval requests; an installation appears once approved and accessible to the user.
- **Operations:** the `POST /scans` rate limit keeps its counters in memory, so each API instance applies its own limit. The supplied Compose configuration runs 2 scans at a time per worker. Finished scans are deleted after 30 days and idempotency keys after 24 hours (configurable, see [`.env.example`](.env.example)).
- **Source checks:** two targeted, textual checks in `.js`, `.jsx`, `.ts` and `.tsx` files at the scanned commit: `FF-TLS-001` (`process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`, high) and `FF-TLS-002` (`rejectUnauthorized: false`, medium). They are not a comprehensive security review: a match doesn't prove the line runs or can be exploited, and no match doesn't mean the code is secure.
    - **Missed:** aliases (`const env = process.env`), values computed at runtime, code inside template substitutions, and cross-file flows.
    - **Possible false positives:** TypeScript literal types like `{ rejectUnauthorized: false }`, dead code, and test-only code (labelled "test file").
    - **Limits:** up to 200 files, 256 KB each and 10 MB in total (configurable), in path order. Dependency and build folders (`node_modules/`, `dist/`, `build/`, `vendor/`…), symlinks and submodules are skipped, as are files nested too deeply to read as code. Coverage limits and skipped eligible files are reported. Matches are counted separately from stored evidence; at most 500 findings are listed, highest severity first.
    - Repository code is never run, and complete source files are not stored: only bounded matched-code excerpts of at most 200 characters.
    - Each matched source rule receives an explanation from AI when configured, or from a template otherwise. Source-specific AI input contains rule metadata and aggregate counts, not source-file paths or excerpts. The request also includes repository context and structured dependency facts when available.

## Roadmap

- **More ecosystems:** other lockfile ecosystems (Python with Poetry or uv, Rust/Cargo, Ruby/Bundler, PHP/Composer); yarn and pnpm lockfiles for JavaScript; several lockfiles per repository.
- **Broader source-code checks:** additional vulnerability patterns and languages, run by the same worker and reported alongside dependency findings.

## Checks

Use Node.js 22.18+ and run `npm ci`. For the full test suite, set `DATABASE_URL` to a reachable PostgreSQL instance using a role that can create temporary databases.

~~~sh
npm run typecheck
npm run lint
npm test
npm run eval
~~~

The eval checks explanations against fixed fixtures. Export `LLM_API_KEY` in the shell to also evaluate the live model.

## How I used coding agents

I brainstormed with two AI models to explore different approaches. I made the final product and technical decisions, documented the architecture, and broke the work into milestones. I used Claude Code to implement most of the code one milestone at a time.

I also used AI to review the implementation and surface subtle issues. I verified the work with type checks, linting, tests, and independent reviews.

The [architecture](docs/ARCHITECTURE.md), [implementation plan](docs/PLAN.md), and [agent log](docs/AGENT_LOG.md) have more detail.