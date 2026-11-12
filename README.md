# FirstFix

**Dependency security, in the order to fix it.**

FirstFix reviews npm dependencies in GitHub repositories: public ones anonymously, private ones after signing in with GitHub. Paste a repository URL (or pick one of yours), follow the scan, and get a report that explains what to address first, why it matters, and how to verify the change.

## Quick start

You’ll need Docker with Compose, internet access, and ports `3000` and `5432` free.

```sh
cp -n .env.example .env
openssl rand -hex 24
```

Set `POSTGRES_PASSWORD` in `.env` to the generated value, then run:

```sh
docker compose up --build
```

Open `http://localhost:3000`. Compose starts Postgres, runs migrations, and starts the API and worker.

`GITHUB_TOKEN` is optional and raises GitHub’s rate limit for public scans. It must be a token that can't read private repositories (a fine-grained token with public read-only access); the worker checks this at startup and ignores any other token. `LLM_API_KEY` is optional and enables AI-written explanations. The default report uses template explanations. See [`.env.example`](.env.example) for other settings.

### Private repositories (optional)

Private scans need a GitHub App that you register once. Without it, sign-in is hidden and FirstFix scans public repositories only.

1. Create a GitHub App (GitHub → Settings → Developer settings → GitHub Apps → New GitHub App):
   - **Callback URL:** `<PUBLIC_URL>/auth/callback`. Leave "Request user authorization (OAuth) during installation" off.
   - **Setup URL:** `<PUBLIC_URL>/github/setup`, with "Redirect on update" on.
   - **Webhook:** off.
   - **Repository permissions:** Contents: Read-only (Metadata: Read-only is added automatically). No other permissions.
   - **Where can this GitHub App be installed:** any account, so organizations can install it.
2. On the app's page, generate a client secret and a private key.
3. Set in `.env`: `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET`, `GITHUB_APP_SLUG` (the app's URL name), `GITHUB_APP_PRIVATE_KEY` (the `.pem` contents; `\n` escapes are fine), `SESSION_SECRET` (`openssl rand -hex 32`) and `PUBLIC_URL` (https, or `http://localhost:3000` locally).
4. Restart with `docker compose up --build`.

Anyone can then sign in with GitHub. Users see the repositories that both they and the app can access, including organization repositories installed by an owner, and only they can open the reports of their private scans. Installing the app on an organization, or adding repositories to it, may need an organization owner's approval.

### Try the demo

Paste `https://github.com/arturowin/scan-review-demo` into FirstFix. Look for the recommendation to remove `flatmap-stream`, the advisory evidence behind that recommendation, and the Git dependency the scanner couldn’t check.

The demo repository intentionally pins vulnerable and malicious package versions. Scan it by URL and avoid installing its dependencies.

## Product interpretation

The report helps a repository owner decide what to do next. It groups findings by package, leads with the highest-priority actions, and shows the evidence and verification steps for each suggestion. It also provides a prompt for handing the work to a coding agent.

The scanner determines the findings, priorities, and suggested actions. AI can explain those results when configured.

## Architecture

```text
Browser ──▶ Fastify API ──▶ Postgres ◀── Scan worker ──▶ GitHub + OSV
                           scans, findings,             └──▶ optional LLM
                           pg-boss jobs
```

- **Queue and worker.** GitHub and OSV requests can be slow or fail temporarily. The API returns a scan ID once the job is saved, and the browser polls for progress while the worker runs. The worker limits concurrent scans. If it exits mid-scan, the job can be retried under the same scan ID once a worker is available and the queue detects the interruption.
- **One Postgres instance.** Using pg-boss keeps the deployment small and lets the API create the scan and enqueue its job in one transaction.
- **Explicit SQL for scan ownership.** The attempt check and completion transaction are visible in the queries. A stale worker cannot overwrite the result of a newer attempt.
- **Commit-pinned reads.** The worker resolves the default branch to a commit and reads the lockfile at that commit. The report identifies exactly which snapshot it checked.
- **GitHub decides who sees private scans.** A private scan is bound to the repository's GitHub id and the app installation. Every status and report request checks, with the viewer's own GitHub token, that GitHub lists that repository for them (cached for at most 5 minutes). There are no FirstFix accounts, organizations or roles. The worker reads private repositories with a short-lived app token limited to that one repository. Public scans never use credentials that can read private repositories.

See the [architecture doc](docs/ARCHITECTURE.md) for the scan pipeline, failure handling, and extension points.

## Failure behaviour

- **Temporary failures** (timeouts, 5xx, rate limits from GitHub or OSV): the scan shows `retrying` with the reason and is retried with backoff. If the last attempt also fails, the scan ends `failed` with "Retries exhausted: <reason>".
- **Permanent failures** are recorded and not retried. A missing or private repository, or a rejected token, ends `failed`. No root `package-lock.json`, an unsupported lockfile version, invalid JSON, an empty repository or an oversized lockfile ends `unsupported` with the reason.
- **Some advisory lookups fail:** the scan completes with partial coverage and lists the dependencies it couldn't check. A partial result is never shown as clean. If every lookup fails, the scan is retried, then fails.
- **Worker crash mid-scan:** pg-boss notices the missed heartbeat (about 30 s) and retries the job under the same scan ID; Compose restarts the worker. A crash on the last attempt is caught by a dead-letter handler, which marks the scan `failed`. A periodic sweeper fails a scan only when its job has finished or disappeared, so a queue backlog or a stopped worker never fails a healthy scan.
- **Stale or duplicate workers:** each attempt owns the scan through an attempt counter. Findings and completion are written in one transaction on the locked scan row, so an older attempt or a duplicate delivery changes nothing.
- **AI explanations** that time out, fail validation or have no API key fall back to template text. They never fail a scan or change its coverage.
- **Private repositories:**
  - The app was uninstalled, or the repository removed from it, before the scan ran: the scan ends `failed` ("FirstFix no longer has access…") and is not retried.
  - GitHub timeouts and errors while reading are retried like any temporary failure.
  - A public repository that becomes private while queued fails as "not found or private". The worker never reads it with credentials.
  - Signed out, or without access: a private scan answers "not found", the same as a missing one.
  - An expired session (sign-ins last at most 8 hours) answers "sign in again".
  - GitHub unavailable while checking access answers 503 and is never served from an expired check.
- **Overload:** `POST /scans` returns 429 above the per-client rate and 503 when too many scans are outstanding. Resending with the same `Idempotency-Key` is safe.

Every scan outcome and the test that covers it are listed under [Lifecycle](docs/ARCHITECTURE.md#lifecycle).

## Limits and next steps

- **Scope:** one root npm `package-lock.json` (v2 or v3) per scan, read from the default branch of a github.com repository: public ones without an account, private ones through the FirstFix GitHub App after signing in. Dependency advisories only: no source-code analysis, secrets or reachability.
- **Ecosystems:** npm only. Lockfile parsing, version rules and upgrade commands are registered per ecosystem, so other lockfile ecosystems (Cargo, Poetry, Bundler, Composer) fit the same seams. Manifests without exact versions, such as a plain `requirements.txt` or Maven `pom.xml`, would need dependency resolution first.
- **Advisory data:** OSV.dev only, behind a provider-neutral contract. Findings reflect its coverage. Severity uses GitHub's advisory label; advisories without one show `unknown` (no CVSS scoring yet).
- **Not checked:** Git, local and non-registry tarball dependencies are listed as unchecked.
- **Candidate versions** come from advisory data and are never claimed as fixes. After applying a suggested upgrade, run the project's tests for compatibility and rescan the resulting lockfile to see whether the advisories still match.
- **Private repositories:** no webhooks and no refresh tokens. Users sign in again after at most 8 hours, and revoked access can still allow viewing a report for up to 5 minutes. An installation's repository list is read up to 10,000 entries. GitHub doesn't report pending organization approval requests, so FirstFix doesn't show them; the organization appears once an owner approves.
- **Operations:** the `POST /scans` rate limit keeps its counters in memory, so each API instance applies its own limit. Each worker runs 2 scans at a time (`WORKER_CONCURRENCY`). Finished scans are deleted after 30 days and idempotency keys after 24 hours (configurable, see [`.env.example`](.env.example)).
- **Next steps:** support more lockfile formats, and add a dedicated SAST worker for source-code analysis alongside dependency scans.

## Checks

Use Node.js 22.18+ and run `npm ci`. For the full test suite, set `DATABASE_URL` to a reachable PostgreSQL instance using a role that can create temporary databases.

```sh
npm run typecheck
npm run lint
npm test
npm run eval
```

The eval checks explanations against fixed fixtures. Export `LLM_API_KEY` in the shell to also evaluate the live model.

## How I used coding agents

I brainstormed with two AI models to explore different approaches. I made the final product and technical decisions, documented the architecture, and broke the work into milestones. I used Claude Code to implement most of the code one milestone at a time.

I also used AI to review the implementation and surface subtle issues. I verified the work with type checks, linting, tests, and independent reviews.

The [architecture](docs/ARCHITECTURE.md), [implementation plan](docs/PLAN.md), and [agent log](docs/AGENT_LOG.md) have more detail.
