# AI Scan Review

Paste a public GitHub repository URL, follow the scan as it runs, and get a prioritized review of the npm
dependencies: what to do first, why, how to verify it, and a prompt you can hand to a coding agent.
Facts come from the scan; AI only explains them.

- [Product interpretation](#product-interpretation)
- [Assumptions](#assumptions)
- [Quick start](#quick-start)
- [Demo repo](#demo-repo)
- [Architecture](#architecture)
- [Decisions](#decisions)
- [Failure behaviour](#failure-behaviour)
- [Limits](#limits)
- [Next steps](#next-steps)
- [How I used coding agents](#how-i-used-coding-agents)

## Product interpretation

The goal is to help a repository owner turn security findings into a prioritized next step, without needing
security expertise. How I read each part of the brief:

| The brief says | What this builds |
|---|---|
| "connect my repo" | paste a public GitHub URL; no install, no account |
| "code or dependencies" | npm dependencies, deliberately: every finding is verifiable against advisory data |
| "AI-assisted" | AI writes the explanation; versions, IDs, severities and steps are rendered from data |
| "not a raw report" | one summary line, up to three next actions, evidence one click away, everything else below |
| "what I should do next" | actions grouped by package, ranked, with how to verify; a coding-agent handoff prompt |
| "a product, not an API" | real UI states (progress, retrying, partial, clean, failed), shareable `/scans/:id` links |

The report is honest about what it doesn't know: candidate versions are never called fixes, coverage sits
beside the summary, a partial result never reads as clean, and nothing says "secure".

## Assumptions

- The reader owns the repository but isn't a security specialist; many will apply fixes through a coding agent.
- Public github.com repositories with a root `package-lock.json` (lockfile v2/v3, npm 7+). Other repositories
  get a clear "unsupported" with the reason.
- The default branch's current commit is scanned; every file read is pinned to that commit's SHA.
- Advisory data comes from [OSV.dev](https://osv.dev). Severity is GitHub's advisory label when present,
  otherwise "unknown" (shown, never hidden).
- "Runtime" and "dev" are the lockfile's classification. The scan doesn't see what is deployed or executed,
  and the report says so instead of guessing exposure.

## Quick start

Requirements: Docker. For the non-Docker path, Node.js 22.18+ (`.nvmrc`; `.ts` files run directly) and
PostgreSQL (developed and tested on 17).

### Docker

```sh
docker compose up --build
# open http://localhost:3000
```

Compose starts Postgres, runs migrations once, then the API (port 3000) and the worker. Optional settings go in
your shell or a `.env` file (see `.env.example`):

| Variable | Default | What it does |
|---|---|---|
| `GITHUB_TOKEN` | none | raises GitHub's limit from 60 to 5000 requests/hour |
| `LLM_API_KEY` | none | enables AI-written explanations; without it a template writes them (the report is complete either way) |
| `LLM_PROVIDER` | `anthropic` | which LLM adapter to use (only Anthropic is implemented) |
| `LLM_MODEL` | provider default (`claude-opus-5-5`) | model for explanations |
| `LLM_TIMEOUT_MS` | `20000` | after this, the template's text is used |
| `WORKER_CONCURRENCY` | `2` | scans per worker process |

### Without Docker

```sh
nvm use                                  # Node 22
npm ci
export DATABASE_URL=postgres://scan:scan@localhost:5432/scan
docker compose up -d postgres            # or any PostgreSQL with that URL
npm run migrate
npm run build:web
npm run api                              # terminal 1: http://localhost:3000
npm run worker                           # terminal 2
```

### Checks

```sh
npm run typecheck && npm run lint && npm test   # tests create throwaway databases next to DATABASE_URL
npm run eval                                    # explanation checks over fixed fixtures (AI only with LLM_API_KEY)
```

The test suite takes about two minutes: about 35 s of it runs real crash and restart scenarios through
pg-boss.

## Demo repo

**[arturowin/scan-review-demo](https://github.com/arturowin/scan-review-demo)**: a repository that exists to
be scanned.

> ⚠️ **Do not `npm install` it.** Its lockfile pins known-vulnerable and known-malicious package versions on
> purpose. It contains no application code.

It covers each case the report has to handle:
- a known malicious package (`flatmap-stream`);
- direct and transitive vulnerabilities (`lodash`, `qs` via `express` and via `request`, at two versions);
- a package with many advisories and a major-version jump (`postcss`);
- a dev-only dependency (`minimist`);
- no fixed version published (`request`);
- a git dependency that can't be checked (`slash`);
- a workspace.

Scanned end to end on the live stack: 107 dependencies, 106 checked, 1 not checked (git source). It finds 1
malicious package and 14 vulnerable ones, and starts with "remove flatmap-stream".

Real repositories also tried:

| Repository | Dependencies | Time | Result |
|---|---|---|---|
| `nestjs/nest` | 1425, all checked | 8 s | 21 packages with known vulnerabilities |
| `npm/cli` (workspaces) | 993, all checked | 8 s | 17 packages with known vulnerabilities |
| `microsoft/vscode` | none | 3 s | unsupported: no root `package-lock.json` |

## Architecture

```
 browser ──HTTP──▶ API process ──┐                ┌── worker process(es) ──▶ GitHub (SHA-pinned reads)
 (static UI,       (Fastify, zod, │   PostgreSQL   │   ScanPipeline           OSV.dev (advisories)
  polls /scans/:id) idempotency)  └─ scans, findings, pg-boss queue ─┘          LLM (optional, explanations)
```

- **Two processes, one database.** A scan row and its pg-boss job are created in one transaction (job id =
  scan id), so a scan never exists without its job. The UI polls the scan row for progress.
- **Pipeline** (`src/application/scan-pipeline.ts`), in order:
  1. claim the attempt;
  2. resolve the default branch to a SHA;
  3. find a supported lockfile at that SHA;
  4. parse it (dependency graph: direct parents, install paths);
  5. look up advisories (partial coverage allowed);
  6. pick candidate versions;
  7. rank and group into actions;
  8. explain;
  9. save findings and completion in one locked, attempt-guarded transaction.
- **Hexagonal, enforced by lint.** `domain/` is pure (no I/O), `application/` talks to `ports/` only, and
  `adapters/` implement them: GitHub, OSV, Postgres, pg-boss, the LLM, and the template explainer. Import rules
  live in `eslint.boundaries.js`, with tests.
- **Seams for growth, each with a contract test suite:**
  - **Ecosystems:** a lockfile-format registry, version schemes and remediation hints. A test-only ecosystem
    runs through the real pipeline.
  - **Advisory sources:** a neutral `AffectedRange`, with the provider adapter owning all translation.
  - **LLM providers:** one adapter per provider plus a registry line; only that adapter may import its SDK.
- More detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Milestones: [`docs/PLAN.md`](docs/PLAN.md).

## Decisions

| Decision | Why |
|---|---|
| Postgres + pg-boss (same database) instead of Redis/BullMQ | one dependency to run; job creation shares the scan's transaction |
| Explicit SQL, no ORM | the attempt guard (`WHERE id = $1 AND attempt = $2`) and the locked completion must stay visible |
| Every scan-row write is attempt-guarded; recovery bumps the attempt | a stale or zombie worker can never overwrite a newer outcome |
| Read files by commit SHA, never by branch | the report describes exactly one commit, even if the branch moves mid-scan |
| Ranking: malicious › severity › runtime before dev › direct before transitive | fix availability shapes the action, not the urgency |
| One action per package, across installed versions | that's the unit someone changes |
| A candidate is checked against **every** advisory's ranges | advisories can affect separate version intervals; "addresses N" counts only what the version leaves |
| npm aliases are looked up by their real name; every declaration is a required update | an alias under its folder name gives a false clean result; two aliases are two changes |
| AI writes prose only, checked against the facts before use | no invented versions or advisory IDs, no other package's evidence, no "secure"/"fixed"; otherwise the template |
| Actions are built when the report is read, from stored findings | findings are the stored facts; wording improvements apply to old reports |
| Node runs `.ts` directly (type stripping) | no build step for the server; the UI is bundled with esbuild |

## Failure behaviour

Every lifecycle outcome is reachable and tested; the outcome → test map is in
[`docs/ARCHITECTURE.md` › Lifecycle](docs/ARCHITECTURE.md#lifecycle).

| What happens | Result |
|---|---|
| Repository not found, private, or token rejected | `failed` with the reason, not retried |
| No supported lockfile, lockfile v1, invalid JSON, empty repo, lockfile over 50 MB | `unsupported` with the reason |
| GitHub/OSV timeout, 5xx, rate limit | `retrying` (the UI shows why), retried with backoff (3 retries) |
| Retries exhausted | `failed`: "Retries exhausted: <reason>" |
| Some advisory lookups fail | `completed`, coverage **partial**; those packages listed as "lookup failed, scan again" |
| Every advisory lookup fails | retried; `failed` once retries run out |
| All dependencies from git/file/URL sources | `completed`, "No dependencies could be checked" (never "no vulnerabilities") |
| Worker stopped or killed mid-scan | the job is retried (after the 30 s heartbeat for a hard crash) and completes |
| Worker crashes on the last attempt | dead-lettered → `failed`, not stuck |
| A job lost for any other reason | the sweeper (every 60 s) fails scans whose job is finished or missing; queued/active jobs are left alone |
| LLM missing, slow, failing, refusing, or wrong | template explanation; the scan never fails because of prose |
| Duplicate job delivery, stale attempt, zombie worker | no effect (attempt guard; completed scans are never reopened) |

## Limits

- **Scope:**
  - Public github.com repositories only (next: a GitHub App for private repos).
  - npm only: one root `package-lock.json`, lockfileVersion 2 or 3. The ecosystem seams are ready for
    ecosystems that have lockfiles (Cargo.lock, poetry.lock/uv.lock, Gemfile.lock, composer.lock). Manifests
    with ranges and no lockfile (plain `requirements.txt`, `pom.xml`) need dependency resolution first, which
    is a different problem.
  - One lockfile per scan: npm and Python in one repository would need per-lockfile coverage.
  - Not a SAST, secrets or reachability scanner.
- **Data:**
  - One advisory source (OSV.dev); findings reflect its coverage. The provider contract is ready for others
    but none is implemented.
  - Severity is GitHub's label only; there's no CVSS parsing, so records without a label show "unknown".
  - Candidate versions come from advisory data; compatibility and resolution aren't checked. Only a rescan
    confirms.
- **AI text:** it's checked for invented identifiers and versions, overlong text and banned claims, but the
  truth of its prose can't be validated. That's why it's labelled and facts never come from it.
- **Operations:**
  - No rate limiting on `POST /scans`.
  - Worker concurrency is set per process (`WORKER_CONCURRENCY`); there's no global limit.
  - Idempotency keys are kept forever (no retention job).
  - GitHub without a token allows 60 requests/hour per IP; each scan uses 2 API calls plus raw file reads.

## Next steps

1. Private repositories through a GitHub App (installation tokens, the same SHA-pinned reads).
2. More lockfile formats on the existing seams: `yarn.lock` and `pnpm-lock.yaml` for npm first, then
   `poetry.lock` / `uv.lock`.
3. CVSS-based severity when the label is missing; a second advisory source behind the same contract.
4. Rescan diffs ("2 fixed, 1 new since last scan"), so the loop of upgrade → rescan → confirm is visible.
5. A rate limit on `POST /scans` and a retention job for idempotency keys and old scans.
6. Reachability hints for the top action (is the vulnerable function imported?), labelled as heuristics.

## How I used coding agents

I built this with Claude Code as a pair. I made the product and design calls; the agent wrote most of the code
under a written plan and rules (`CLAUDE.md`, `docs/PLAN.md`), one milestone at a time. External reviews
checked each milestone. The raw log is [`docs/AGENT_LOG.md`](docs/AGENT_LOG.md); this is the summary.

**How the work was set up**
- **Plan before code.** Each milestone started with the agent listing the files, tests and open decisions,
  and coding only after I approved. Decisions that were mine stayed mine: workspace dependencies count as
  direct, what a major jump means on 0.x, building actions when the report is read, switchable LLM providers,
  partial coverage instead of retrying.
- **Verify, don't assume.** Before any queue or OSV code existed, the agent wrote contract tests against the
  installed pg-boss version and saved real OSV responses as fixtures. That surfaced facts the docs had wrong:
  pg-boss 12, not 10; no archive table; heartbeat-based crash detection.
- **One commit per green step**, with typecheck, lint and tests run before each.

**What the reviews and I caught**, with each fix a test:
- The parser named npm aliases by their install folder, so `my-lodash` was looked up instead of `lodash`.
  That could have produced a false clean result.
- The candidate logic called a version "addresses both advisories" when it sat inside a second vulnerable
  interval of one of them.
- Two aliases were offered as alternatives ("A or B") when both needed updating, and "candidate or later"
  promised more than was checked.
- The fallback text could fail the scan it was meant to protect: a package named `safe-buffer` tripped the
  "safe" check.
- The explanation check pooled every package's evidence, so one package's text could quote another's.
- Wording claimed deployment facts the scan can't see ("ships with the application").
- The sweeper could circle the same 100 healthy scans forever, missing a lost one behind them.
- Malformed advisory data could reject a whole lookup instead of one package.
- Unchecked packages were all labelled "non-registry source", even when the lookup had only failed.

**Where the agent was wrong or I overruled it**
- It committed one step with lint errors (its command chain didn't stop on them); it fixed and amended the
  commit before moving on.
- Its first lockfile picked up an internal company registry from my machine's npm config. Caught before any
  push, it was regenerated against the public registry, and `.npmrc` now pins it.
- It proposed `tsx`; I chose running `.ts` directly on Node 22.

**What I'd keep doing:** contract tests for every external system before relying on it, failure tests
through the real queue rather than mocks, and a reviewer reading each milestone with fresh eyes.
