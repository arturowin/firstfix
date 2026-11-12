// Composition root for the worker process.
import { PgBoss } from 'pg-boss';
import { GitHubRepoSource } from '../adapters/github/repo-source.ts';
import { GitHubAppTokens } from '../adapters/github/app-tokens.ts';
import { checkPublicOnlyToken } from '../adapters/github/public-token.ts';
import { PostgresSessionRetention } from '../adapters/postgres/session-store.ts';
import { OsvVulnDatabase } from '../adapters/osv/vuln-database.ts';
import { createPool } from '../adapters/postgres/pool.ts';
import { PostgresScanRepository } from '../adapters/postgres/scan-repository.ts';
import { ensureQueues, SCAN_QUEUE } from '../adapters/pgboss/queue.ts';
import { ScanPipeline } from '../application/scan-pipeline.ts';
import { startPeriodic, startScanWorker, startSweeper } from './scan-worker.ts';
import { purgeExpired } from '../application/retention.ts';
import { Sweeper } from '../application/lost-scans.ts';
import { PgBossJobQueue } from '../adapters/pgboss/job-queue.ts';
import { TemplateExplainer } from '../adapters/template-explainer.ts';
import { LlmExplainer } from '../adapters/llm/explainer.ts';
import { llmClientFromEnv, llmTimeoutMs } from '../adapters/llm/registry.ts';

const databaseUrl = process.env['DATABASE_URL'];
if (!databaseUrl) {
  console.error('DATABASE_URL is not set (see .env.example)');
  process.exit(1);
}
const concurrency = Number(process.env['WORKER_CONCURRENCY'] ?? 2);

// Private scans: the FirstFix GitHub App (client id + private key), both or neither.
const appClientId = process.env['GITHUB_APP_CLIENT_ID']?.trim() ?? '';
const appPrivateKey = process.env['GITHUB_APP_PRIVATE_KEY']?.trim() ?? '';
if ((appClientId === '') !== (appPrivateKey === '')) {
  console.error('Set both GITHUB_APP_CLIENT_ID and GITHUB_APP_PRIVATE_KEY for private repositories, or neither');
  process.exit(1);
}
let appTokens: GitHubAppTokens | undefined;
try {
  appTokens = appClientId ? new GitHubAppTokens({ clientId: appClientId, privateKey: appPrivateKey }) : undefined;
} catch {
  console.error('GITHUB_APP_PRIVATE_KEY is not a valid PEM private key');
  process.exit(1);
}

// Public scans never use credentials that can read private repositories: GITHUB_TOKEN is used only when
// GitHub confirms it can't (docs/ARCHITECTURE.md "Public and private paths never mix").
const configuredToken = process.env['GITHUB_TOKEN']?.trim() || undefined;
const tokenCheck = configuredToken ? await checkPublicOnlyToken(configuredToken) : null;
const publicToken = tokenCheck === 'public_only' ? configuredToken : undefined;
if (tokenCheck !== null && tokenCheck !== 'public_only') {
  console.error(
    JSON.stringify({
      msg: 'GITHUB_TOKEN not used for public scans',
      reason: tokenCheck, // privileged: can read private repositories; invalid; unverified: GitHub didn't answer
      fix: 'use a fine-grained token with public repositories (read-only) access',
    }),
  );
}
console.log(JSON.stringify({ msg: 'github', publicToken: publicToken !== undefined, privateRepos: appTokens !== undefined }));

const pool = createPool(databaseUrl);
const boss = new PgBoss({ connectionString: databaseUrl });
boss.on('error', (err: unknown) => {
  console.error('pg-boss error', err);
});
await boss.start();
await ensureQueues(boss);

// No LLM_API_KEY → template explanations only (the app works without a key).
const llm = llmClientFromEnv(process.env);
console.log(JSON.stringify({ msg: 'explanations', llm: llm ? `${llm.provider}/${llm.model}` : 'none (template only)' }));

const scans = new PostgresScanRepository(pool);
const sessionRetention = new PostgresSessionRetention(pool);
const pipeline = new ScanPipeline({
  scans,
  source: new GitHubRepoSource({ token: publicToken, appTokens }),
  vulns: new OsvVulnDatabase(),
  explain: {
    ai: llm ? new LlmExplainer(llm) : null,
    template: new TemplateExplainer(),
    timeoutMs: llmTimeoutMs(process.env),
  },
});

const log = (entry: Record<string, unknown>) => {
  console.log(JSON.stringify(entry));
};
await startScanWorker(boss, { pipeline, scans, concurrency, log });

// Safety net for scans whose job is gone. Staleness = longer than one attempt can take (expireInSeconds 300)
// plus retry backoff and a margin; the job's state in pg-boss decides, not the clock.
// Retention: finished scans after SCAN_RETENTION_DAYS (cascading), idempotency keys after IDEMPOTENCY_KEY_TTL_HOURS.
const positive = (name: string, fallback: number) => {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};
const stopRetention = startPeriodic(
  'retention',
  async () => {
    const r = await purgeExpired(scans, {
      scanDays: positive('SCAN_RETENTION_DAYS', 30),
      keyHours: positive('IDEMPOTENCY_KEY_TTL_HOURS', 24),
    });
    const sessions = await sessionRetention.deleteExpired(500);
    if (r.scans + r.keys + sessions > 0) log({ msg: 'retention deleted expired rows', ...r, sessions });
  },
  positive('RETENTION_INTERVAL_MS', 3_600_000),
  log,
);

const stopSweeper = startSweeper(
  new Sweeper({ scans, jobs: new PgBossJobQueue(boss), staleAfterSeconds: Number(process.env['SWEEP_STALE_AFTER_SECONDS'] ?? 600) }),
  Number(process.env['SWEEP_INTERVAL_MS'] ?? 60_000),
  log,
);
console.log(`worker: listening on queue "${SCAN_QUEUE}" (concurrency ${concurrency})`);

let stopping = false;
async function shutdown(signal: string): Promise<void> {
  if (stopping) return;
  stopping = true;
  console.log(`worker: ${signal}, finishing in-flight scans`);
  stopSweeper();
  stopRetention();
  // Graceful: in-flight jobs get up to 30 s; anything cut off is retried via heartbeat/expiry.
  await boss.stop({ graceful: true, timeout: 30_000 });
  await pool.end();
  process.exit(0);
}
process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));
