// Composition root for the worker process.
import { PgBoss } from 'pg-boss';
import { GitHubRepoSource } from '../adapters/github/repo-source.ts';
import { OsvVulnDatabase } from '../adapters/osv/vuln-database.ts';
import { createPool } from '../adapters/postgres/pool.ts';
import { PostgresScanRepository } from '../adapters/postgres/scan-repository.ts';
import { ensureQueues, SCAN_QUEUE } from '../adapters/pgboss/queue.ts';
import { ScanPipeline } from '../application/scan-pipeline.ts';
import { startScanWorker } from './scan-worker.ts';
import { TemplateExplainer } from '../adapters/template-explainer.ts';
import { LlmExplainer } from '../adapters/llm/explainer.ts';
import { llmClientFromEnv, llmTimeoutMs } from '../adapters/llm/registry.ts';

const databaseUrl = process.env['DATABASE_URL'];
if (!databaseUrl) {
  console.error('DATABASE_URL is not set (see .env.example)');
  process.exit(1);
}
const concurrency = Number(process.env['WORKER_CONCURRENCY'] ?? 2);

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

const pipeline = new ScanPipeline({
  scans: new PostgresScanRepository(pool),
  source: new GitHubRepoSource({ token: process.env['GITHUB_TOKEN'] || undefined }),
  vulns: new OsvVulnDatabase(),
  explain: {
    ai: llm ? new LlmExplainer(llm) : null,
    template: new TemplateExplainer(),
    timeoutMs: llmTimeoutMs(process.env),
  },
});

await startScanWorker(boss, {
  pipeline,
  concurrency,
  log: (entry) => {
    console.log(JSON.stringify(entry));
  },
});
console.log(`worker: listening on queue "${SCAN_QUEUE}" (concurrency ${concurrency})`);

let stopping = false;
async function shutdown(signal: string): Promise<void> {
  if (stopping) return;
  stopping = true;
  console.log(`worker: ${signal}, finishing in-flight scans`);
  // Graceful: in-flight jobs get up to 30 s; anything cut off is retried via heartbeat/expiry.
  await boss.stop({ graceful: true, timeout: 30_000 });
  await pool.end();
  process.exit(0);
}
process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));
