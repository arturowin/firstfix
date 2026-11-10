// Composition root for the API process.
import path from 'node:path';
import { PgBoss } from 'pg-boss';
import { createPool } from '../adapters/postgres/pool.ts';
import { PostgresScanRepository } from '../adapters/postgres/scan-repository.ts';
import { PostgresScanSubmission } from '../adapters/postgres/scan-submission.ts';
import { ensureQueues } from '../adapters/pgboss/queue.ts';
import { ScanService } from '../application/scan-service.ts';
import { buildApp } from './app.ts';

const databaseUrl = process.env['DATABASE_URL'];
if (!databaseUrl) {
  console.error('DATABASE_URL is not set (see .env.example)');
  process.exit(1);
}
const port = Number(process.env['PORT'] ?? 3000);
const host = process.env['HOST'] ?? '0.0.0.0';

const pool = createPool(databaseUrl);
// The API only sends jobs: no supervision or maintenance here, the worker runs those.
const boss = new PgBoss({ connectionString: databaseUrl, supervise: false, schedule: false });
boss.on('error', (err: unknown) => {
  console.error('pg-boss error', err);
});
await boss.start();
await ensureQueues(boss);

const app = buildApp({
  scans: new ScanService(new PostgresScanSubmission(pool, boss), new PostgresScanRepository(pool)),
  checkReady: async () => {
    await pool.query('SELECT 1');
  },
  webDir: path.join(import.meta.dirname, '..', '..', 'dist', 'web'),
  logger: true,
});

let stopping = false;
async function shutdown(signal: string): Promise<void> {
  if (stopping) return;
  stopping = true;
  app.log.info(`${signal}: shutting down`);
  await app.close();
  await boss.stop({ graceful: true });
  await pool.end();
  process.exit(0);
}
process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));

await app.listen({ port, host });
