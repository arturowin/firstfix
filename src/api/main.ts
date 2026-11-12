// Composition root for the API process.
import path from 'node:path';
import { PgBoss } from 'pg-boss';
import { createPool } from '../adapters/postgres/pool.ts';
import { PostgresScanRepository } from '../adapters/postgres/scan-repository.ts';
import { PostgresScanSubmission } from '../adapters/postgres/scan-submission.ts';
import { ensureQueues } from '../adapters/pgboss/queue.ts';
import { ScanService } from '../application/scan-service.ts';
import { AccessService } from '../application/access-service.ts';
import { GitHubUserAuth } from '../adapters/github/user-auth.ts';
import { PostgresSessionStore } from '../adapters/postgres/session-store.ts';
import { SecretBox } from '../adapters/secret-box.ts';
import { buildApp } from './app.ts';
import { fixedWindowLimiter } from './rate-limit.ts';
import { signInConfig, type SignInConfig } from './sign-in-config.ts';

const databaseUrl = process.env['DATABASE_URL'];
if (!databaseUrl) {
  console.error('DATABASE_URL is not set (see .env.example)');
  process.exit(1);
}
let config: SignInConfig | null;
try {
  config = signInConfig(process.env);
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err));
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

const intEnv = (name: string, fallback: number) => {
  const n = Number(process.env[name]);
  return Number.isInteger(n) && n > 0 ? n : fallback;
};

// GitHub sign-in and private repositories: only with the GitHub App configured (docs/ARCHITECTURE.md).
const signIn = config
  ? {
      publicUrl: config.publicUrl,
      access: new AccessService({
        github: new GitHubUserAuth({ clientId: config.clientId, clientSecret: config.clientSecret, slug: config.slug }),
        sessions: new PostgresSessionStore(pool, new SecretBox(config.sessionSecret)),
        redirectUri: `${config.publicUrl}/auth/callback`,
      }),
    }
  : null;
console.log(JSON.stringify({ msg: 'github sign-in', enabled: signIn !== null }));

const app = buildApp({
  signIn,
  scans: new ScanService(
    new PostgresScanSubmission(pool, boss, { maxOutstanding: intEnv('MAX_OUTSTANDING_SCANS', 200) }),
    new PostgresScanRepository(pool),
  ),
  submitLimiter: fixedWindowLimiter(intEnv('SUBMIT_RATE_PER_MINUTE', 10)),
  trustProxy: process.env['TRUST_PROXY'] === 'true',
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
