import path from 'node:path';
import pg from 'pg';
import { PgBoss } from 'pg-boss';
import { migrate } from '../../src/adapters/postgres/migrate.ts';
import { ensureQueues } from '../../src/adapters/pgboss/queue.ts';
import { createTestDatabase, type TestDatabase } from './db.ts';

export interface TestEnv {
  db: TestDatabase;
  pool: pg.Pool;
  boss: PgBoss;
  close: () => Promise<void>;
}

/** A fresh database with our schema, pg-boss installed and the scan queues created. */
export async function createTestEnv(): Promise<TestEnv> {
  const db = await createTestDatabase();
  const pool = new pg.Pool({ connectionString: db.url });
  await migrate(pool, path.join(import.meta.dirname, '..', '..', 'migrations'));
  const boss = new PgBoss({ connectionString: db.url, superviseIntervalSeconds: 1, monitorIntervalSeconds: 1 });
  boss.on('error', (err: unknown) => {
    console.error('pg-boss error', err);
  });
  await boss.start();
  await ensureQueues(boss);
  return {
    db,
    pool,
    boss,
    close: async () => {
      await boss.stop({ graceful: false });
      await pool.end();
      await db.drop();
    },
  };
}
