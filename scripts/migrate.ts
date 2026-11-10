import path from 'node:path';
import pg from 'pg';
import { migrate } from '../src/adapters/postgres/migrate.ts';

const url = process.env['DATABASE_URL'];
if (!url) {
  console.error('DATABASE_URL is not set (see .env.example)');
  process.exit(1);
}

const pool = new pg.Pool({ connectionString: url });
try {
  const dir = path.join(import.meta.dirname, '..', 'migrations');
  const { applied, skipped } = await migrate(pool, dir);
  console.log(`migrations: ${applied.length} applied, ${skipped.length} already applied`);
  for (const f of applied) console.log(`  + ${f}`);
} finally {
  await pool.end();
}
