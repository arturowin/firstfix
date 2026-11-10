import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import type pg from 'pg';

const MIGRATION_FILE = /^(\d{3})_[a-z0-9_]+\.sql$/;
// Arbitrary constant: serializes concurrent `migrate` runs on the same database.
const ADVISORY_LOCK_KEY = 727_001;

export interface MigrationResult {
  applied: string[];
  skipped: string[];
}

export async function listMigrationFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir);
  const files = entries.filter((f) => f.endsWith('.sql'));
  for (const f of files) {
    if (!MIGRATION_FILE.test(f)) {
      throw new Error(`bad migration file name: ${f} (expected NNN_name.sql)`);
    }
  }
  files.sort();
  const seen = new Set<string>();
  for (const f of files) {
    const n = f.slice(0, 3);
    if (seen.has(n)) throw new Error(`duplicate migration number: ${n}`);
    seen.add(n);
  }
  return files;
}

export function checksum(sql: string): string {
  return createHash('sha256').update(sql).digest('hex');
}

/**
 * Applies pending migrations in order. Each file runs in its own transaction together with
 * its row in schema_migrations, so a failed file leaves no partial state and is retried next run.
 * An already-applied file whose content changed is an error, never silently skipped.
 */
export async function migrate(pool: pg.Pool, dir: string): Promise<MigrationResult> {
  const files = await listMigrationFiles(dir);
  const client = await pool.connect();
  const result: MigrationResult = { applied: [], skipped: [] };
  // Set when the connection can't be trusted any more (e.g. ROLLBACK failed); it is then
  // destroyed on release instead of going back to the pool.
  let broken: Error | undefined;
  try {
    await client.query('SELECT pg_advisory_lock($1)', [ADVISORY_LOCK_KEY]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name       text PRIMARY KEY,
        checksum   text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )`);
    const { rows } = await client.query<{ name: string; checksum: string }>(
      'SELECT name, checksum FROM schema_migrations',
    );
    const done = new Map(rows.map((r) => [r.name, r.checksum]));

    for (const file of files) {
      const sql = await readFile(path.join(dir, file), 'utf8');
      const sum = checksum(sql);
      const appliedSum = done.get(file);
      if (appliedSum !== undefined) {
        if (appliedSum !== sum) {
          throw new Error(`migration ${file} was changed after it was applied; add a new migration instead`);
        }
        result.skipped.push(file);
        continue;
      }
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)', [file, sum]);
        await client.query('COMMIT');
      } catch (err) {
        try {
          await client.query('ROLLBACK');
        } catch (rollbackErr) {
          broken = rollbackErr instanceof Error ? rollbackErr : new Error(String(rollbackErr));
        }
        // Always report the migration's own error; a rollback failure is secondary.
        throw new Error(`migration ${file} failed`, { cause: err });
      }
      result.applied.push(file);
    }
    return result;
  } finally {
    if (!broken) {
      await client.query('SELECT pg_advisory_unlock($1)', [ADVISORY_LOCK_KEY]).catch((err: unknown) => {
        broken = err instanceof Error ? err : new Error(String(err));
      });
    }
    // release(err) destroys the connection (which also drops the session's advisory lock).
    client.release(broken);
  }
}
