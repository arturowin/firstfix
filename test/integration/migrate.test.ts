import { randomUUID } from 'node:crypto';
import { copyFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import pg from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { migrate } from '../../src/adapters/postgres/migrate.ts';
import { createTestDatabase, type TestDatabase } from '../support/db.ts';

const MIGRATIONS = path.join(import.meta.dirname, '..', '..', 'migrations');

describe('migrate', () => {
  let db: TestDatabase;
  let pool: pg.Pool;

  beforeAll(async () => {
    db = await createTestDatabase();
    pool = new pg.Pool({ connectionString: db.url });
  });

  afterAll(async () => {
    await pool.end();
    await db.drop();
  });

  it('applies all migrations on a fresh database, then is a no-op', async () => {
    const first = await migrate(pool, MIGRATIONS);
    expect(first.applied).toContain('001_init.sql');
    expect(first.skipped).toEqual([]);

    const second = await migrate(pool, MIGRATIONS);
    expect(second.applied).toEqual([]);
    expect(second.skipped).toEqual(first.applied);

    const { rows } = await pool.query<{ table_name: string }>(
      `SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' ORDER BY table_name`,
    );
    expect(rows.map((r) => r.table_name)).toEqual([
      'findings',
      'idempotency_keys',
      'scans',
      'schema_migrations',
      'unchecked_deps',
    ]);
  });

  it('serializes concurrent runs (each migration applied exactly once)', async () => {
    const fresh = await createTestDatabase();
    const p = new pg.Pool({ connectionString: fresh.url });
    try {
      const results = await Promise.all([migrate(p, MIGRATIONS), migrate(p, MIGRATIONS)]);
      const appliedTotal = results.flatMap((r) => r.applied);
      expect(appliedTotal.filter((f) => f === '001_init.sql')).toHaveLength(1);
    } finally {
      await p.end();
      await fresh.drop();
    }
  });

  it('rejects an invalid status', async () => {
    await expect(
      pool.query(
        `INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized, status)
         VALUES (gen_random_uuid(), 'o', 'r', 'https://github.com/o/r', 'done')`,
      ),
    ).rejects.toThrow(/check constraint/);
  });

  it('allows a stage only while running', async () => {
    const insert = (status: string) =>
      pool.query(
        `INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized, status, stage)
         VALUES (gen_random_uuid(), 'o', 'r', 'https://github.com/o/r', $1, 'scanning')`,
        [status],
      );
    await expect(insert('running')).resolves.toBeDefined();
    await expect(insert('retrying')).rejects.toThrow(/stage_only_while_running/);
    await expect(insert('queued')).rejects.toThrow(/stage_only_while_running/);
  });

  it('maintains updated_at on every update without the statement setting it', async () => {
    const { rows } = await pool.query<{ id: string; updated_at: Date }>(
      `INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized, updated_at)
       VALUES (gen_random_uuid(), 'o', 'r', 'https://github.com/o/r', now() - interval '1 hour')
       RETURNING id, updated_at`,
    );
    const before = rows[0];
    if (!before) throw new Error('insert returned no row');
    await pool.query(`UPDATE scans SET status = 'running' WHERE id = $1`, [before.id]);
    const after = await pool.query<{ updated_at: Date }>('SELECT updated_at FROM scans WHERE id = $1', [before.id]);
    expect(after.rows[0]?.updated_at.getTime()).toBeGreaterThan(before.updated_at.getTime() + 59 * 60_000);
  });
});

describe('scans status bookkeeping (trigger)', () => {
  let db: TestDatabase;
  let pool: pg.Pool;

  beforeAll(async () => {
    db = await createTestDatabase();
    pool = new pg.Pool({ connectionString: db.url });
    await migrate(pool, MIGRATIONS);
  });

  afterAll(async () => {
    await pool.end();
    await db.drop();
  });

  async function runningScan(): Promise<string> {
    const { rows } = await pool.query<{ id: string }>(
      `INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized, status, stage, attempt)
       VALUES (gen_random_uuid(), 'o', 'r', 'https://github.com/o/r', 'running', 'scanning', 1)
       RETURNING id`,
    );
    const id = rows[0]?.id;
    if (!id) throw new Error('insert returned no row');
    return id;
  }

  async function row(id: string) {
    const { rows } = await pool.query<{ status: string; stage: string | null; completed_at: Date | null; attempt: number }>(
      'SELECT status, stage, completed_at, attempt FROM scans WHERE id = $1',
      [id],
    );
    return rows[0];
  }

  it('the documented dead-letter/sweeper update succeeds on a running scan with a stage', async () => {
    const id = await runningScan();
    // Exactly the statement from ARCHITECTURE.md: it does not mention stage or completed_at.
    const res = await pool.query(
      `UPDATE scans SET status = 'failed', attempt = attempt + 1, error_code = 'retries_exhausted'
        WHERE id = $1 AND status NOT IN ('completed', 'failed', 'unsupported')`,
      [id],
    );
    expect(res.rowCount).toBe(1);
    expect(await row(id)).toMatchObject({ status: 'failed', stage: null, attempt: 2 });
    expect((await row(id))?.completed_at).toBeInstanceOf(Date);
  });

  it('moving to retrying clears the stage', async () => {
    const id = await runningScan();
    await pool.query(`UPDATE scans SET status = 'retrying' WHERE id = $1 AND attempt = 1`, [id]);
    expect(await row(id)).toMatchObject({ status: 'retrying', stage: null, completed_at: null });
  });

  it('completion stamps completed_at', async () => {
    const id = await runningScan();
    await pool.query(`UPDATE scans SET status = 'completed', coverage = 'full' WHERE id = $1 AND attempt = 1`, [id]);
    expect(await row(id)).toMatchObject({ status: 'completed', stage: null });
    expect((await row(id))?.completed_at).toBeInstanceOf(Date);
  });

  it('a terminal scan cannot leave its terminal state', async () => {
    const id = await runningScan();
    await pool.query(`UPDATE scans SET status = 'failed' WHERE id = $1`, [id]);
    await expect(pool.query(`UPDATE scans SET status = 'running' WHERE id = $1`, [id])).rejects.toThrow(
      /terminal state/,
    );
    // Non-status updates on a terminal row (e.g. an attempt bump) are still allowed.
    await expect(pool.query('UPDATE scans SET attempt = attempt + 1 WHERE id = $1', [id])).resolves.toBeDefined();
  });
});

describe('migrate: failures', () => {
  let db: TestDatabase;
  let pool: pg.Pool;
  let dir: string;

  beforeEach(async () => {
    db = await createTestDatabase();
    pool = new pg.Pool({ connectionString: db.url });
    dir = await mkdtemp(path.join(tmpdir(), 'migrations-'));
  });

  afterEach(async () => {
    await pool.end();
    await db.drop();
    await rm(dir, { recursive: true, force: true });
  });

  it('a failing migration reports its own error and leaves nothing behind', async () => {
    await writeFile(path.join(dir, '001_ok.sql'), 'CREATE TABLE a (id int);');
    await writeFile(path.join(dir, '002_bad.sql'), 'CREATE TABLE b (id int); SELECT * FROM missing_table;');

    const err: unknown = await migrate(pool, dir).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toBe('migration 002_bad.sql failed');
    expect(String((err as Error).cause)).toMatch(/missing_table/);

    const { rows } = await pool.query<{ name: string }>('SELECT name FROM schema_migrations ORDER BY name');
    expect(rows.map((r) => r.name)).toEqual(['001_ok.sql']);
    const b = await pool.query(`SELECT to_regclass('public.b') AS t`);
    expect(b.rows[0]).toEqual({ t: null });

    // The pool is still usable afterwards (the lock was released, the client returned or discarded).
    await writeFile(path.join(dir, '002_bad.sql'), 'CREATE TABLE b (id int);');
    expect((await migrate(pool, dir)).applied).toEqual(['002_bad.sql']);
  });

  it('refuses to run when an applied migration was edited', async () => {
    await writeFile(path.join(dir, '001_a.sql'), 'CREATE TABLE a (id int);');
    await migrate(pool, dir);
    await writeFile(path.join(dir, '001_a.sql'), 'CREATE TABLE a (id int, extra text);');
    await expect(migrate(pool, dir)).rejects.toThrow(/001_a\.sql was changed after it was applied/);
  });
});

describe('migration 002: ecosystem', () => {
  let db: TestDatabase;
  let pool: pg.Pool;
  let dir: string;

  beforeAll(async () => {
    db = await createTestDatabase();
    pool = new pg.Pool({ connectionString: db.url });
    // Start from a database that only has 001, with data written before ecosystems existed.
    dir = await mkdtemp(path.join(tmpdir(), 'migrations-001-'));
    await copyFile(path.join(MIGRATIONS, '001_init.sql'), path.join(dir, '001_init.sql'));
    await migrate(pool, dir);
  });

  afterAll(async () => {
    await pool.end();
    await db.drop();
    await rm(dir, { recursive: true, force: true });
  });

  it('keeps existing rows as npm, and the unique key includes the ecosystem', async () => {
    const id = randomUUID();
    await pool.query(
      `INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized) VALUES ($1, 'o', 'r', 'https://github.com/o/r')`,
      [id],
    );
    const finding = `INSERT INTO findings (scan_id, package, installed_version, scope, is_direct, advisory_id, severity)
                     VALUES ($1, 'lodash', '4.17.20', 'runtime', true, 'GHSA-1', 'high')`;
    await pool.query(finding, [id]);
    await pool.query(`INSERT INTO unchecked_deps (scan_id, package, version, reason) VALUES ($1, 'g', '1.0.0', 'unsupported_source')`, [id]);

    expect((await migrate(pool, MIGRATIONS)).applied).toEqual(['002_ecosystem.sql']);

    const f = await pool.query<{ ecosystem: string }>('SELECT ecosystem FROM findings WHERE scan_id = $1', [id]);
    const u = await pool.query<{ ecosystem: string }>('SELECT ecosystem FROM unchecked_deps WHERE scan_id = $1', [id]);
    expect([...f.rows, ...u.rows]).toEqual([{ ecosystem: 'npm' }, { ecosystem: 'npm' }]);
    const s = await pool.query<{ lockfile_path: string | null }>('SELECT lockfile_path FROM scans WHERE id = $1', [id]);
    expect(s.rows).toEqual([{ lockfile_path: null }]);

    // Same name@version × advisory in another ecosystem is a different finding; a duplicate in npm is not.
    await pool.query(
      `INSERT INTO findings (scan_id, ecosystem, package, installed_version, scope, is_direct, advisory_id, severity)
       VALUES ($1, 'PyPI', 'lodash', '4.17.20', 'runtime', true, 'GHSA-1', 'high')`,
      [id],
    );
    await expect(pool.query(finding, [id])).rejects.toThrow(/findings_unique/);
  });
});
