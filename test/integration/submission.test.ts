import type { PgBoss } from 'pg-boss';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { PostgresScanSubmission } from '../../src/adapters/postgres/scan-submission.ts';
import { SCAN_QUEUE } from '../../src/adapters/pgboss/queue.ts';
import { ScanService } from '../../src/application/scan-service.ts';
import { createTestEnv, type TestEnv } from '../support/env.ts';

describe('scan submission (Postgres + pg-boss)', () => {
  let env: TestEnv;
  let service: ScanService;

  beforeAll(async () => {
    env = await createTestEnv();
    service = new ScanService(new PostgresScanSubmission(env.pool, env.boss), new PostgresScanRepository(env.pool));
  });

  afterAll(async () => {
    await env.close();
  });

  async function scanCount(): Promise<number> {
    const { rows } = await env.pool.query<{ n: string }>('SELECT count(*) AS n FROM scans');
    return Number(rows[0]?.n);
  }

  it('creates the scan row and a job whose id is the scan id, in one go', async () => {
    const r = await service.submit('https://github.com/Owner/Repo.git', null);
    expect(r.kind).toBe('created');
    if (r.kind !== 'created') return;

    const scan = await service.get(r.scanId);
    expect(scan).toMatchObject({
      status: 'queued',
      repo: { owner: 'owner', name: 'repo', url: 'https://github.com/owner/repo' },
    });
    const [job] = await env.boss.findJobs(SCAN_QUEUE, { id: r.scanId });
    expect(job?.data).toEqual({ scanId: r.scanId });
    expect(job?.state).toBe('created');
  });

  it('invalid URL → invalid, nothing created', async () => {
    const before = await scanCount();
    expect(await service.submit('https://gitlab.com/a/b', 'k-invalid')).toEqual({
      kind: 'invalid',
      error: expect.stringMatching(/github.com/) as string,
    });
    expect(await scanCount()).toBe(before);
  });

  it('same key + same request (even spelled differently) → the same scan, created once', async () => {
    const first = await service.submit('https://github.com/a/same', 'k-same');
    const again = await service.submit('github.com/A/same.git/', 'k-same');
    expect(first.kind).toBe('created');
    expect(again).toEqual({ kind: 'existing', scanId: first.kind === 'created' ? first.scanId : '' });
    const { rows } = await env.pool.query('SELECT 1 FROM scans WHERE repo_name = $1', ['same']);
    expect(rows).toHaveLength(1);
  });

  it('same key + different request → conflict, nothing created', async () => {
    await service.submit('https://github.com/a/one', 'k-conflict');
    const before = await scanCount();
    expect(await service.submit('https://github.com/a/two', 'k-conflict')).toEqual({ kind: 'conflict' });
    expect(await scanCount()).toBe(before);
  });

  it('concurrent requests with one key → exactly one scan and one job; everyone gets its id', async () => {
    const results = await Promise.all(
      Array.from({ length: 8 }, () => service.submit('https://github.com/a/race', 'k-race')),
    );
    const ids = new Set(results.map((r) => (r.kind === 'created' || r.kind === 'existing' ? r.scanId : r.kind)));
    expect(ids.size).toBe(1);
    expect(results.filter((r) => r.kind === 'created')).toHaveLength(1);

    const { rows } = await env.pool.query<{ id: string }>('SELECT id FROM scans WHERE repo_name = $1', ['race']);
    expect(rows).toHaveLength(1);
    const jobs = await env.boss.findJobs(SCAN_QUEUE, { data: { scanId: rows[0]?.id ?? '' } });
    expect(jobs).toHaveLength(1);
  });

  it('without a key every request is a new scan', async () => {
    const a = await service.submit('https://github.com/a/nokey', null);
    const b = await service.submit('https://github.com/a/nokey', null);
    expect(a.kind).toBe('created');
    expect(b.kind).toBe('created');
    expect(a).not.toEqual(b);
  });

  it('if enqueueing fails, the scan row is rolled back too', async () => {
    const failingBoss = {
      send: () => Promise.reject(new Error('queue unavailable')),
    } as unknown as PgBoss;
    const broken = new ScanService(new PostgresScanSubmission(env.pool, failingBoss), new PostgresScanRepository(env.pool));
    const before = await scanCount();
    await expect(broken.submit('https://github.com/a/rollback', 'k-rollback')).rejects.toThrow('queue unavailable');
    expect(await scanCount()).toBe(before);
    const key = await env.pool.query('SELECT 1 FROM idempotency_keys WHERE key = $1', ['k-rollback']);
    expect(key.rows).toHaveLength(0);
  });

  it('if send() dedupes (returns null), the scan row is rolled back', async () => {
    const dedupingBoss = { send: () => Promise.resolve(null) } as unknown as PgBoss;
    const broken = new ScanService(new PostgresScanSubmission(env.pool, dedupingBoss), new PostgresScanRepository(env.pool));
    const before = await scanCount();
    await expect(broken.submit('https://github.com/a/dedupe', null)).rejects.toThrow(/job was not created/);
    expect(await scanCount()).toBe(before);
  });
});
