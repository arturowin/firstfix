/**
 * Contract checks for the INSTALLED pg-boss version (CLAUDE.md "Verify, don't assume").
 * These pin the behaviours ARCHITECTURE.md relies on; if an upgrade changes one, this file fails.
 */
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { PgBoss, type Db, type JobWithMetadata } from 'pg-boss';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../support/db.ts';

/** pg-boss runs its statements through our client, inside our open transaction. */
function txDb(client: pg.PoolClient): Db {
  return {
    executeSql: async (text, values) => {
      const res = await client.query(text, values);
      return { rows: res.rows };
    },
  };
}

async function waitFor<T>(fn: () => Promise<T | undefined>, timeoutMs: number, label: string): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await fn();
    if (value !== undefined) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for: ${label}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

async function findJob(boss: PgBoss, queue: string, id: string): Promise<JobWithMetadata<unknown> | undefined> {
  const [job] = await boss.findJobs<unknown>(queue, { id });
  return job;
}

describe('pg-boss contract', () => {
  let db: TestDatabase;
  let pool: pg.Pool;
  let boss: PgBoss;

  beforeAll(async () => {
    db = await createTestDatabase();
    pool = new pg.Pool({ connectionString: db.url });
    boss = new PgBoss({
      connectionString: db.url,
      // Fast supervision so expiry/heartbeat failures are detected within the test.
      superviseIntervalSeconds: 1,
      monitorIntervalSeconds: 1,
    });
    boss.on('error', (err: unknown) => {
      console.error('pg-boss error', err);
    });
    await boss.start();
  });

  afterAll(async () => {
    await boss.stop({ graceful: false });
    await pool.end();
    await db.drop();
  });

  it('send() joins our transaction: rollback leaves no job, commit keeps it', async () => {
    await boss.createQueue('tx-send');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const rolledBack = await boss.send('tx-send', { n: 1 }, { db: txDb(client) });
      expect(rolledBack).toEqual(expect.any(String));
      await client.query('ROLLBACK');
      expect(await findJob(boss, 'tx-send', rolledBack ?? '')).toBeUndefined();

      await client.query('BEGIN');
      const committed = await boss.send('tx-send', { n: 2 }, { db: txDb(client) });
      await client.query('COMMIT');
      const job = await findJob(boss, 'tx-send', committed ?? '');
      expect(job?.state).toBe('created');
      expect(job?.data).toEqual({ n: 2 });
    } finally {
      client.release();
    }
  });

  it('send() accepts a caller-chosen id; a duplicate id returns null instead of a second job', async () => {
    await boss.createQueue('custom-id');
    const id = randomUUID();
    expect(await boss.send('custom-id', {}, { id })).toBe(id);
    expect(await boss.send('custom-id', {}, { id })).toBeNull();
    expect(await boss.findJobs('custom-id', { id })).toHaveLength(1);
  });

  it('retries a throwing handler retryLimit times with metadata visible, then fails and dead-letters', async () => {
    await boss.createQueue('dlq-a');
    await boss.createQueue('retry-a', { retryLimit: 2, retryDelay: 0, deadLetter: 'dlq-a' });

    const seen: { retryCount: number; retryLimit: number }[] = [];
    await boss.work('retry-a', { includeMetadata: true, pollingIntervalSeconds: 0.5 }, async ([job]) => {
      if (job) seen.push({ retryCount: job.retryCount, retryLimit: job.retryLimit });
      await Promise.resolve();
      throw new Error('transient');
    });

    const id = await boss.send('retry-a', { scanId: 's1' });
    const dead = await waitFor(
      async () => (await boss.findJobs('dlq-a')).find((j) => j.sourceId === id),
      20_000,
      'dead-lettered copy',
    );
    await boss.offWork('retry-a');

    expect(seen).toEqual([
      { retryCount: 0, retryLimit: 2 },
      { retryCount: 1, retryLimit: 2 },
      { retryCount: 2, retryLimit: 2 },
    ]);
    expect((await findJob(boss, 'retry-a', id ?? ''))?.state).toBe('failed');
    expect(dead.data).toEqual({ scanId: 's1' });
    expect(dead.sourceRetryCount).toBe(2);
  });

  it('crash on the last attempt (job left active, never settled): expiry fails it and dead-letters it', async () => {
    await boss.createQueue('dlq-b');
    await boss.createQueue('crash-b', { retryLimit: 1, retryDelay: 0, expireInSeconds: 1, deadLetter: 'dlq-b' });
    const id = await boss.send('crash-b', { scanId: 's2' });

    // A "worker" claims the job and dies: fetch() without complete/fail.
    const [first] = await boss.fetch('crash-b');
    expect(first?.retryCount).toBe(0);

    const second = await waitFor(
      async () => (await boss.fetch('crash-b'))[0],
      15_000,
      'expired job to be claimable again',
    );
    expect(second.id).toBe(id);
    expect(second.retryCount).toBe(1); // final attempt; it also dies

    const dead = await waitFor(
      async () => (await boss.findJobs('dlq-b')).find((j) => j.sourceId === id),
      15_000,
      'dead-lettered copy after final expiry',
    );
    expect((await findJob(boss, 'crash-b', id ?? ''))?.state).toBe('failed');
    expect(dead.data).toEqual({ scanId: 's2' });
  });

  it('heartbeat: a claimed job whose worker stops heartbeating is retried long before expiry', async () => {
    await boss.createQueue('hb-f', { retryLimit: 1, retryDelay: 0, heartbeatSeconds: 10, expireInSeconds: 900 });
    const id = await boss.send('hb-f', {});
    const started = Date.now();
    const [first] = await boss.fetch('hb-f'); // claimed, then the "worker" dies: no touch()
    expect(first?.id).toBe(id);

    const again = await waitFor(async () => (await boss.fetch('hb-f'))[0], 40_000, 'heartbeat-expired job');
    expect(again.retryCount).toBe(1);
    expect(Date.now() - started).toBeLessThan(40_000); // vs 900 s expiry
  }, 60_000);

  it('heartbeat: work() keeps a live handler alive past heartbeatSeconds (no duplicate run, signal intact)', async () => {
    await boss.createQueue('hb-live', { retryLimit: 1, retryDelay: 0, heartbeatSeconds: 10, expireInSeconds: 120 });
    const runs: { retryCount: number; abortedAtEnd: boolean }[] = [];
    await boss.work('hb-live', { pollingIntervalSeconds: 0.5 }, async ([job]) => {
      // 2.5x heartbeatSeconds: without refreshes the monitor would fail the job and retry it.
      await new Promise((r) => setTimeout(r, 25_000));
      runs.push({ retryCount: job?.retryCount ?? -1, abortedAtEnd: job?.signal.aborted ?? true });
    });
    const id = (await boss.send('hb-live', {})) ?? '';
    await waitFor(
      async () => ((await findJob(boss, 'hb-live', id))?.state === 'completed' ? true : undefined),
      45_000,
      'long job to complete',
    );
    await boss.offWork('hb-live');
    expect(runs).toEqual([{ retryCount: 0, abortedAtEnd: false }]);
  }, 60_000);

  it('missed heartbeat on the last attempt (worker crash): job fails and is dead-lettered', async () => {
    await boss.createQueue('dlq-hb');
    await boss.createQueue('hb-last', { retryLimit: 0, heartbeatSeconds: 10, expireInSeconds: 900, deadLetter: 'dlq-hb' });
    const id = await boss.send('hb-last', { scanId: 's3' });
    const [claimed] = await boss.fetch('hb-last'); // only attempt; the "worker" dies, no touch()
    expect(claimed?.id).toBe(id);

    const dead = await waitFor(
      async () => (await boss.findJobs('dlq-hb')).find((j) => j.sourceId === id),
      40_000,
      'dead-lettered copy after missed heartbeat',
    );
    expect((await findJob(boss, 'hb-last', id ?? ''))?.state).toBe('failed');
    expect(dead.data).toEqual({ scanId: 's3' });
  }, 60_000);

  it('backoff: retry delays grow from retryDelay and are capped by retryDelayMax', async () => {
    // pg-boss: delay = min(retryDelayMax, retryDelay * (2^n/2 + 2^n/2 * random)).
    // With retryDelay 1 the 4th retry would wait >= 4 s uncapped; retryDelayMax 2 caps it.
    await boss.createQueue('backoff-g', { retryLimit: 4, retryDelay: 1, retryBackoff: true, retryDelayMax: 2 });
    const startedAt: number[] = [];
    await boss.work('backoff-g', { pollingIntervalSeconds: 0.5 }, async () => {
      startedAt.push(Date.now());
      await Promise.resolve();
      throw new Error('transient');
    });
    const id = (await boss.send('backoff-g', {})) ?? '';
    await waitFor(
      async () => ((await findJob(boss, 'backoff-g', id))?.state === 'failed' ? true : undefined),
      40_000,
      'all retries to run',
    );
    await boss.offWork('backoff-g');

    expect(startedAt).toHaveLength(5);
    const gaps = startedAt.slice(1).map((t, i) => (t - (startedAt[i] ?? t)) / 1000);
    for (const g of gaps) expect(g).toBeGreaterThanOrEqual(0.9); // never retried immediately
    expect(gaps.at(-1)).toBeLessThan(3.5); // capped at 2 s (+ polling), not >= 4 s
  }, 60_000);

  it('settling with a stale attempt is fenced: fail() for retryCount 0 does nothing once retried', async () => {
    await boss.createQueue('fence-fail', { retryLimit: 1, retryDelay: 0, expireInSeconds: 1 });
    const id = await boss.send('fence-fail', {});
    const [first] = await boss.fetch('fence-fail');
    const second = await waitFor(async () => (await boss.fetch('fence-fail'))[0], 15_000, 'retried claim');
    expect(second.retryCount).toBe(1);

    await boss.fail('fence-fail', { id: first?.id ?? '', retryCount: 0 });
    const job = await findJob(boss, 'fence-fail', id ?? '');
    expect(job?.state).toBe('active');
    expect(job?.retryCount).toBe(1);
  });

  it('settling with a stale attempt is fenced: complete() for retryCount 0 does nothing once retried', async () => {
    await boss.createQueue('fence-c', { retryLimit: 1, retryDelay: 0, expireInSeconds: 1 });
    const id = await boss.send('fence-c', {});
    const [first] = await boss.fetch('fence-c');
    const second = await waitFor(async () => (await boss.fetch('fence-c'))[0], 15_000, 'retried claim');
    expect(second.retryCount).toBe(1);

    // CommandResponse is untyped in 12.x, so assert on the job instead: still active, not completed.
    await boss.complete('fence-c', { id: first?.id ?? '', retryCount: 0 });
    expect((await findJob(boss, 'fence-c', id ?? ''))?.state).toBe('active');
  });

  it('aborts job.signal when the job expires while the handler is still running', async () => {
    await boss.createQueue('signal-d', { retryLimit: 0, expireInSeconds: 1 });
    let aborted = false;
    await boss.work('signal-d', { pollingIntervalSeconds: 0.5 }, async ([job]) => {
      await new Promise((r) => setTimeout(r, 4000));
      aborted = job?.signal.aborted ?? false;
    });
    const id = await boss.send('signal-d', {});
    await waitFor(
      async () => ((await findJob(boss, 'signal-d', id ?? ''))?.state === 'failed' ? true : undefined),
      15_000,
      'expired job to fail',
    );
    await new Promise((r) => setTimeout(r, 4500));
    await boss.offWork('signal-d');
    expect(aborted).toBe(true);
  });

  it('findJobs by id reports every state, and nothing once the job is deleted', async () => {
    await boss.createQueue('states-e', { retryLimit: 0 });
    const id = (await boss.send('states-e', {})) ?? '';
    expect((await findJob(boss, 'states-e', id))?.state).toBe('created');

    const [job] = await boss.fetch('states-e');
    expect(job?.id).toBe(id);
    expect((await findJob(boss, 'states-e', id))?.state).toBe('active');

    await boss.complete('states-e', id);
    const done = await findJob(boss, 'states-e', id);
    expect(done?.state).toBe('completed');
    expect(done?.deleteAfterSeconds).toBe(7 * 24 * 3600); // completed jobs kept 7 days by default

    const cancelledId = (await boss.send('states-e', {})) ?? '';
    await boss.cancel('states-e', cancelledId);
    expect((await findJob(boss, 'states-e', cancelledId))?.state).toBe('cancelled');

    await boss.deleteJob('states-e', id);
    expect(await findJob(boss, 'states-e', id)).toBeUndefined();
  });
});
