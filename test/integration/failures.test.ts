/**
 * M4 failure behaviour through the real queue: Postgres + pg-boss + the production worker wiring
 * (src/worker/scan-worker.ts) + the real pipeline. Only GitHub and the advisory source are fakes, so each test
 * can make them fail, hang or recover. Queue settings are shortened (heartbeat 10 s, the pg-boss minimum; retry delay 0,
 * so backoff waits 0), so crash tests take 10-25 s each.
 */
import { randomUUID } from 'node:crypto';
import { PgBoss } from 'pg-boss';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { PgBossJobQueue } from '../../src/adapters/pgboss/job-queue.ts';
import { SCAN_DEAD_LETTER_QUEUE, SCAN_QUEUE, type ScanJobData } from '../../src/adapters/pgboss/queue.ts';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { PostgresScanSubmission } from '../../src/adapters/postgres/scan-submission.ts';
import { LOST_JOB_REASON, Sweeper } from '../../src/application/lost-scans.ts';
import { ScanPipeline } from '../../src/application/scan-pipeline.ts';
import { ScanService } from '../../src/application/scan-service.ts';
import { TransientError } from '../../src/ports/errors.ts';
import type { RepoSource } from '../../src/ports/repo-source.ts';
import type { ClaimedScan } from '../../src/ports/scan-repository.ts';
import type { LookupResult, PackageRef, VulnDatabase } from '../../src/ports/vuln-database.ts';
import { startScanWorker } from '../../src/worker/scan-worker.ts';
import { createTestEnv, type TestEnv } from '../support/env.ts';

const LOCK = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { dependencies: { a: '1.0.0' } },
    'node_modules/a': { version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz' },
  },
});

const source: RepoSource = {
  resolveDefaultCommit: () => Promise.resolve({ sha: 'a'.repeat(40), branch: 'main' }),
  readFile: (_r, _s, path) => Promise.resolve(path === 'package-lock.json' ? LOCK : null),
};

/** What the advisory source does on the next lookups; tests swap it. */
type Behaviour = (pkgs: PackageRef[], signal: AbortSignal, call: number) => Promise<LookupResult>;
const ok: Behaviour = () => Promise.resolve({ advisories: new Map(), failed: [], incomplete: [] });
const down: Behaviour = () => Promise.reject(new TransientError('osv_unavailable', 'OSV answered 503'));
/** Hangs until the attempt's signal aborts (a scan stuck mid-lookup). */
const hang: Behaviour = (_p, signal) =>
  new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => {
      reject(new Error('aborted'));
    });
  });

let behaviour: Behaviour = ok;
let calls = 0;
const vulns: VulnDatabase = {
  source: { name: 'Test advisories', url: 'https://advisories.test' },
  lookup: (pkgs, signal) => behaviour(pkgs, signal, ++calls),
};

async function waitFor<T>(probe: () => Promise<T | undefined>, timeoutMs: number, what: string): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = await probe();
    if (v !== undefined) return v;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

describe('failure behaviour through the real queue', () => {
  let env: TestEnv;
  let scans: PostgresScanRepository;
  let service: ScanService;
  let pipeline: ScanPipeline;
  const extraBosses: PgBoss[] = [];

  beforeAll(async () => {
    env = await createTestEnv({ queue: { heartbeatSeconds: 10, retryDelay: 0, retryLimit: 1 } });
    scans = new PostgresScanRepository(env.pool);
    service = new ScanService(new PostgresScanSubmission(env.pool, env.boss), scans);
    pipeline = new ScanPipeline({ scans, source, vulns });
  });

  afterEach(async () => {
    await env.boss.offWork(SCAN_QUEUE);
    await env.boss.offWork(SCAN_DEAD_LETTER_QUEUE);
    for (const b of extraBosses.splice(0)) await b.stop({ graceful: false }).catch(() => undefined);
    behaviour = ok;
    calls = 0;
  });

  afterAll(async () => {
    await env.close();
  });

  const setRetryLimit = (retryLimit: number, retryDelay = 0) => env.boss.updateQueue(SCAN_QUEUE, { retryLimit, retryDelay });
  const startWorker = (boss: PgBoss = env.boss) => startScanWorker(boss, { pipeline, scans, concurrency: 2, pollingIntervalSeconds: 0.5 });

  async function submit(): Promise<string> {
    const r = await service.submit(`https://github.com/o/r${randomUUID().slice(0, 8)}`, null);
    if (r.kind !== 'created') throw new Error(r.kind);
    return r.scanId;
  }

  const statusOf = async (id: string) => (await scans.get(id))?.status;
  const until = (id: string, status: string, timeoutMs: number) =>
    waitFor(async () => ((await statusOf(id)) === status ? true : undefined), timeoutMs, `scan ${status}`);

  /** A worker that claims a job and the scan row, then dies without a word (kill -9): no heartbeat, no fail. */
  async function crashAfterClaiming(id: string): Promise<ClaimedScan> {
    const [job] = await env.boss.fetch<ScanJobData>(SCAN_QUEUE);
    expect(job?.data.scanId).toBe(id);
    const claim = await scans.claim(id);
    if (!claim) throw new Error('claim failed');
    return claim;
  }

  it('transient error: the scan shows retrying with the reason, is retried, and recovers', async () => {
    await setRetryLimit(1, 2); // a 2 s pause before the retry, so `retrying` is observable
    behaviour = (p, s, call) => (call === 1 ? down(p, s, call) : ok(p, s, call));
    await startWorker();
    const id = await submit();

    const retrying = await waitFor(async () => {
      const s = await scans.get(id);
      return s?.status === 'retrying' ? s : undefined;
    }, 10_000, 'retrying');
    expect(retrying.error).toEqual({ code: 'osv_unavailable', message: 'OSV answered 503' });

    await until(id, 'completed', 15_000);
    expect(await scans.get(id)).toMatchObject({ status: 'completed', error: null });
  }, 30_000);

  it('retries exhausted: the last attempt ends the scan failed; the dead-letter handler then changes nothing', async () => {
    await setRetryLimit(1);
    behaviour = down;
    await startWorker();
    const id = await submit();

    await until(id, 'failed', 15_000);
    expect((await scans.get(id))?.error).toEqual({ code: 'osv_unavailable', message: 'Retries exhausted: OSV answered 503' });
    expect(calls).toBe(2);
    // pg-boss dead-letters the job; our handler runs and finds the scan already terminal.
    await waitFor(
      async () => ((await env.boss.findJobs(SCAN_DEAD_LETTER_QUEUE)).find((j) => j.sourceId === id)?.state === 'completed' ? true : undefined),
      15_000,
      'dead-letter job handled',
    );
    expect((await scans.get(id))?.error?.message).toBe('Retries exhausted: OSV answered 503');
  }, 30_000);

  it('restart: a worker stopped mid-scan; another worker picks the scan up and completes it', async () => {
    await setRetryLimit(1);
    behaviour = hang;
    const workerA = new PgBoss({ connectionString: env.db.url });
    extraBosses.push(workerA);
    workerA.on('error', () => undefined);
    await workerA.start();
    await startWorker(workerA);
    const id = await submit();
    await waitFor(async () => ((await scans.get(id))?.stage === 'scanning' ? true : undefined), 10_000, 'scan mid-lookup on worker A');

    // Stop A without waiting for the scan (deploy, scale-down): pg-boss fails its in-flight job and aborts it.
    await workerA.stop({ graceful: false });
    expect(await statusOf(id)).toBe('running'); // the aborted attempt wrote nothing
    behaviour = ok;
    await startWorker();

    await until(id, 'completed', 15_000);
    expect(await scans.get(id)).toMatchObject({ status: 'completed' });
  }, 30_000);

  it('crash (no heartbeat) mid-scan: retried after the heartbeat lapses and completed; the dead worker’s writes change nothing', async () => {
    await setRetryLimit(1);
    const id = await submit();
    const zombie = await crashAfterClaiming(id);
    await startWorker();

    await until(id, 'completed', 30_000);
    // The crashed attempt "wakes up" late: every write is fenced by the newer attempt.
    expect(await scans.recordProgress(zombie, { stage: 'analyzing' })).toBe(false);
    expect(await scans.markRetrying(zombie, { code: 'x', message: 'x' })).toBe(false);
    expect(await scans.finish(zombie, { status: 'failed', code: 'x', message: 'x' })).toBe(false);
    expect(
      await scans.complete(zombie, {
        advisorySource: 'x',
        summaryLine: 'x',
        explanation: null,
        counts: { totalDeps: 0, checkedDeps: 0, unsupportedDeps: 0, failedLookups: 0 },
        coverage: 'full',
        findings: [],
        unchecked: [],
      }),
    ).toBe(false);
    expect(await scans.get(id)).toMatchObject({ status: 'completed', error: null });
  }, 45_000);

  it('crash on the last attempt: the job is dead-lettered and the scan ends failed, not stuck', async () => {
    await setRetryLimit(0);
    const id = await submit();
    await crashAfterClaiming(id);
    await startWorker(); // its dead-letter handler is what closes the scan

    await until(id, 'failed', 30_000);
    expect((await scans.get(id))?.error?.code).toBe('retries_exhausted');
  }, 45_000);

  describe('sweeper (no workers running: a backlog that must survive)', () => {
    it('fails only scans whose job is finished or missing; queued, retrying and active jobs are left alone', async () => {
      await setRetryLimit(2);
      // Created in this order; fetch() takes the oldest available job first.
      const failedJob = await submit();
      const activeJob = await submit();
      const retryJob = await submit();
      const queued = await submit();

      const [f] = await env.boss.fetch<ScanJobData>(SCAN_QUEUE);
      await env.boss.cancel(SCAN_QUEUE, f?.id ?? ''); // finished: no attempt will run again
      expect(f?.data.scanId).toBe(failedJob);
      const [a] = await env.boss.fetch<ScanJobData>(SCAN_QUEUE); // stays active (a live worker, mid-scan)
      expect(a?.data.scanId).toBe(activeJob);
      const [r] = await env.boss.fetch<ScanJobData>(SCAN_QUEUE);
      await env.boss.fail(SCAN_QUEUE, r?.id ?? ''); // retryLimit 2 at send → state "retry" (waiting for backoff)
      expect(r?.data.scanId).toBe(retryJob);

      // A scan whose job no longer exists (deleted after retention).
      const missing = randomUUID();
      await env.pool.query(
        `INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized) VALUES ($1, 'o', 'gone', 'https://github.com/o/gone')`,
        [missing],
      );
      const zombie = await scans.claim(missing); // a worker that once claimed it and is somewhere, frozen

      const jobs = new PgBossJobQueue(env.boss);
      expect(await jobs.scanJobState(failedJob)).toBe('finished');
      expect(await jobs.scanJobState(activeJob)).toBe('active');
      expect(await jobs.scanJobState(retryJob)).toBe('pending');
      expect(await jobs.scanJobState(queued)).toBe('pending');
      expect(await jobs.scanJobState(missing)).toBe('missing');

      // Nothing is stale yet with a realistic threshold.
      expect(await new Sweeper({ scans, jobs, staleAfterSeconds: 600 }).sweepOnce()).toEqual({ checked: 0, failed: [] });

      // Everything counts as stale with threshold 0: only the queue decides.
      const result = await new Sweeper({ scans, jobs, staleAfterSeconds: 0 }).sweepOnce();
      expect(result.failed.sort()).toEqual([failedJob, missing].sort());
      for (const id of [activeJob, retryJob, queued]) expect(await statusOf(id)).not.toBe('failed');
      expect((await scans.get(missing))?.error).toEqual(LOST_JOB_REASON);

      // The frozen worker wakes up: its writes match nothing (failIfOpen bumped the attempt).
      if (!zombie) throw new Error('claim failed');
      expect(await scans.recordProgress(zombie, { stage: 'scanning' })).toBe(false);
      expect(await statusOf(missing)).toBe('failed');

      // A second sweep is a no-op.
      expect((await new Sweeper({ scans, jobs, staleAfterSeconds: 0 }).sweepOnce()).failed).toEqual([]);
    }, 30_000);

    it('a backlog of healthy stale scans can’t hide a lost one: sweeps resume where they stopped', async () => {
      // Review reproduction, scaled down: older pending jobs first, then a scan whose job is missing.
      const backlog: string[] = [];
      for (let i = 0; i < 7; i++) backlog.push(await submit());
      const lost = randomUUID();
      await env.pool.query(
        `INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized) VALUES ($1, 'o', 'lost', 'https://github.com/o/lost')`,
        [lost],
      );
      const sweeper = new Sweeper({ scans, jobs: new PgBossJobQueue(env.boss), staleAfterSeconds: 0, pageSize: 2, maxChecksPerSweep: 3 });

      const sweeps: { checked: number; failed: string[] }[] = [];
      while ((await statusOf(lost)) !== 'failed') {
        if (sweeps.length === 10) throw new Error(`lost scan never checked: ${JSON.stringify(sweeps)}`);
        sweeps.push(await sweeper.sweepOnce());
      }
      // Other open scans in this database (earlier tests) also count as stale; what matters is that each sweep
      // checks at most 3 and they move forward instead of repeating the first page.
      expect(sweeps.every((r) => r.checked <= 3)).toBe(true);
      expect(sweeps.flatMap((r) => r.failed)).toContain(lost);
      for (const id of backlog) expect(await statusOf(id)).toBe('queued');
    }, 30_000);
  });
});
