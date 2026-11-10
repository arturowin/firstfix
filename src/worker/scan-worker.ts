/**
 * Queue wiring for the worker, shared by src/worker/main.ts and the failure tests (so they exercise exactly
 * what runs in production): the scan handler, the dead-letter handler, and the sweeper timer.
 */
import type { PgBoss } from 'pg-boss';
import { SCAN_DEAD_LETTER_QUEUE, SCAN_QUEUE, type ScanJobData } from '../adapters/pgboss/queue.ts';
import { failDeadLettered, type Sweeper } from '../application/lost-scans.ts';
import type { ScanPipeline } from '../application/scan-pipeline.ts';
import type { ScanRepository } from '../ports/scan-repository.ts';

export type Log = (entry: Record<string, unknown>) => void;

export interface ScanWorkerDeps {
  pipeline: ScanPipeline;
  scans: ScanRepository;
  concurrency: number;
  pollingIntervalSeconds?: number;
  log?: Log;
}

export async function startScanWorker(boss: PgBoss, deps: ScanWorkerDeps): Promise<void> {
  const log = deps.log ?? (() => undefined);
  // includeMetadata: the handler sees retryCount/retryLimit to know the last attempt.
  const options = {
    localConcurrency: deps.concurrency,
    pollingIntervalSeconds: deps.pollingIntervalSeconds ?? 1,
    includeMetadata: true,
  } as const;
  await boss.work<ScanJobData, undefined, typeof options>(
    SCAN_QUEUE,
    options,
    async ([job]) => {
      if (!job) return;
      const started = Date.now();
      // retryCount counts from 0; the attempt with retryCount === retryLimit is the last (verified in M0).
      const lastAttempt = job.retryCount >= job.retryLimit;
      try {
        const result = await deps.pipeline.run(job.data.scanId, job.signal, { lastAttempt });
        log({ msg: 'scan finished', scanId: job.data.scanId, attempt: job.retryCount, result, ms: Date.now() - started });
      } catch (err) {
        log({
          msg: lastAttempt ? 'scan attempt failed, no retries left' : 'scan attempt failed, will be retried',
          scanId: job.data.scanId,
          attempt: job.retryCount,
          error: err instanceof Error ? `${err.name}: ${err.message}` : String(err),
        });
        throw err; // pg-boss retries (or, on the last attempt, fails and dead-letters the job)
      }
    },
  );

  // Retries exhausted (including a last attempt that crashed or expired): close the scan if still open.
  await boss.work<ScanJobData>(SCAN_DEAD_LETTER_QUEUE, { pollingIntervalSeconds: deps.pollingIntervalSeconds ?? 1 }, async ([job]) => {
    if (!job) return;
    const closed = await failDeadLettered(deps.scans, job.data.scanId);
    log({ msg: 'dead-lettered scan', scanId: job.data.scanId, closed });
  });
}

/** Runs the sweeper every `intervalMs`; returns a stop function. One sweep at a time; errors are logged. */
export function startSweeper(sweeper: Sweeper, intervalMs: number, log: Log = () => undefined): () => void {
  let running = false;
  const timer = setInterval(() => {
    if (running) return;
    running = true;
    sweeper
      .sweepOnce()
      .then((r) => {
        if (r.failed.length > 0) log({ msg: 'sweeper failed lost scans', scanIds: r.failed, checked: r.checked });
      })
      .catch((err: unknown) => {
        log({ msg: 'sweeper error', error: err instanceof Error ? err.message : String(err) });
      })
      .finally(() => {
        running = false;
      });
  }, intervalMs);
  timer.unref();
  return () => {
    clearInterval(timer);
  };
}
