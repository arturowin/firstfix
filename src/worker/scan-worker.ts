/**
 * Queue wiring for the worker, shared by src/worker/main.ts and the failure tests (so they exercise exactly
 * what runs in production): the scan handler, and (M4 step 3) the dead-letter handler.
 */
import type { PgBoss } from 'pg-boss';
import { SCAN_QUEUE, type ScanJobData } from '../adapters/pgboss/queue.ts';
import type { ScanPipeline } from '../application/scan-pipeline.ts';

export type Log = (entry: Record<string, unknown>) => void;

export interface ScanWorkerDeps {
  pipeline: ScanPipeline;
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
}
