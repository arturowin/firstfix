/**
 * Closing scans whose attempts are gone (docs/ARCHITECTURE.md "Retries exhausted / stuck scans"). No code of
 * ours runs when pg-boss gives up on a job, so two things catch it:
 * - the dead-letter handler: pg-boss copies a job to the dead-letter queue when retries are exhausted, including
 *   when the last attempt crashed or expired;
 * - the sweeper, defence in depth: scans that haven't changed for longer than any attempt can take, whose job is
 *   finished or missing. A job still pending or active is left alone, so backlog, backoff and stopped workers
 *   never fail a healthy scan.
 * Both use failIfOpen, which bumps `attempt`: a zombie worker's later writes match nothing.
 */
import type { JobQueue } from '../ports/job-queue.ts';
import type { ScanRepository, StaleCursor } from '../ports/scan-repository.ts';

export const DEAD_LETTER_REASON = {
  code: 'retries_exhausted',
  message: 'The scan stopped after its last attempt failed or timed out. Try scanning again.',
};

export const LOST_JOB_REASON = {
  code: 'job_lost',
  message: 'The scan stopped unexpectedly and its job is no longer running. Try scanning again.',
};

/** Dead-letter handler. A no-op when the last attempt already recorded the outcome. */
export function failDeadLettered(scans: ScanRepository, scanId: string): Promise<boolean> {
  return scans.failIfOpen(scanId, DEAD_LETTER_REASON);
}

export interface SweepResult {
  checked: number;
  failed: string[];
}

/**
 * Each sweep checks at most `maxChecksPerSweep` scans, in pages of `pageSize`, resuming where the previous sweep
 * stopped and starting over once it reaches the end. So stale scans whose jobs are healthy (a queued backlog)
 * can't hide a lost one behind them: every stale scan is checked within a few sweeps. The cursor lives in
 * memory; each worker keeps its own, which only means some scans are checked more often.
 */
export class Sweeper {
  private readonly scans: ScanRepository;
  private readonly jobs: JobQueue;
  private readonly staleAfterSeconds: number;
  private readonly pageSize: number;
  private readonly maxChecksPerSweep: number;
  private cursor: StaleCursor | null = null;

  constructor(deps: {
    scans: ScanRepository;
    jobs: JobQueue;
    staleAfterSeconds: number;
    pageSize?: number;
    maxChecksPerSweep?: number;
  }) {
    this.scans = deps.scans;
    this.jobs = deps.jobs;
    this.staleAfterSeconds = deps.staleAfterSeconds;
    this.pageSize = deps.pageSize ?? 100;
    this.maxChecksPerSweep = deps.maxChecksPerSweep ?? 500;
  }

  async sweepOnce(): Promise<SweepResult> {
    const failed: string[] = [];
    let checked = 0;
    while (checked < this.maxChecksPerSweep) {
      const page = await this.scans.findStale(
        this.staleAfterSeconds,
        Math.min(this.pageSize, this.maxChecksPerSweep - checked),
        this.cursor,
      );
      if (page.length === 0) {
        this.cursor = null; // reached the end: the next sweep starts from the oldest again
        break;
      }
      for (const scan of page) {
        checked++;
        this.cursor = scan;
        const state = await this.jobs.scanJobState(scan.id);
        if (state !== 'finished' && state !== 'missing') continue;
        if (await this.scans.failIfOpen(scan.id, LOST_JOB_REASON)) failed.push(scan.id);
      }
    }
    return { checked, failed };
  }
}
