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
import type { ScanRepository } from '../ports/scan-repository.ts';

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

export class Sweeper {
  private readonly scans: ScanRepository;
  private readonly jobs: JobQueue;
  private readonly staleAfterSeconds: number;
  private readonly batchSize: number;

  constructor(deps: { scans: ScanRepository; jobs: JobQueue; staleAfterSeconds: number; batchSize?: number }) {
    this.scans = deps.scans;
    this.jobs = deps.jobs;
    this.staleAfterSeconds = deps.staleAfterSeconds;
    this.batchSize = deps.batchSize ?? 100;
  }

  async sweepOnce(): Promise<SweepResult> {
    const ids = await this.scans.findStale(this.staleAfterSeconds, this.batchSize);
    const failed: string[] = [];
    for (const id of ids) {
      const state = await this.jobs.scanJobState(id);
      if (state !== 'finished' && state !== 'missing') continue;
      if (await this.scans.failIfOpen(id, LOST_JOB_REASON)) failed.push(id);
    }
    return { checked: ids.length, failed };
  }
}
