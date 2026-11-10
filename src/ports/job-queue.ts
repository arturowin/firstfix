/**
 * What the sweeper needs to know about a scan's job (job id = scan id). The queue, not the clock, decides
 * whether a scan is lost: time only narrows which scans are worth asking about.
 */
export type ScanJobState =
  /** Waiting to run or waiting for a retry (backlog, backoff, stopped workers): leave it alone. */
  | 'pending'
  | 'active'
  /** Completed, failed or cancelled: no attempt will run again. */
  | 'finished'
  /** Gone (deleted after retention) or never existed. */
  | 'missing';

export interface JobQueue {
  scanJobState(scanId: string): Promise<ScanJobState>;
}
