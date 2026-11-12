import type { RepoRef } from '../domain/repo-url.ts';

export interface IdempotencyInput {
  key: string;
  /** Hash of the normalized request; same key with a different hash is a conflict. */
  requestHash: string;
}

export interface SubmitInput {
  scanId: string;
  repo: RepoRef;
  idempotency: IdempotencyInput | null;
  /** Omitted: a public scan. Private: bound to these ids for its whole life. */
  private?: { repositoryId: number; installationId: number; submittedBy: number };
}

export type SubmitResult =
  | { kind: 'created'; scanId: string }
  /** Same key, same request: the scan created by the first request. */
  | { kind: 'existing'; scanId: string }
  /** Same key, different request. */
  | { kind: 'conflict' }
  /** Too many scans are queued or running; nothing was created. */
  | { kind: 'busy'; outstanding: number };

/**
 * Creates the scan row and its job atomically (one transaction): a scan never exists without a job,
 * and a job never exists without its scan. The job id is the scan id.
 */
export interface ScanSubmission {
  /**
   * `maxOutstanding`: refuse (kind 'busy') when this many scans are already queued, running or retrying.
   * Replays of an existing Idempotency-Key are answered regardless: they create nothing.
   */
  submit(input: SubmitInput): Promise<SubmitResult>;
}
