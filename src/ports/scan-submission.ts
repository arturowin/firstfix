import type { RepoRef } from '../domain/repo-url.ts';

export interface IdempotencyInput {
  key: string;
  /** Hash of the normalized request; same key with a different hash is a conflict. */
  requestHash: string;
}

export type SubmitResult =
  | { kind: 'created'; scanId: string }
  /** Same key, same request: the scan created by the first request. */
  | { kind: 'existing'; scanId: string }
  /** Same key, different request. */
  | { kind: 'conflict' };

/**
 * Creates the scan row and its job atomically (one transaction): a scan never exists without a job,
 * and a job never exists without its scan. The job id is the scan id.
 */
export interface ScanSubmission {
  submit(input: { scanId: string; repo: RepoRef; idempotency: IdempotencyInput | null }): Promise<SubmitResult>;
}
