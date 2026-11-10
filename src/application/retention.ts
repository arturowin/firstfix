/**
 * Retention: finished scans don't accumulate forever, and idempotency keys expire sooner (a key only needs to
 * outlive client retries). Runs in the worker on a timer, in batches, until nothing is left to delete.
 * Unfinished scans are never touched; a deleted scan's shareable link answers "not found".
 */
import type { ScanRepository } from '../ports/scan-repository.ts';

export interface RetentionPolicy {
  scanDays: number;
  keyHours: number;
  batchSize?: number;
  /** Stop after this many batches per run, so one run can't hold the database for long. */
  maxBatches?: number;
}

export async function purgeExpired(scans: ScanRepository, policy: RetentionPolicy): Promise<{ scans: number; keys: number }> {
  const batchSize = policy.batchSize ?? 500;
  const total = { scans: 0, keys: 0 };
  for (let i = 0; i < (policy.maxBatches ?? 20); i++) {
    const r = await scans.deleteExpired({ scanDays: policy.scanDays, keyHours: policy.keyHours, batchSize });
    total.scans += r.scans;
    total.keys += r.keys;
    if (r.scans < batchSize && r.keys < batchSize) break;
  }
  return total;
}
