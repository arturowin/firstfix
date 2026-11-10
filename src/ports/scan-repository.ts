import type { Advisory, Severity } from '../domain/advisory.ts';
import type { Scope } from '../domain/lockfile.ts';

export type ScanStatus = 'queued' | 'running' | 'retrying' | 'completed' | 'unsupported' | 'failed';
export type ScanStage = 'fetching' | 'scanning' | 'analyzing';

export interface ScanCounts {
  totalDeps: number;
  checkedDeps: number;
  unsupportedDeps: number;
  failedLookups: number;
}

export interface ScanView {
  id: string;
  repo: { owner: string; name: string; url: string };
  commitSha: string | null;
  status: ScanStatus;
  stage: ScanStage | null;
  counts: ScanCounts;
  coverage: 'full' | 'partial' | null;
  error: { code: string; message: string } | null;
  createdAt: Date;
  updatedAt: Date;
  completedAt: Date | null;
}

export interface FindingInput {
  package: string;
  installedVersion: string;
  scope: Scope;
  isDirect: boolean;
  directParents: string[];
  installPaths: string[][];
  advisory: Advisory;
  candidateVersion: string | null;
}

export interface FindingView {
  package: string;
  installedVersion: string;
  scope: Scope;
  isDirect: boolean;
  directParents: string[];
  advisoryId: string;
  aliases: string[];
  severity: Severity;
  isMalicious: boolean;
  title: string | null;
  candidateVersion: string | null;
  references: { type: string; url: string }[];
}

export interface UncheckedView {
  package: string;
  version: string | null;
  reason: 'unsupported_source' | 'lookup_failed';
}

export interface ReportData {
  scan: ScanView;
  findings: FindingView[];
  unchecked: UncheckedView[];
}

/** The attempt a worker holds. Every write below is fenced by it (WHERE id = $1 AND attempt = $2). */
export interface ClaimedScan {
  scanId: string;
  attempt: number;
  repo: { owner: string; name: string };
}

export interface Completion {
  counts: ScanCounts;
  coverage: 'full' | 'partial';
  findings: FindingInput[];
  unchecked: UncheckedView[];
}

export interface ScanRepository {
  get(scanId: string): Promise<ScanView | null>;
  getReport(scanId: string): Promise<ReportData | null>;

  /**
   * Starts a new attempt: increments `attempt`, sets running/fetching. Returns null if the scan is
   * missing or already terminal (duplicate delivery is a no-op).
   */
  claim(scanId: string): Promise<ClaimedScan | null>;

  /** Each returns false when the attempt is stale (0 rows): the caller stops quietly. */
  recordProgress(
    claim: ClaimedScan,
    update: { stage?: ScanStage; commitSha?: string; counts?: Partial<ScanCounts> },
  ): Promise<boolean>;
  /** Findings + completion in one transaction that first locks the owned, non-terminal row. */
  complete(claim: ClaimedScan, completion: Completion): Promise<boolean>;
  /** Terminal outcome without findings. */
  finish(
    claim: ClaimedScan,
    outcome: { status: 'failed' | 'unsupported'; code: string; message: string },
  ): Promise<boolean>;
}
