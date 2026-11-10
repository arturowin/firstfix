import type { Advisory, AffectedRange, Severity } from '../domain/advisory.ts';
import type { FixStatus } from '../domain/candidate.ts';
import type { EcosystemId } from '../domain/ecosystems/types.ts';
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
  /** Which lockfile was scanned, relative to the repository root. */
  lockfilePath: string | null;
  /** Name of the advisory data source used, e.g. "OSV.dev". */
  advisorySource: string | null;
  /** Deterministic one-line summary, written at completion. */
  summaryLine: string | null;
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
  ecosystem: EcosystemId;
  package: string;
  installedAs: string[];
  directAs: string[];
  installedVersion: string;
  scope: Scope;
  isDirect: boolean;
  directParents: string[];
  installPaths: string[][];
  advisory: Advisory;
  candidateVersion: string | null;
  fixStatus: FixStatus;
}

export interface FindingView {
  ecosystem: EcosystemId;
  package: string;
  installedAs: string[];
  directAs: string[];
  installedVersion: string;
  scope: Scope;
  isDirect: boolean;
  directParents: string[];
  installPaths: string[][];
  advisoryId: string;
  aliases: string[];
  severity: Severity;
  isMalicious: boolean;
  title: string | null;
  candidateVersion: string | null;
  fixStatus: FixStatus;
  /** Null for rows stored before ranges were provider-neutral (see migration 003). */
  affectedRanges: AffectedRange[] | null;
  references: { type: string; url: string }[];
}

export interface UncheckedView {
  ecosystem: EcosystemId;
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
  advisorySource: string;
  summaryLine: string;
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
    update: { stage?: ScanStage; commitSha?: string; lockfilePath?: string; counts?: Partial<ScanCounts> },
  ): Promise<boolean>;
  /** Findings + completion in one transaction that first locks the owned, non-terminal row. */
  complete(claim: ClaimedScan, completion: Completion): Promise<boolean>;
  /** Terminal outcome without findings. */
  finish(
    claim: ClaimedScan,
    outcome: { status: 'failed' | 'unsupported'; code: string; message: string },
  ): Promise<boolean>;
}
