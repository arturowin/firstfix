import type { Advisory, AffectedRange, Severity } from '../domain/advisory.ts';
import type { FixStatus } from '../domain/candidate.ts';
import type { StoredExplanation } from '../domain/explanation.ts';
import type { EcosystemId } from '../domain/ecosystems/types.ts';
import type { Scope } from '../domain/lockfile.ts';
import type { SourceCheckStatus, SourceCounts, SourceSeverity } from '../domain/source-rules.ts';
import type { RepoAccess } from './repo-source.ts';

export type ScanStatus = 'queued' | 'running' | 'retrying' | 'completed' | 'unsupported' | 'failed';
export type ScanStage = 'fetching' | 'scanning' | 'analyzing' | 'source';

/** The dependency check's own outcome. Null on scans from before source checks (read from the scan status). */
export type DependencyCheck = { status: 'complete' } | { status: 'unsupported' | 'failed'; error: { code: string; message: string } };

/** The source check's outcome. Null on scans from before source checks: "not run". */
export interface SourceCheck {
  status: SourceCheckStatus;
  counts: SourceCounts;
  error: { code: string; message: string } | null;
}

export interface SourceFinding {
  ruleId: string;
  ruleVersion: number;
  severity: SourceSeverity;
  path: string;
  start: { line: number; column: number };
  end: { line: number; column: number };
  excerpt: string;
}

export interface ScanCounts {
  totalDeps: number;
  checkedDeps: number;
  unsupportedDeps: number;
  failedLookups: number;
}

/** Private scans are bound to a GitHub repository id and installation id, fixed at submit. */
export type ScanVisibility =
  | { kind: 'public' }
  | { kind: 'private'; repositoryId: number; installationId: number };

export interface ScanView {
  id: string;
  repo: { owner: string; name: string; url: string };
  visibility: ScanVisibility;
  commitSha: string | null;
  /** Which lockfile was scanned, relative to the repository root. */
  lockfilePath: string | null;
  /** Name of the advisory data source used, e.g. "OSV.dev". */
  advisorySource: string | null;
  /** Deterministic one-line summary, written at completion. */
  summaryLine: string | null;
  /** Prose written at completion (AI or template); null for scans completed without one. */
  explanation: StoredExplanation | null;
  status: ScanStatus;
  stage: ScanStage | null;
  counts: ScanCounts;
  coverage: 'full' | 'partial' | null;
  error: { code: string; message: string } | null;
  /** Each check's own outcome (null on older scans; see the types). */
  checks: { dependency: DependencyCheck | null; source: SourceCheck | null };
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
  contextTruncated: boolean;
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
  contextTruncated: boolean;
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
  reason: 'unsupported_source' | 'lookup_failed' | 'invalid_name';
}

export interface ReportData {
  scan: ScanView;
  findings: FindingView[];
  unchecked: UncheckedView[];
  sourceFindings: SourceFinding[];
}

export interface StaleCursor {
  updatedAt: Date;
  id: string;
}
export type StaleScan = StaleCursor;

/** The attempt a worker holds. Every write below is fenced by it (WHERE id = $1 AND attempt = $2). */
export interface ClaimedScan {
  scanId: string;
  attempt: number;
  repo: { owner: string; name: string };
  /** From the scan's visibility: public scans never get credentials that can read private content. */
  access: RepoAccess;
}

/**
 * Both checks' results, written together. When the dependency check didn't complete (no lockfile, or it failed on
 * the last attempt), its fields are empty and `coverage` is null; the scan completes on its source check.
 */
export interface Completion {
  advisorySource: string | null;
  summaryLine: string | null;
  explanation: StoredExplanation | null;
  counts: ScanCounts;
  coverage: 'full' | 'partial' | null;
  findings: FindingInput[];
  unchecked: UncheckedView[];
  dependency: DependencyCheck;
  source: SourceCheck;
  sourceFindings: SourceFinding[];
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
  /**
   * A transient error on a non-final attempt: `retrying` + reason, so the UI can say what is being retried.
   * Only from `running` and only for the owning attempt; the next claim sets `running` again.
   */
  markRetrying(claim: ClaimedScan, reason: { code: string; message: string }): Promise<boolean>;
  /**
   * For scans whose attempts are gone (dead-lettered job, sweeper): `failed` + reason if still non-terminal,
   * regardless of attempt, and bumps `attempt` so a zombie worker's later writes match nothing.
   */
  failIfOpen(scanId: string, reason: { code: string; message: string }): Promise<boolean>;
  /**
   * Non-terminal scans not updated for `olderThanSeconds`, oldest first, strictly after `after` (keyset
   * pagination, so a sweep can move past stale scans that are healthy, e.g. a queued backlog).
   */
  findStale(olderThanSeconds: number, limit: number, after?: StaleCursor | null): Promise<StaleScan[]>;
  /**
   * Retention: deletes up to `batchSize` finished scans completed more than `scanDays` ago (their findings,
   * unchecked deps and keys cascade) and up to `batchSize` idempotency keys older than `keyHours`.
   * Scans that aren't finished are never deleted. Returns how many rows of each went.
   */
  deleteExpired(limits: { scanDays: number; keyHours: number; batchSize: number }): Promise<{ scans: number; keys: number }>;
  /** Terminal outcome without findings; `checks` records each check's outcome when both ran. */
  finish(
    claim: ClaimedScan,
    outcome: { status: 'failed' | 'unsupported'; code: string; message: string },
    checks?: { dependency: DependencyCheck; source: SourceCheck },
  ): Promise<boolean>;
}
