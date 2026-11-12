import type pg from 'pg';
import type {
  ClaimedScan,
  Completion,
  FindingView,
  ReportData,
  ScanCounts,
  ScanRepository,
  ScanStage,
  ScanStatus,
  ScanView,
  ScanVisibility,
  DependencyCheck,
  SourceCheck,
  SourceFinding,
  StaleCursor,
  StaleScan,
  UncheckedView,
} from '../../ports/scan-repository.ts';
import type { AffectedRange, Severity } from '../../domain/advisory.ts';
import type { FixStatus } from '../../domain/candidate.ts';
import type { StoredExplanation } from '../../domain/explanation.ts';
import type { Scope } from '../../domain/lockfile.ts';
import { NO_SOURCE_COUNTS, type SourceCheckStatus, type SourceCounts, type SourceSeverity } from '../../domain/source-rules.ts';
import { isStorableText, storableText } from '../../domain/text.ts';
import { inTransactionOrRollback, Rollback } from './pool.ts';

const TERMINAL = `('completed', 'unsupported', 'failed')`;

interface ScanRow {
  id: string;
  repo_owner: string;
  repo_name: string;
  repo_url_normalized: string;
  visibility: 'public' | 'private';
  github_repo_id: string | null;
  installation_id: string | null;
  commit_sha: string | null;
  lockfile_path: string | null;
  advisory_source: string | null;
  summary_line: string | null;
  explanation: StoredExplanation | null;
  status: ScanStatus;
  stage: ScanStage | null;
  total_deps: number;
  checked_deps: number;
  unsupported_deps: number;
  failed_lookups: number;
  coverage: 'full' | 'partial' | null;
  error_code: string | null;
  error_message: string | null;
  dependency_status: 'complete' | 'unsupported' | 'failed' | null;
  dependency_error_code: string | null;
  dependency_error_message: string | null;
  source_status: SourceCheckStatus | null;
  source_counts: Partial<SourceCounts> | null;
  source_error_code: string | null;
  source_error_message: string | null;
  created_at: Date;
  updated_at: Date;
  completed_at: Date | null;
}

/** bigint ids arrive as strings; GitHub ids are well inside Number's safe range. */
function visibilityOf(r: Pick<ScanRow, 'visibility' | 'github_repo_id' | 'installation_id'>): ScanVisibility {
  if (r.visibility === 'public') return { kind: 'public' };
  if (r.github_repo_id === null || r.installation_id === null) throw new Error('private scan without its repository binding');
  return { kind: 'private', repositoryId: Number(r.github_repo_id), installationId: Number(r.installation_id) };
}

function toView(r: ScanRow): ScanView {
  return {
    id: r.id,
    repo: { owner: r.repo_owner, name: r.repo_name, url: r.repo_url_normalized },
    visibility: visibilityOf(r),
    commitSha: r.commit_sha,
    lockfilePath: r.lockfile_path,
    advisorySource: r.advisory_source,
    summaryLine: r.summary_line,
    explanation: r.explanation,
    status: r.status,
    stage: r.stage,
    counts: {
      totalDeps: r.total_deps,
      checkedDeps: r.checked_deps,
      unsupportedDeps: r.unsupported_deps,
      failedLookups: r.failed_lookups,
    },
    coverage: r.coverage,
    error: r.error_code ? { code: r.error_code, message: r.error_message ?? '' } : null,
    checks: { dependency: dependencyOf(r), source: sourceOf(r) },
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    completedAt: r.completed_at,
  };
}

function dependencyOf(r: ScanRow): DependencyCheck | null {
  if (r.dependency_status === null) return null;
  if (r.dependency_status === 'complete') return { status: 'complete' };
  return { status: r.dependency_status, error: { code: r.dependency_error_code ?? '', message: r.dependency_error_message ?? '' } };
}

function sourceOf(r: ScanRow): SourceCheck | null {
  if (r.source_status === null) return null;
  return {
    status: r.source_status,
    counts: { ...NO_SOURCE_COUNTS, ...(r.source_counts ?? {}) },
    error: r.source_error_code ? { code: r.source_error_code, message: r.source_error_message ?? '' } : null,
  };
}

/** Column values for both checks' outcomes. */
function checkColumns(checks: { dependency: DependencyCheck; source: SourceCheck }): unknown[] {
  const dep = checks.dependency;
  return [
    dep.status,
    dep.status === 'complete' ? null : dep.error.code,
    dep.status === 'complete' ? null : dep.error.message,
    checks.source.status,
    JSON.stringify(checks.source.counts),
    checks.source.error?.code ?? null,
    checks.source.error?.message ?? null,
  ];
}

/**
 * JSON for jsonb parameters, with every string made storable: PostgreSQL rejects \u0000 and unpaired surrogates,
 * and one such value from a lockfile would otherwise abort the whole report transaction. Last line of defence;
 * the parser already normalises what it reads.
 */
function storableJson(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) => (typeof v === 'string' && !isStorableText(v) ? storableText(v, Infinity) : v));
}

/** Stored ranges in the neutral AffectedRange shape, or null for older rows that hold raw provider JSON. */
function neutralRanges(value: unknown): AffectedRange[] | null {
  if (!Array.isArray(value)) return null;
  const str = (v: unknown) => typeof v === 'string';
  const strOrNull = (v: unknown) => v === null || typeof v === 'string';
  const ok = value.every((r: unknown) => {
    if (typeof r !== 'object' || r === null) return false;
    const x = r as Record<string, unknown>;
    if (x['kind'] === 'versions') return Array.isArray(x['versions']) && x['versions'].every(str);
    return (
      x['kind'] === 'range' &&
      str(x['introduced']) &&
      strOrNull(x['fixed']) &&
      strOrNull(x['lastAffected']) &&
      (x['limit'] === undefined || strOrNull(x['limit'])) &&
      (x['limits'] === undefined || (Array.isArray(x['limits']) && x['limits'].every(str)))
    );
  });
  return ok ? (value as AffectedRange[]) : null;
}

const COUNT_COLUMNS: Record<keyof ScanCounts, string> = {
  totalDeps: 'total_deps',
  checkedDeps: 'checked_deps',
  unsupportedDeps: 'unsupported_deps',
  failedLookups: 'failed_lookups',
};

export class PostgresScanRepository implements ScanRepository {
  private readonly pool: pg.Pool;

  constructor(pool: pg.Pool) {
    this.pool = pool;
  }

  async get(scanId: string): Promise<ScanView | null> {
    const { rows } = await this.pool.query<ScanRow>('SELECT * FROM scans WHERE id = $1', [scanId]);
    const row = rows[0];
    return row ? toView(row) : null;
  }

  async getReport(scanId: string): Promise<ReportData | null> {
    const scan = await this.get(scanId);
    if (!scan) return null;
    const findings = await this.pool.query<{
      ecosystem: string;
      package: string;
      installed_as: string[];
      direct_as: string[];
      installed_version: string;
      scope: Scope;
      is_direct: boolean;
      direct_parents: string[];
      install_paths: string[][];
      context_truncated: boolean;
      advisory_id: string;
      aliases: string[];
      severity: Severity;
      is_malicious: boolean;
      title: string | null;
      candidate_version: string | null;
      fix_status: FixStatus;
      affected_ranges: unknown;
      references: { type: string; url: string }[];
    }>(
      `SELECT ecosystem, package, installed_as, direct_as, installed_version, scope, is_direct, direct_parents, install_paths, context_truncated, advisory_id, aliases, severity,
              is_malicious, title, candidate_version, fix_status, affected_ranges, "references"
         FROM findings WHERE scan_id = $1 ORDER BY ecosystem, package, installed_version, advisory_id`,
      [scanId],
    );
    const source = await this.pool.query<{
      rule_id: string;
      rule_version: number;
      severity: SourceSeverity;
      path: string;
      start_line: number;
      start_col: number;
      end_line: number;
      end_col: number;
      excerpt: string;
    }>(
      `SELECT rule_id, rule_version, severity, path, start_line, start_col, end_line, end_col, excerpt
         FROM source_findings WHERE scan_id = $1 ORDER BY CASE severity WHEN 'high' THEN 0 ELSE 1 END, path, start_line, start_col`,
      [scanId],
    );
    const sourceFindings: SourceFinding[] = source.rows.map((f) => ({
      ruleId: f.rule_id,
      ruleVersion: f.rule_version,
      severity: f.severity,
      path: f.path,
      start: { line: f.start_line, column: f.start_col },
      end: { line: f.end_line, column: f.end_col },
      excerpt: f.excerpt,
    }));
    const unchecked = await this.pool.query<UncheckedView>(
      `SELECT ecosystem, package, version, reason FROM unchecked_deps WHERE scan_id = $1
        ORDER BY ecosystem, package, version`,
      [scanId],
    );
    return {
      scan,
      findings: findings.rows.map(
        (f): FindingView => ({
          ecosystem: f.ecosystem,
          package: f.package,
          installedAs: f.installed_as,
          directAs: f.direct_as,
          installedVersion: f.installed_version,
          scope: f.scope,
          isDirect: f.is_direct,
          directParents: f.direct_parents,
          installPaths: f.install_paths,
          contextTruncated: f.context_truncated,
          advisoryId: f.advisory_id,
          aliases: f.aliases,
          severity: f.severity,
          isMalicious: f.is_malicious,
          title: f.title,
          candidateVersion: f.candidate_version,
          fixStatus: f.fix_status,
          affectedRanges: neutralRanges(f.affected_ranges),
          references: f.references,
        }),
      ),
      unchecked: unchecked.rows,
      sourceFindings,
    };
  }

  async claim(scanId: string): Promise<ClaimedScan | null> {
    const { rows } = await this.pool.query<
      { attempt: number; repo_owner: string; repo_name: string } & Pick<ScanRow, 'visibility' | 'github_repo_id' | 'installation_id'>
    >(
      `UPDATE scans
          SET attempt = attempt + 1, status = 'running', stage = 'fetching', error_code = NULL, error_message = NULL
        WHERE id = $1 AND status NOT IN ${TERMINAL}
        RETURNING attempt, repo_owner, repo_name, visibility, github_repo_id, installation_id`,
      [scanId],
    );
    const row = rows[0];
    if (!row) return null;
    const visibility = visibilityOf(row);
    return {
      scanId,
      attempt: row.attempt,
      repo: { owner: row.repo_owner, name: row.repo_name },
      access:
        visibility.kind === 'public'
          ? { kind: 'public' }
          : { kind: 'installation', installationId: visibility.installationId, repositoryId: visibility.repositoryId },
    };
  }

  async recordProgress(
    claim: ClaimedScan,
    update: { stage?: ScanStage; commitSha?: string; lockfilePath?: string; counts?: Partial<ScanCounts> },
  ): Promise<boolean> {
    const sets: string[] = [];
    const values: unknown[] = [claim.scanId, claim.attempt];
    const set = (column: string, value: unknown) => {
      values.push(value);
      sets.push(`${column} = $${values.length}`);
    };
    if (update.stage) set('stage', update.stage);
    if (update.commitSha) set('commit_sha', update.commitSha);
    if (update.lockfilePath) set('lockfile_path', update.lockfilePath);
    for (const [k, v] of Object.entries(update.counts ?? {})) {
      set(COUNT_COLUMNS[k as keyof ScanCounts], v);
    }
    if (sets.length === 0) return true;
    const res = await this.pool.query(
      `UPDATE scans SET ${sets.join(', ')}
        WHERE id = $1 AND attempt = $2 AND status = 'running'`,
      values,
    );
    return res.rowCount === 1;
  }

  async complete(claim: ClaimedScan, c: Completion): Promise<boolean> {
    return inTransactionOrRollback(this.pool, async (client) => {
      const owned = await client.query(
        `SELECT 1 FROM scans WHERE id = $1 AND attempt = $2 AND status NOT IN ${TERMINAL} FOR UPDATE`,
        [claim.scanId, claim.attempt],
      );
      if (owned.rowCount !== 1) throw new Rollback(false);

      await client.query('DELETE FROM findings WHERE scan_id = $1', [claim.scanId]);
      await client.query('DELETE FROM unchecked_deps WHERE scan_id = $1', [claim.scanId]);
      await client.query('DELETE FROM source_findings WHERE scan_id = $1', [claim.scanId]);

      if (c.sourceFindings.length > 0) {
        await client.query(
          `INSERT INTO source_findings (scan_id, rule_id, rule_version, severity, path, start_line, start_col, end_line, end_col, excerpt)
           SELECT $1, f.rule_id, f.rule_version, f.severity, f.path, f.start_line, f.start_col, f.end_line, f.end_col, f.excerpt
             FROM jsonb_to_recordset($2::jsonb) AS f(
                  rule_id text, rule_version integer, severity text, path text,
                  start_line integer, start_col integer, end_line integer, end_col integer, excerpt text)`,
          [
            claim.scanId,
            storableJson(
              c.sourceFindings.map((f) => ({
                rule_id: f.ruleId,
                rule_version: f.ruleVersion,
                severity: f.severity,
                path: f.path,
                start_line: f.start.line,
                start_col: f.start.column,
                end_line: f.end.line,
                end_col: f.end.column,
                excerpt: f.excerpt,
              })),
            ),
          ],
        );
      }

      if (c.findings.length > 0) {
        await client.query(
          `INSERT INTO findings (scan_id, ecosystem, package, installed_as, direct_as, installed_version, scope, is_direct, direct_parents, install_paths, context_truncated,
                                 advisory_id, aliases, severity, is_malicious, title, affected_ranges,
                                 candidate_version, fix_status, "references")
           SELECT $1, f.ecosystem, f.package, ARRAY(SELECT jsonb_array_elements_text(f.installed_as)),
                  ARRAY(SELECT jsonb_array_elements_text(f.direct_as)), f.installed_version, f.scope, f.is_direct,
                  ARRAY(SELECT jsonb_array_elements_text(f.direct_parents)), f.install_paths, f.context_truncated,
                  f.advisory_id, ARRAY(SELECT jsonb_array_elements_text(f.aliases)), f.severity, f.is_malicious,
                  f.title, f.affected_ranges, f.candidate_version, f.fix_status, f."references"
             FROM jsonb_to_recordset($2::jsonb) AS f(
                  ecosystem text, package text, installed_as jsonb, direct_as jsonb, installed_version text, scope text, is_direct boolean, direct_parents jsonb,
                  install_paths jsonb, context_truncated boolean, advisory_id text, aliases jsonb, severity text, is_malicious boolean,
                  title text, affected_ranges jsonb, candidate_version text, fix_status text, "references" jsonb)`,
          [
            claim.scanId,
            storableJson(
              c.findings.map((f) => ({
                ecosystem: f.ecosystem,
                package: f.package,
                installed_as: f.installedAs,
                direct_as: f.directAs,
                installed_version: f.installedVersion,
                scope: f.scope,
                is_direct: f.isDirect,
                direct_parents: f.directParents,
                install_paths: f.installPaths,
                context_truncated: f.contextTruncated,
                advisory_id: f.advisory.id,
                aliases: f.advisory.aliases,
                severity: f.advisory.severity,
                is_malicious: f.advisory.isMalicious,
                title: f.advisory.title,
                affected_ranges: f.advisory.affectedRanges,
                candidate_version: f.candidateVersion,
                fix_status: f.fixStatus,
                references: f.advisory.references,
              })),
            ),
          ],
        );
      }

      if (c.unchecked.length > 0) {
        await client.query(
          `INSERT INTO unchecked_deps (scan_id, ecosystem, package, version, reason)
           SELECT $1, u.ecosystem, u.package, u.version, u.reason
             FROM jsonb_to_recordset($2::jsonb) AS u(ecosystem text, package text, version text, reason text)`,
          [claim.scanId, storableJson(c.unchecked)],
        );
      }

      const done = await client.query(
        `UPDATE scans
            SET status = 'completed', coverage = $3,
                total_deps = $4, checked_deps = $5, unsupported_deps = $6, failed_lookups = $7,
                advisory_source = $8, summary_line = $9,
                explanation = $10::jsonb, explanation_source = $11,
                dependency_status = $12, dependency_error_code = $13, dependency_error_message = $14,
                source_status = $15, source_counts = $16::jsonb, source_error_code = $17, source_error_message = $18
          WHERE id = $1 AND attempt = $2`,
        [
          claim.scanId,
          claim.attempt,
          c.coverage,
          c.counts.totalDeps,
          c.counts.checkedDeps,
          c.counts.unsupportedDeps,
          c.counts.failedLookups,
          c.advisorySource,
          c.summaryLine,
          c.explanation === null ? null : storableJson(c.explanation),
          c.explanation?.source ?? null,
          ...checkColumns(c),
        ],
      );
      if (done.rowCount !== 1) throw new Error(`completion update matched ${String(done.rowCount)} rows under lock`);
      return true;
    });
  }

  async failIfOpen(scanId: string, reason: { code: string; message: string }): Promise<boolean> {
    const res = await this.pool.query(
      `UPDATE scans SET status = 'failed', attempt = attempt + 1, error_code = $2, error_message = $3
        WHERE id = $1 AND status NOT IN ${TERMINAL}`,
      [scanId, reason.code, reason.message],
    );
    return res.rowCount === 1;
  }

  async findStale(olderThanSeconds: number, limit: number, after: StaleCursor | null = null): Promise<StaleScan[]> {
    // Uses the partial index on updated_at for non-terminal rows (migration 001). (updated_at, id) is a total
    // order, so pages neither repeat nor skip rows that didn't change in between.
    const { rows } = await this.pool.query<{ id: string; updated_at: Date }>(
      `SELECT id, updated_at FROM scans
        WHERE status NOT IN ${TERMINAL} AND updated_at < now() - make_interval(secs => $1)
          AND ($3::timestamptz IS NULL OR (updated_at, id) > ($3::timestamptz, $4::uuid))
        ORDER BY updated_at, id LIMIT $2`,
      [olderThanSeconds, limit, after?.updatedAt ?? null, after?.id ?? null],
    );
    return rows.map((r) => ({ id: r.id, updatedAt: r.updated_at }));
  }

  async deleteExpired(limits: { scanDays: number; keyHours: number; batchSize: number }): Promise<{ scans: number; keys: number }> {
    const keys = await this.pool.query(
      `DELETE FROM idempotency_keys WHERE key IN (
         SELECT key FROM idempotency_keys WHERE created_at < now() - make_interval(hours => $1) LIMIT $2)`,
      [limits.keyHours, limits.batchSize],
    );
    const scans = await this.pool.query(
      `DELETE FROM scans WHERE id IN (
         SELECT id FROM scans
          WHERE status IN ${TERMINAL} AND completed_at < now() - make_interval(days => $1)
          LIMIT $2)`,
      [limits.scanDays, limits.batchSize],
    );
    return { scans: scans.rowCount ?? 0, keys: keys.rowCount ?? 0 };
  }

  async markRetrying(claim: ClaimedScan, reason: { code: string; message: string }): Promise<boolean> {
    const res = await this.pool.query(
      `UPDATE scans SET status = 'retrying', error_code = $3, error_message = $4
        WHERE id = $1 AND attempt = $2 AND status = 'running'`,
      [claim.scanId, claim.attempt, reason.code, reason.message],
    );
    return res.rowCount === 1;
  }

  async finish(
    claim: ClaimedScan,
    outcome: { status: 'failed' | 'unsupported'; code: string; message: string },
    checks?: { dependency: DependencyCheck; source: SourceCheck },
  ): Promise<boolean> {
    const res = checks
      ? await this.pool.query(
          `UPDATE scans SET status = $3, error_code = $4, error_message = $5,
                  dependency_status = $6, dependency_error_code = $7, dependency_error_message = $8,
                  source_status = $9, source_counts = $10::jsonb, source_error_code = $11, source_error_message = $12
            WHERE id = $1 AND attempt = $2 AND status NOT IN ${TERMINAL}`,
          [claim.scanId, claim.attempt, outcome.status, outcome.code, outcome.message, ...checkColumns(checks)],
        )
      : await this.pool.query(
          `UPDATE scans SET status = $3, error_code = $4, error_message = $5
            WHERE id = $1 AND attempt = $2 AND status NOT IN ${TERMINAL}`,
          [claim.scanId, claim.attempt, outcome.status, outcome.code, outcome.message],
        );
    return res.rowCount === 1;
  }
}
