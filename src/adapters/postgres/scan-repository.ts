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
  UncheckedView,
} from '../../ports/scan-repository.ts';
import type { Severity } from '../../domain/advisory.ts';
import type { FixStatus } from '../../domain/candidate.ts';
import type { Scope } from '../../domain/lockfile.ts';
import { inTransactionOrRollback, Rollback } from './pool.ts';

const TERMINAL = `('completed', 'unsupported', 'failed')`;

interface ScanRow {
  id: string;
  repo_owner: string;
  repo_name: string;
  repo_url_normalized: string;
  commit_sha: string | null;
  lockfile_path: string | null;
  advisory_source: string | null;
  summary_line: string | null;
  status: ScanStatus;
  stage: ScanStage | null;
  total_deps: number;
  checked_deps: number;
  unsupported_deps: number;
  failed_lookups: number;
  coverage: 'full' | 'partial' | null;
  error_code: string | null;
  error_message: string | null;
  created_at: Date;
  updated_at: Date;
  completed_at: Date | null;
}

function toView(r: ScanRow): ScanView {
  return {
    id: r.id,
    repo: { owner: r.repo_owner, name: r.repo_name, url: r.repo_url_normalized },
    commitSha: r.commit_sha,
    lockfilePath: r.lockfile_path,
    advisorySource: r.advisory_source,
    summaryLine: r.summary_line,
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
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    completedAt: r.completed_at,
  };
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
      installed_version: string;
      scope: Scope;
      is_direct: boolean;
      direct_parents: string[];
      install_paths: string[][];
      advisory_id: string;
      aliases: string[];
      severity: Severity;
      is_malicious: boolean;
      title: string | null;
      candidate_version: string | null;
      fix_status: FixStatus;
      references: { type: string; url: string }[];
    }>(
      `SELECT ecosystem, package, installed_as, installed_version, scope, is_direct, direct_parents, install_paths, advisory_id, aliases, severity,
              is_malicious, title, candidate_version, fix_status, "references"
         FROM findings WHERE scan_id = $1 ORDER BY ecosystem, package, installed_version, advisory_id`,
      [scanId],
    );
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
          installedVersion: f.installed_version,
          scope: f.scope,
          isDirect: f.is_direct,
          directParents: f.direct_parents,
          installPaths: f.install_paths,
          advisoryId: f.advisory_id,
          aliases: f.aliases,
          severity: f.severity,
          isMalicious: f.is_malicious,
          title: f.title,
          candidateVersion: f.candidate_version,
          fixStatus: f.fix_status,
          references: f.references,
        }),
      ),
      unchecked: unchecked.rows,
    };
  }

  async claim(scanId: string): Promise<ClaimedScan | null> {
    const { rows } = await this.pool.query<{ attempt: number; repo_owner: string; repo_name: string }>(
      `UPDATE scans
          SET attempt = attempt + 1, status = 'running', stage = 'fetching', error_code = NULL, error_message = NULL
        WHERE id = $1 AND status NOT IN ${TERMINAL}
        RETURNING attempt, repo_owner, repo_name`,
      [scanId],
    );
    const row = rows[0];
    return row ? { scanId, attempt: row.attempt, repo: { owner: row.repo_owner, name: row.repo_name } } : null;
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

      if (c.findings.length > 0) {
        await client.query(
          `INSERT INTO findings (scan_id, ecosystem, package, installed_as, installed_version, scope, is_direct, direct_parents, install_paths,
                                 advisory_id, aliases, severity, is_malicious, title, affected_ranges,
                                 candidate_version, fix_status, "references")
           SELECT $1, f.ecosystem, f.package, ARRAY(SELECT jsonb_array_elements_text(f.installed_as)), f.installed_version, f.scope, f.is_direct,
                  ARRAY(SELECT jsonb_array_elements_text(f.direct_parents)), f.install_paths,
                  f.advisory_id, ARRAY(SELECT jsonb_array_elements_text(f.aliases)), f.severity, f.is_malicious,
                  f.title, f.affected_ranges, f.candidate_version, f.fix_status, f."references"
             FROM jsonb_to_recordset($2::jsonb) AS f(
                  ecosystem text, package text, installed_as jsonb, installed_version text, scope text, is_direct boolean, direct_parents jsonb,
                  install_paths jsonb, advisory_id text, aliases jsonb, severity text, is_malicious boolean,
                  title text, affected_ranges jsonb, candidate_version text, fix_status text, "references" jsonb)`,
          [
            claim.scanId,
            JSON.stringify(
              c.findings.map((f) => ({
                ecosystem: f.ecosystem,
                package: f.package,
                installed_as: f.installedAs,
                installed_version: f.installedVersion,
                scope: f.scope,
                is_direct: f.isDirect,
                direct_parents: f.directParents,
                install_paths: f.installPaths,
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
          [claim.scanId, JSON.stringify(c.unchecked)],
        );
      }

      const done = await client.query(
        `UPDATE scans
            SET status = 'completed', coverage = $3,
                total_deps = $4, checked_deps = $5, unsupported_deps = $6, failed_lookups = $7,
                advisory_source = $8, summary_line = $9
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
        ],
      );
      if (done.rowCount !== 1) throw new Error(`completion update matched ${String(done.rowCount)} rows under lock`);
      return true;
    });
  }

  async finish(
    claim: ClaimedScan,
    outcome: { status: 'failed' | 'unsupported'; code: string; message: string },
  ): Promise<boolean> {
    const res = await this.pool.query(
      `UPDATE scans SET status = $3, error_code = $4, error_message = $5
        WHERE id = $1 AND attempt = $2 AND status NOT IN ${TERMINAL}`,
      [claim.scanId, claim.attempt, outcome.status, outcome.code, outcome.message],
    );
    return res.rowCount === 1;
  }
}
