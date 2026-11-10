import { selectCandidate } from '../domain/candidate.ts';
import { buildFixPlan, type PlanFinding } from '../domain/fix-plan.ts';
import { explainPlan, type ExplainDeps } from './explain.ts';
import { summaryLine } from '../domain/report-text.ts';
import { defaultRegistry, missingLockfileMessage } from '../domain/ecosystems/registry.ts';
import type { EcosystemRegistry, LockfileFormat } from '../domain/ecosystems/types.ts';
import { PermanentError, TransientError } from '../ports/errors.ts';
import type { RepoSource } from '../ports/repo-source.ts';
import type { ClaimedScan, FindingInput, ScanRepository } from '../ports/scan-repository.ts';
import { packageKey, type VulnDatabase } from '../ports/vuln-database.ts';

export type RunResult =
  | 'not_claimed' // missing or already terminal: duplicate delivery, nothing to do
  | 'stale' // a newer attempt owns the scan; this one stopped without writing
  | 'completed'
  | 'unsupported'
  | 'failed';

/**
 * Worker-side use case: claim → resolve SHA → find a supported lockfile at that SHA → parse with its
 * ecosystem's format → advisory lookup → save. Ecosystem-specific parts come from the registry.
 *
 * Error contract (docs/ARCHITECTURE.md "Failures"):
 * - PermanentError → the outcome is recorded and run() returns normally, so pg-boss does not retry.
 * - Anything else (TransientError, bugs) → `retrying` + reason (or `failed` on the last attempt), then rethrown
 *   so pg-boss retries. Aborts write nothing and propagate.
 */
export class ScanPipeline {
  private readonly scans: ScanRepository;
  private readonly source: RepoSource;
  private readonly vulns: VulnDatabase;
  private readonly registry: EcosystemRegistry;

  private readonly explain: ExplainDeps | null;

  /** `explain` null: no prose is written (tests that don't look at it). The worker always configures it. */
  constructor(deps: {
    scans: ScanRepository;
    source: RepoSource;
    vulns: VulnDatabase;
    registry?: EcosystemRegistry;
    explain?: ExplainDeps | null;
  }) {
    this.scans = deps.scans;
    this.source = deps.source;
    this.vulns = deps.vulns;
    this.registry = deps.registry ?? defaultRegistry;
    this.explain = deps.explain ?? null;
  }

  /**
   * One attempt. `lastAttempt`: the queue won't retry after this one, so a transient error ends the scan as
   * `failed` instead of `retrying` (no code runs when the queue gives up; the dead-letter handler and the
   * sweeper are the safety nets for attempts that die without reaching this point).
   */
  async run(scanId: string, signal: AbortSignal, options: { lastAttempt?: boolean } = {}): Promise<RunResult> {
    const claim = await this.scans.claim(scanId);
    if (!claim) return 'not_claimed';
    try {
      return await this.scan(claim, signal);
    } catch (err) {
      if (err instanceof PermanentError) {
        const recorded = await this.scans.finish(claim, { status: err.outcome, code: err.code, message: err.message });
        return recorded ? err.outcome : 'stale';
      }
      // The job was stopped (expired, claim lost, shutdown): another attempt owns what happens next.
      if (signal.aborted) throw err;
      await this.recordTransient(claim, err, options.lastAttempt === true);
      throw err;
    }
  }

  private async recordTransient(claim: ClaimedScan, err: unknown, lastAttempt: boolean): Promise<void> {
    // Known transient errors carry user-facing messages; anything else is a bug and stays internal.
    const reason =
      err instanceof TransientError
        ? { code: err.code, message: err.message }
        : { code: 'internal_error', message: 'An unexpected error occurred while scanning' };
    try {
      if (lastAttempt) {
        await this.scans.finish(claim, { status: 'failed', code: reason.code, message: `Retries exhausted: ${reason.message}` });
      } else {
        await this.scans.markRetrying(claim, reason);
      }
    } catch {
      // Recording failed too (e.g. the database is down): the original error is what gets retried; the
      // dead-letter handler and the sweeper still close the scan if this was the end.
    }
  }

  private async scan(claim: ClaimedScan, signal: AbortSignal): Promise<RunResult> {
    const { sha } = await this.source.resolveDefaultCommit(claim.repo, signal);
    if (!(await this.scans.recordProgress(claim, { commitSha: sha }))) return 'stale';

    const found = await this.findLockfile(claim, sha, signal);
    if (!found) throw new PermanentError('no_lockfile', missingLockfileMessage(this.registry, sha.slice(0, 7)), 'unsupported');
    if (!(await this.scans.recordProgress(claim, { lockfilePath: found.path }))) return 'stale';

    const { format } = found;
    const ecosystem = format.ecosystem;
    const parsed = format.parse(found.text);
    if (parsed.kind === 'invalid') throw new PermanentError('invalid_lockfile', parsed.reason, 'unsupported');
    if (parsed.kind === 'unsupported') throw new PermanentError('unsupported_lockfile', parsed.reason, 'unsupported');

    const { packages, uncheckable } = parsed;
    const scheme = this.registry.ecosystems.get(ecosystem)?.versionScheme ?? null;
    const totalDeps = packages.length + uncheckable.length;
    const moving = await this.scans.recordProgress(claim, {
      stage: 'scanning',
      counts: { totalDeps, unsupportedDeps: uncheckable.length },
    });
    if (!moving) return 'stale';

    const { advisories, failed, incomplete } = await this.vulns.lookup(
      packages.map((p) => ({ ecosystem, name: p.name, version: p.version })),
      signal,
    );
    // Nothing could be checked: almost always the advisory source being down. Retried like any transient error;
    // on the last attempt the scan ends failed with this reason.
    if (packages.length > 0 && failed.length === packages.length) {
      throw new TransientError(
        'advisory_lookup_failed',
        `${this.vulns.source.name} could not be reached: none of the ${String(packages.length)} dependencies could be checked`,
      );
    }
    const keyOf = (p: { name: string; version: string }) => packageKey({ ecosystem, ...p });
    const failedKeys = new Set(failed.map(packageKey));
    const incompleteKeys = new Set(incomplete.map(packageKey));
    // Fully checked: every advisory for it was fetched. Incomplete packages keep their confirmed findings but
    // count, like failed ones, as not fully checked (coverage partial, listed as lookup_failed).
    const checked = packages.filter((p) => !failedKeys.has(keyOf(p)) && !incompleteKeys.has(keyOf(p)));
    const lookupFailed = packages.filter((p) => failedKeys.has(keyOf(p)) || incompleteKeys.has(keyOf(p)));
    const withFindings = packages.filter((p) => !failedKeys.has(keyOf(p)));

    if (!(await this.scans.recordProgress(claim, { stage: 'analyzing', counts: { checkedDeps: checked.length } }))) {
      return 'stale';
    }

    const findings: FindingInput[] = withFindings.flatMap((p) =>
      (advisories.get(packageKey({ ecosystem, ...p })) ?? []).map((advisory): FindingInput => {
        const candidate = selectCandidate(p.version, advisory.affectedRanges, scheme);
        return {
          ecosystem,
          package: p.name,
          installedAs: p.installedAs,
          directAs: p.directAs,
          installedVersion: p.version,
          scope: p.scope,
          isDirect: p.isDirect,
          directParents: p.directParents,
          installPaths: p.installPaths,
          advisory,
          candidateVersion: candidate.version,
          fixStatus: candidate.status,
        };
      }),
    );

    const counts = {
      totalDeps,
      checkedDeps: checked.length,
      unsupportedDeps: uncheckable.length,
      failedLookups: lookupFailed.length,
    };
    const plan = buildFixPlan(findings.map(toPlanFinding), (e) => this.registry.ecosystems.get(e)?.versionScheme ?? null);

    const line = summaryLine({ counts, lockfilePath: found.path, actions: plan });
    const explanation = this.explain
      ? await explainPlan(
          this.explain,
          { repo: `${claim.repo.owner}/${claim.repo.name}`, summaryLine: line, checkedDeps: counts.checkedDeps, totalDeps, actions: plan },
          signal,
        )
      : null;

    const saved = await this.scans.complete(claim, {
      advisorySource: this.vulns.source.name,
      summaryLine: line,
      explanation,
      counts,
      // "full" = every supported dependency in the lockfile was checked (unsupported sources are listed
      // separately); "partial" = some lookups failed, and those are listed as unchecked.
      coverage: lookupFailed.length > 0 ? 'partial' : 'full',
      findings,
      unchecked: [
        ...uncheckable.map((u) => ({ ecosystem, package: u.name, version: u.version, reason: u.reason })),
        ...lookupFailed.map((p) => ({ ecosystem, package: p.name, version: p.version, reason: 'lookup_failed' as const })),
      ],
    });
    return saved ? 'completed' : 'stale';
  }

  /** The first registered lockfile present at the repository root, in registry order. One lockfile per scan. */
  private async findLockfile(
    claim: ClaimedScan,
    sha: string,
    signal: AbortSignal,
  ): Promise<{ format: LockfileFormat; path: string; text: string } | null> {
    for (const format of this.registry.formats) {
      for (const path of format.fileNames) {
        const text = await this.source.readFile(claim.repo, sha, path, signal);
        if (text !== null) return { format, path, text };
      }
    }
    return null;
  }
}

function toPlanFinding(f: FindingInput): PlanFinding {
  return {
    ecosystem: f.ecosystem,
    package: f.package,
    installedAs: f.installedAs,
    directAs: f.directAs,
    installedVersion: f.installedVersion,
    scope: f.scope,
    isDirect: f.isDirect,
    directParents: f.directParents,
    advisoryId: f.advisory.id,
    severity: f.advisory.severity,
    isMalicious: f.advisory.isMalicious,
    title: f.advisory.title,
    candidateVersion: f.candidateVersion,
    fixStatus: f.fixStatus,
    affectedRanges: f.advisory.affectedRanges,
  };
}
