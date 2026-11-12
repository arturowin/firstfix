import { selectCandidate } from '../domain/candidate.ts';
import { buildFixPlan, type PlanFinding } from '../domain/fix-plan.ts';
import { explainPlan, type ExplainDeps } from './explain.ts';
import { summaryLine } from '../domain/report-text.ts';
import { defaultRegistry, missingLockfileMessage } from '../domain/ecosystems/registry.ts';
import type { EcosystemRegistry, LockfileFormat } from '../domain/ecosystems/types.ts';
import { PermanentError, TransientError } from '../ports/errors.ts';
import type { RepoSource } from '../ports/repo-source.ts';
import type { ClaimedScan, DependencyCheck, FindingInput, ScanCounts, ScanRepository, SourceCheck, UncheckedView } from '../ports/scan-repository.ts';
import { NO_SOURCE_COUNTS, sourceSummaryLine } from '../domain/source-rules.ts';
import { sourceFacts } from '../domain/explanation.ts';
import type { Action } from '../domain/fix-plan.ts';
import { DEFAULT_SOURCE_CHECK, runSourceCheck, type SourceCheckOptions } from './source-check.ts';
import { packageKey, type VulnDatabase } from '../ports/vuln-database.ts';

/** The dependency check's result inside one attempt (nothing is written until both checks are done). */
type DependencyResult =
  | {
      status: 'complete';
      counts: ScanCounts;
      coverage: 'full' | 'partial';
      findings: FindingInput[];
      unchecked: UncheckedView[];
      plan: Action[];
      summaryLine: string;
    }
  | { status: 'unsupported'; error: { code: string; message: string } };

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
  private readonly sourceOptions: SourceCheckOptions;

  /** `explain` null: no prose is written (tests that don't look at it). The worker always configures it. */
  constructor(deps: {
    scans: ScanRepository;
    source: RepoSource;
    vulns: VulnDatabase;
    registry?: EcosystemRegistry;
    explain?: ExplainDeps | null;
    /** Limits for the source check; defaults from ARCHITECTURE.md. */
    sourceCheck?: SourceCheckOptions;
  }) {
    this.scans = deps.scans;
    this.source = deps.source;
    this.vulns = deps.vulns;
    this.registry = deps.registry ?? defaultRegistry;
    this.explain = deps.explain ?? null;
    this.sourceOptions = deps.sourceCheck ?? DEFAULT_SOURCE_CHECK;
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
      return await this.scan(claim, signal, options.lastAttempt === true);
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

  private async scan(claim: ClaimedScan, signal: AbortSignal, lastAttempt: boolean): Promise<RunResult> {
    // Shared by both checks: failures here (not found, access lost, empty repository) end the whole scan.
    const { sha, treeSha } = await this.source.resolveDefaultCommit(claim.repo, claim.access, signal);
    if (!(await this.scans.recordProgress(claim, { commitSha: sha }))) return 'stale';

    const dep = await this.guarded(() => this.dependencyCheck(claim, sha, signal), lastAttempt, signal);
    if (dep === 'stale') return 'stale';

    if (!(await this.scans.recordProgress(claim, { stage: 'source' }))) return 'stale';
    const src = await this.guarded(
      () => runSourceCheck(this.source, { repo: claim.repo, access: claim.access, commitSha: sha, treeSha }, this.sourceOptions, signal),
      lastAttempt,
      signal,
    );

    const dependency: DependencyCheck =
      'failed' in dep ? { status: 'failed', error: dep.failed } : dep.status === 'complete' ? { status: 'complete' } : { status: 'unsupported', error: dep.error };
    const source: SourceCheck = 'failed' in src ? { status: 'failed', counts: NO_SOURCE_COUNTS, error: src.failed } : src.check;
    const sourceFindings = 'failed' in src ? [] : src.findings;
    const checks = { dependency, source };

    const sourceUsable = source.status === 'complete' || (source.status === 'partial' && source.counts.checked > 0);
    const srcFacts = sourceFacts(source, sourceFindings);
    if ('failed' in dep || dep.status !== 'complete') {
      if (sourceUsable) {
        // The scan completes on its source check; the report says why dependencies weren't checked.
        if (!(await this.scans.recordProgress(claim, { stage: 'analyzing' }))) return 'stale';
        const explanation = this.explain
          ? await explainPlan(
              this.explain,
              {
                repo: `${claim.repo.owner}/${claim.repo.name}`,
                summaryLine: sourceSummaryLine(source, sourceFindings),
                checkedDeps: 0,
                totalDeps: 0,
                actions: [],
                dependenciesChecked: false,
                source: srcFacts,
              },
              signal,
            )
          : null;
        const empty = { totalDeps: 0, checkedDeps: 0, unsupportedDeps: 0, failedLookups: 0 };
        const saved = await this.scans.complete(claim, {
          advisorySource: null,
          summaryLine: null,
          explanation,
          counts: empty,
          coverage: null,
          findings: [],
          unchecked: [],
          dependency,
          source,
          sourceFindings,
        });
        return saved ? 'completed' : 'stale';
      }
      const result = await this.finishWithout(claim, checks);
      // Failed because a check ran out of retries: rethrow, as before source checks, so the queue records the
      // job as failed too (the scan is already terminal, so nothing else changes it).
      const cause = 'failed' in dep ? dep.cause : 'failed' in src ? src.cause : null;
      if (result === 'failed' && cause) throw cause;
      return result;
    }

    // Prioritize and explain once both checks are in.
    if (!(await this.scans.recordProgress(claim, { stage: 'analyzing' }))) return 'stale';
    const explanation = this.explain
      ? await explainPlan(
          this.explain,
          {
            repo: `${claim.repo.owner}/${claim.repo.name}`,
            summaryLine: dep.summaryLine,
            checkedDeps: dep.counts.checkedDeps,
            totalDeps: dep.counts.totalDeps,
            actions: dep.plan,
            source: srcFacts,
          },
          signal,
        )
      : null;

    const saved = await this.scans.complete(claim, {
      advisorySource: this.vulns.source.name,
      summaryLine: dep.summaryLine,
      explanation,
      counts: dep.counts,
      // "full" = every supported dependency in the lockfile was checked (unsupported sources are listed
      // separately); "partial" = some lookups failed, and those are listed as unchecked.
      coverage: dep.coverage,
      findings: dep.findings,
      unchecked: dep.unchecked,
      dependency,
      source,
      sourceFindings,
    });
    return saved ? 'completed' : 'stale';
  }

  /**
   * Neither check produced anything usable. Failed if either failed (the dependency check's reason first, as
   * before source checks existed); otherwise nothing could be checked at all: unsupported, with the dependency
   * check's reason (e.g. no lockfile) and no source files either.
   */
  private async finishWithout(claim: ClaimedScan, checks: { dependency: DependencyCheck; source: SourceCheck }): Promise<RunResult> {
    const { dependency: dep, source: src } = checks;
    let outcome: { status: 'failed' | 'unsupported'; code: string; message: string };
    if (dep.status === 'failed') {
      outcome = { status: 'failed', code: dep.error.code, message: dep.error.message };
    } else if (src.status === 'failed' && src.error) {
      const depNote = dep.status === 'unsupported' ? ` Dependencies: ${dep.error.message}` : '';
      outcome = { status: 'failed', code: src.error.code, message: `Source checks failed: ${src.error.message}.${depNote}` };
    } else if (dep.status === 'unsupported') {
      outcome = { status: 'unsupported', code: dep.error.code, message: dep.error.message };
    } else {
      throw new Error('unreachable: a complete dependency check is always usable');
    }
    const recorded = await this.scans.finish(claim, outcome, checks);
    return recorded ? outcome.status : 'stale';
  }

  /**
   * Runs one check. On the last attempt a transient error ends just this check as failed (the other check's
   * results are kept); before that it propagates, so the whole job is retried. Shared failures and cancellation
   * always propagate.
   */
  private async guarded<T>(
    run: () => Promise<T>,
    lastAttempt: boolean,
    signal: AbortSignal,
  ): Promise<T | { failed: { code: string; message: string }; cause: TransientError }> {
    try {
      return await run();
    } catch (err) {
      if (!signal.aborted && lastAttempt && err instanceof TransientError) {
        return { failed: { code: err.code, message: `Retries exhausted: ${err.message}` }, cause: err };
      }
      throw err;
    }
  }

  /**
   * The dependency check: lockfile → parse → advisory lookup → plan. A missing or unsupported lockfile is this
   * check's outcome (`unsupported`), not the scan's: the source check still runs.
   */
  private async dependencyCheck(claim: ClaimedScan, sha: string, signal: AbortSignal): Promise<DependencyResult | 'stale'> {
    try {
      return await this.checkDependencies(claim, sha, signal);
    } catch (err) {
      if (err instanceof PermanentError && err.outcome === 'unsupported') {
        return { status: 'unsupported', error: { code: err.code, message: err.message } };
      }
      throw err;
    }
  }

  private async checkDependencies(claim: ClaimedScan, sha: string, signal: AbortSignal): Promise<DependencyResult | 'stale'> {
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
    // on the last attempt the dependency check ends failed with this reason.
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

    // Prioritizing comes after the source check (stage `analyzing`); record the count now.
    if (!(await this.scans.recordProgress(claim, { counts: { checkedDeps: checked.length } }))) {
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
          contextTruncated: p.contextTruncated,
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
    return {
      status: 'complete',
      counts,
      coverage: lookupFailed.length > 0 ? 'partial' : 'full',
      findings,
      unchecked: [
        ...uncheckable.map((u) => ({ ecosystem, package: u.name, version: u.version, reason: u.reason })),
        ...lookupFailed.map((p) => ({ ecosystem, package: p.name, version: p.version, reason: 'lookup_failed' as const })),
      ],
      plan,
      summaryLine: summaryLine({ counts, lockfilePath: found.path, actions: plan }),
    };
  }

  /** The first registered lockfile present at the repository root, in registry order. One lockfile per scan. */
  private async findLockfile(
    claim: ClaimedScan,
    sha: string,
    signal: AbortSignal,
  ): Promise<{ format: LockfileFormat; path: string; text: string } | null> {
    for (const format of this.registry.formats) {
      for (const path of format.fileNames) {
        const text = await this.source.readFile(claim.repo, claim.access, sha, path, signal);
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
    contextTruncated: f.contextTruncated,
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
