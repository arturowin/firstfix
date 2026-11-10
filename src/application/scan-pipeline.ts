import { parseLockfile } from '../domain/lockfile.ts';
import { PermanentError } from '../ports/errors.ts';
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
 * Worker-side use case: claim → resolve SHA → read lockfile at that SHA → OSV lookup → save.
 *
 * Error contract (docs/ARCHITECTURE.md "Failures"):
 * - PermanentError → the outcome is recorded and run() returns normally, so pg-boss does not retry.
 * - Anything else (TransientError, aborts, bugs) propagates, so pg-boss retries the job.
 *   `retrying` status, the last-attempt check and dead-lettering come in M4.
 */
export class ScanPipeline {
  private readonly scans: ScanRepository;
  private readonly source: RepoSource;
  private readonly vulns: VulnDatabase;

  constructor(deps: { scans: ScanRepository; source: RepoSource; vulns: VulnDatabase }) {
    this.scans = deps.scans;
    this.source = deps.source;
    this.vulns = deps.vulns;
  }

  async run(scanId: string, signal: AbortSignal): Promise<RunResult> {
    const claim = await this.scans.claim(scanId);
    if (!claim) return 'not_claimed';
    try {
      return await this.scan(claim, signal);
    } catch (err) {
      if (err instanceof PermanentError) {
        const recorded = await this.scans.finish(claim, { status: err.outcome, code: err.code, message: err.message });
        return recorded ? err.outcome : 'stale';
      }
      throw err;
    }
  }

  private async scan(claim: ClaimedScan, signal: AbortSignal): Promise<RunResult> {
    const { sha } = await this.source.resolveDefaultCommit(claim.repo, signal);
    if (!(await this.scans.recordProgress(claim, { commitSha: sha }))) return 'stale';

    const text = await this.source.readLockfile(claim.repo, sha, signal);
    if (text === null) {
      throw new PermanentError(
        'no_lockfile',
        `No package-lock.json at the repository root (commit ${sha.slice(0, 7)}). Only npm lockfiles are supported.`,
        'unsupported',
      );
    }
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      throw new PermanentError('invalid_lockfile', 'package-lock.json is not valid JSON', 'unsupported');
    }
    const parsed = parseLockfile(json);
    if (parsed.kind === 'unsupported') throw new PermanentError('unsupported_lockfile', parsed.reason, 'unsupported');

    const { packages, uncheckable } = parsed;
    const totalDeps = packages.length + uncheckable.length;
    const moving = await this.scans.recordProgress(claim, {
      stage: 'scanning',
      counts: { totalDeps, unsupportedDeps: uncheckable.length },
    });
    if (!moving) return 'stale';

    const advisories = await this.vulns.lookup(
      packages.map((p) => ({ name: p.name, version: p.version })),
      signal,
    );

    if (!(await this.scans.recordProgress(claim, { stage: 'analyzing', counts: { checkedDeps: packages.length } }))) {
      return 'stale';
    }

    const findings: FindingInput[] = packages.flatMap((p) =>
      (advisories.get(packageKey(p)) ?? []).map((advisory) => ({
        package: p.name,
        installedVersion: p.version,
        scope: p.scope,
        isDirect: p.isDirect,
        directParents: [], // M2: dependency-graph walk
        installPaths: [], // M2
        advisory,
        candidateVersion: null, // M2: candidate selection
      })),
    );

    const saved = await this.scans.complete(claim, {
      counts: { totalDeps, checkedDeps: packages.length, unsupportedDeps: uncheckable.length, failedLookups: 0 },
      // "full" = every supported dependency in the root lockfile was checked (unsupported sources are listed
      // separately). Partial coverage from failed lookups arrives in M4.
      coverage: 'full',
      findings,
      unchecked: uncheckable.map((u) => ({ package: u.name, version: u.version, reason: u.reason })),
    });
    return saved ? 'completed' : 'stale';
  }
}
