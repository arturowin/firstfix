import { selectCandidate } from '../domain/candidate.ts';
import { defaultRegistry, missingLockfileMessage } from '../domain/ecosystems/registry.ts';
import type { EcosystemRegistry, LockfileFormat } from '../domain/ecosystems/types.ts';
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
 * Worker-side use case: claim → resolve SHA → find a supported lockfile at that SHA → parse with its
 * ecosystem's format → advisory lookup → save. Ecosystem-specific parts come from the registry.
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
  private readonly registry: EcosystemRegistry;

  constructor(deps: { scans: ScanRepository; source: RepoSource; vulns: VulnDatabase; registry?: EcosystemRegistry }) {
    this.scans = deps.scans;
    this.source = deps.source;
    this.vulns = deps.vulns;
    this.registry = deps.registry ?? defaultRegistry;
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

    const advisories = await this.vulns.lookup(
      packages.map((p) => ({ ecosystem, name: p.name, version: p.version })),
      signal,
    );

    if (!(await this.scans.recordProgress(claim, { stage: 'analyzing', counts: { checkedDeps: packages.length } }))) {
      return 'stale';
    }

    const findings: FindingInput[] = packages.flatMap((p) =>
      (advisories.get(packageKey({ ecosystem, ...p })) ?? []).map((advisory): FindingInput => {
        const candidate = selectCandidate(p.version, advisory.affectedRanges, scheme);
        return {
          ecosystem,
          package: p.name,
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

    const saved = await this.scans.complete(claim, {
      advisorySource: this.vulns.source.name,
      counts: { totalDeps, checkedDeps: packages.length, unsupportedDeps: uncheckable.length, failedLookups: 0 },
      // "full" = every supported dependency in the root lockfile was checked (unsupported sources are listed
      // separately). Partial coverage from failed lookups arrives in M4.
      coverage: 'full',
      findings,
      unchecked: uncheckable.map((u) => ({ ecosystem, package: u.name, version: u.version, reason: u.reason })),
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
