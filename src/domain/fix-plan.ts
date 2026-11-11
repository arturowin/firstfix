/**
 * Ranking and recommended next actions (docs/ARCHITECTURE.md "Ranking policy", "Recommended next actions").
 * Pure and deterministic: the same findings always give the same plan. Facts come from findings; versions are
 * candidates from advisory data, never "fixes".
 */
import type { AffectedRange, Severity } from './advisory.ts';
import type { FixStatus } from './candidate.ts';
import type { EcosystemId, VersionScheme } from './ecosystems/types.ts';
import type { Scope } from './lockfile.ts';

/** What the plan needs from a stored finding (one package@version × advisory). */
export interface PlanFinding {
  ecosystem: EcosystemId;
  package: string;
  /** npm aliases etc.: the names the project uses for it, when they differ from `package`. */
  installedAs: string[];
  /** Names the project declares it under directly; each declaration needs its own update. */
  directAs: string[];
  installedVersion: string;
  scope: Scope;
  isDirect: boolean;
  directParents: string[];
  advisoryId: string;
  severity: Severity;
  isMalicious: boolean;
  title: string | null;
  candidateVersion: string | null;
  fixStatus: FixStatus;
  /** The advisory's ranges for this package; null when not available (then nothing is claimed as addressed). */
  affectedRanges: AffectedRange[] | null;
  /** Dependency context (parents, paths) was cut to bound work; absent on older stored rows. */
  contextTruncated?: boolean;
}

export type ActionKind =
  /** Known malicious: remove, find how it got in, rotate secrets. Never "upgrade". */
  | 'remove_malicious'
  /** At least one installed version has a candidate version. */
  | 'upgrade'
  /** Affected, and no fixed version is published. */
  | 'no_fix'
  /** Advisory data doesn't let us place a version (or no version scheme): read the advisory. */
  | 'review';

export interface CandidateStep {
  version: string;
  /** Advisories on this installed version that this candidate addresses according to advisory data. */
  addresses: number;
  /** Advisories with a candidate that still list this version as affected (shown, so a partial fix is clear). */
  stillAffected: string[];
  majorJump: boolean;
}

export interface ActionVersion {
  installedVersion: string;
  installedAs: string[];
  /** Every direct declaration of this version (each needs updating); empty if only transitive. */
  directAs: string[];
  /** Its parents/paths are incomplete (bounded graph work); say so instead of implying there are none. */
  contextTruncated: boolean;
  scope: Scope;
  isDirect: boolean;
  directParents: string[];
  advisories: { id: string; severity: Severity; title: string | null; fixStatus: FixStatus; candidateVersion: string | null }[];
  candidate: CandidateStep | null;
  /** When `candidate` is a major jump: the highest candidate that isn't, if it addresses some advisories. */
  compatibleCandidate: CandidateStep | null;
  /** Advisories no upgrade resolves (no fixed version published). */
  unresolved: string[];
  /** Advisories whose ranges don't place this version: see the advisory. */
  unplaced: string[];
  /**
   * Advisory data provides candidates, but none can be verified to address an advisory for this version.
   */
  noUsefulCandidate: boolean;
}

export interface Action {
  /** 1-based position in the plan. */
  rank: number;
  kind: ActionKind;
  ecosystem: EcosystemId;
  package: string;
  /** Highest severity among its advisories. */
  severity: Severity;
  isMalicious: boolean;
  /** Most exposed scope / any direct install, across installed versions. */
  scope: Scope;
  isDirect: boolean;
  advisoryCount: number;
  versions: ActionVersion[];
}

export const SUMMARY_ACTIONS = 3;

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
// "runtime before dev"; optional dependencies are installed at runtime too, so they sit with runtime.
const SCOPE_ORDER: Record<Scope, number> = { runtime: 0, optional: 1, dev: 2 };
const SCOPE_EXPOSURE: Record<Scope, number> = { runtime: 2, optional: 1, dev: 0 };

interface Rankable {
  isMalicious: boolean;
  severity: Severity;
  scope: Scope;
  isDirect: boolean;
  package: string;
}

/** Malicious first, then severity, then runtime before dev, then direct before transitive, then name. */
export function compareRank(a: Rankable, b: Rankable): number {
  return (
    Number(b.isMalicious) - Number(a.isMalicious) ||
    SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
    SCOPE_ORDER[a.scope] - SCOPE_ORDER[b.scope] ||
    Number(b.isDirect) - Number(a.isDirect) ||
    a.package.localeCompare(b.package)
  );
}

/** All findings in plan order (ties: version, then advisory id). */
export function rankFindings<F extends PlanFinding>(findings: readonly F[]): F[] {
  return [...findings].sort(
    (a, b) =>
      compareRank(a, b) || a.installedVersion.localeCompare(b.installedVersion) || a.advisoryId.localeCompare(b.advisoryId),
  );
}

function maxBy<T>(items: readonly T[], compare: (a: T, b: T) => number): T | undefined {
  return items.reduce<T | undefined>((best, x) => (best === undefined || compare(x, best) > 0 ? x : best), undefined);
}

function planVersion(installed: string, findings: PlanFinding[], scheme: VersionScheme | null): ActionVersion {
  const first = findings[0];
  const withCandidate = findings.filter(
    (f): f is PlanFinding & { candidateVersion: string } => f.fixStatus === 'candidate' && f.candidateVersion !== null,
  );
  /**
   * Whether `version` is still affected by advisory `f`. Ranges are checked one by one: an advisory can affect
   * several separate intervals, so "at or above its first fix" is not "unaffected". Without stored ranges
   * nothing can be checked, so the advisory counts as still affecting the version.
   */
  const affects = (f: PlanFinding, version: string): boolean =>
    scheme === null || f.affectedRanges === null || f.affectedRanges.some((r) => scheme.inRange(version, r));

  /**
   * From `start` (no lower version can address every advisory that has a candidate), move up to the fix of any
   * range that still contains the version, until none does or only ranges without a fix remain.
   * `allowJump: false` stops before a major-version jump.
   */
  const resolve = (start: string, allowJump: boolean): string => {
    if (!scheme) return start;
    let version = start;
    for (;;) {
      let next: string | null = null;
      for (const f of withCandidate) {
        for (const r of f.affectedRanges ?? []) {
          if (r.kind !== 'range' || r.fixed === null || !scheme.isValid(r.fixed) || !scheme.inRange(version, r)) continue;
          if (scheme.compare(r.fixed, version) > 0 && (next === null || scheme.compare(r.fixed, next) > 0)) next = r.fixed;
        }
      }
      if (next === null || (!allowJump && scheme.isMajorJump(installed, next))) return version;
      version = next; // strictly increasing over a finite set of fixed versions: terminates
    }
  };

  const step = (version: string): CandidateStep => ({
    version,
    addresses: withCandidate.filter((f) => !affects(f, version)).length,
    // Only what the stored ranges show; rows without ranges can't be checked either way.
    stillAffected: withCandidate.filter((f) => f.affectedRanges !== null && affects(f, version)).map((f) => f.advisoryId),
    majorJump: scheme ? scheme.isMajorJump(installed, version) : false,
  });

  let candidate: CandidateStep | null = null;
  let compatibleCandidate: CandidateStep | null = null;
  let noUsefulCandidate = false;
  if (scheme && withCandidate.length > 0) {
    const versions = withCandidate.map((f) => f.candidateVersion);
    const highest = maxBy(versions, (a, b) => scheme.compare(a, b));
    if (highest !== undefined) {
      candidate = step(resolve(highest, true));
      // Fall back to the candidate with the most verified improvements (lowest version on a tie).
      // Missing ranges do not count as a verified improvement.
      if (candidate.addresses === 0) {
        const options = [...new Set([...versions, ...versions.map((v) => resolve(v, true))])].map(step);
        const best = options.reduce<CandidateStep | null>(
          (b, o) =>
            o.addresses > 0 && (b === null || o.addresses > b.addresses || (o.addresses === b.addresses && scheme.compare(o.version, b.version) < 0))
              ? o
              : b,
          null,
        );
        candidate = best;
        noUsefulCandidate = best === null;
      }
    }
    if (candidate) {
      if (candidate.majorJump) {
        const compatible = maxBy(
          versions.filter((v) => !scheme.isMajorJump(installed, v)),
          (a, b) => scheme.compare(a, b),
        );
        if (compatible !== undefined) {
          const c = step(resolve(compatible, false));
          if (c.addresses > 0) compatibleCandidate = c;
        }
      }
    }
  }

  return {
    installedVersion: installed,
    installedAs: first?.installedAs ?? [],
    contextTruncated: findings.some((f) => f.contextTruncated === true),
    // Rows stored before direct_as existed: fall back to the package name when it was direct.
    directAs: first && first.directAs.length > 0 ? first.directAs : first?.isDirect ? [first.package] : [],
    scope: first?.scope ?? 'runtime',
    isDirect: first?.isDirect ?? false,
    directParents: first?.directParents ?? [],
    advisories: findings.map((f) => ({
      id: f.advisoryId,
      severity: f.severity,
      title: f.title,
      fixStatus: f.fixStatus,
      candidateVersion: f.candidateVersion,
    })),
    candidate,
    compatibleCandidate,
    unresolved: findings.filter((f) => f.fixStatus === 'no_fix').map((f) => f.advisoryId),
    unplaced: findings.filter((f) => f.fixStatus === 'unknown').map((f) => f.advisoryId),
    noUsefulCandidate,
  };
}

/**
 * Groups findings into one action per package (all installed versions together), ranked.
 * `schemeFor` gives the ecosystem's version scheme, or null when it has none.
 */
export function buildFixPlan(
  findings: readonly PlanFinding[],
  schemeFor: (ecosystem: EcosystemId) => VersionScheme | null,
): Action[] {
  const byPackage = Map.groupBy(rankFindings(findings), (f) => `${f.ecosystem}\u0000${f.package}`);

  const actions = [...byPackage.values()].flatMap((group): Omit<Action, 'rank'>[] => {
    const first = group[0];
    if (!first) return [];
    const scheme = schemeFor(first.ecosystem);
    const byVersion = Map.groupBy(group, (f) => f.installedVersion);
    const versions = [...byVersion.entries()]
      .map(([installed, fs]) => planVersion(installed, fs, scheme))
      .sort((a, b) =>
        scheme && scheme.isValid(a.installedVersion) && scheme.isValid(b.installedVersion)
          ? scheme.compare(a.installedVersion, b.installedVersion)
          : a.installedVersion.localeCompare(b.installedVersion),
      );

    const isMalicious = group.some((f) => f.isMalicious);
    const kind: ActionKind = isMalicious
      ? 'remove_malicious'
      : versions.some((v) => v.candidate)
        ? 'upgrade'
        : versions.every((v) => v.unplaced.length === 0 && !v.noUsefulCandidate)
          ? 'no_fix'
          : 'review';

    return [
      {
        kind,
        ecosystem: first.ecosystem,
        package: first.package,
        severity: group.reduce<Severity>((s, f) => (SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[s] ? f.severity : s), 'unknown'),
        isMalicious,
        scope: group.reduce<Scope>((s, f) => (SCOPE_EXPOSURE[f.scope] > SCOPE_EXPOSURE[s] ? f.scope : s), 'dev'),
        isDirect: group.some((f) => f.isDirect),
        advisoryCount: new Set(group.map((f) => f.advisoryId)).size,
        versions,
      },
    ];
  });

  return actions.sort(compareRank).map((a, i) => ({ ...a, rank: i + 1 }));
}
