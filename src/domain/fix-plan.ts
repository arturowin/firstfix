/**
 * Ranking and recommended next actions (docs/ARCHITECTURE.md "Ranking policy", "Recommended next actions").
 * Pure and deterministic: the same findings always give the same plan. Facts come from findings; versions are
 * candidates from advisory data, never "fixes".
 */
import type { Severity } from './advisory.ts';
import type { FixStatus } from './candidate.ts';
import type { EcosystemId, VersionScheme } from './ecosystems/types.ts';
import type { Scope } from './lockfile.ts';

/** What the plan needs from a stored finding (one package@version × advisory). */
export interface PlanFinding {
  ecosystem: EcosystemId;
  package: string;
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
  majorJump: boolean;
}

export interface ActionVersion {
  installedVersion: string;
  scope: Scope;
  isDirect: boolean;
  directParents: string[];
  advisories: { id: string; severity: Severity; title: string | null; fixStatus: FixStatus; candidateVersion: string | null }[];
  /** The highest per-advisory candidate: addresses every advisory that has one. */
  candidate: CandidateStep | null;
  /** When `candidate` is a major jump: the highest candidate that isn't, if it addresses some advisories. */
  compatibleCandidate: CandidateStep | null;
  /** Advisories no upgrade resolves (no fixed version published). */
  unresolved: string[];
  /** Advisories whose ranges don't place this version: see the advisory. */
  unplaced: string[];
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
  const step = (version: string): CandidateStep => ({
    version,
    addresses: scheme ? withCandidate.filter((f) => scheme.compare(f.candidateVersion, version) <= 0).length : 0,
    majorJump: scheme ? scheme.isMajorJump(installed, version) : false,
  });

  let candidate: CandidateStep | null = null;
  let compatibleCandidate: CandidateStep | null = null;
  if (scheme && withCandidate.length > 0) {
    const versions = withCandidate.map((f) => f.candidateVersion);
    const highest = maxBy(versions, (a, b) => scheme.compare(a, b));
    if (highest !== undefined) {
      candidate = step(highest);
      if (candidate.majorJump) {
        const compatible = maxBy(
          versions.filter((v) => !scheme.isMajorJump(installed, v)),
          (a, b) => scheme.compare(a, b),
        );
        if (compatible !== undefined) compatibleCandidate = step(compatible);
      }
    }
  }

  return {
    installedVersion: installed,
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
        : versions.every((v) => v.unplaced.length === 0)
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
