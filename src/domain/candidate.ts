/**
 * Candidate version for one advisory on one installed version (docs/ARCHITECTURE.md "Recommended next actions").
 * A candidate is what advisory data says is the first unaffected version; it is never presented as "fixed":
 * compatibility, resolution and tests still have to be verified, and only a rescan confirms.
 */
import type { AffectedRange } from './advisory.ts';
import type { VersionScheme } from './ecosystems/types.ts';

export type FixStatus =
  /** A candidate version exists. */
  | 'candidate'
  /** The installed version is affected and the advisory publishes no fixed version. */
  | 'no_fix'
  /** No version scheme for the ecosystem, or the ranges don't place the installed version: see the advisory. */
  | 'unknown';

export interface CandidateResult {
  status: FixStatus;
  version: string | null;
}

const UNKNOWN: CandidateResult = { status: 'unknown', version: null };
const NO_FIX: CandidateResult = { status: 'no_fix', version: null };

/**
 * The `fixed` version of the range that contains the installed version. If that candidate is itself inside
 * another affected range of the same advisory, follow that range's fix (e.g. ranges 1.0–1.5 and 1.5–1.8
 * written separately). Any containing range without a fix means no upgrade is known to help.
 */
export function selectCandidate(
  installed: string,
  ranges: readonly AffectedRange[],
  scheme: VersionScheme | null,
): CandidateResult {
  if (!scheme || !scheme.isValid(installed)) return UNKNOWN;

  const containing = (v: string) => ranges.filter((r) => scheme.inRange(v, r));
  let current = installed;
  let hits = containing(current);
  if (hits.length === 0) return UNKNOWN; // provider says affected but its ranges don't say why: don't guess

  // Each step moves strictly upwards, so this ends after at most ranges.length steps.
  for (let step = 0; step <= ranges.length; step++) {
    let next: string | null = null;
    for (const r of hits) {
      if (r.kind === 'versions' || r.fixed === null || !scheme.isValid(r.fixed)) return NO_FIX;
      if (next === null || scheme.compare(r.fixed, next) > 0) next = r.fixed;
    }
    if (next === null || scheme.compare(next, current) <= 0) return NO_FIX;
    current = next;
    hits = containing(current);
    if (hits.length === 0) return { status: 'candidate', version: current };
  }
  return NO_FIX;
}
