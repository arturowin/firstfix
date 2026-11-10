import semver from 'semver';
import type { VersionScheme } from '../types.ts';

const parse = (v: string) => semver.parse(v);

/** npm versions are SemVer; "compatible" means what a caret range allows. */
export const npmVersionScheme: VersionScheme = {
  isValid: (v) => parse(v) !== null,

  compare: (a, b) => semver.compare(a, b),

  // ^ semantics: the leftmost non-zero part must stay the same (1.2→2.0, 0.3→0.4 and 0.0.3→0.0.4 are jumps).
  // Only moving up can be a jump.
  isMajorJump: (from, to) => semver.gt(to, from) && !semver.satisfies(to, `^${from}`, { includePrerelease: true }),

  inRange(version, range) {
    const v = parse(version);
    if (!v) return false;
    if (range.kind === 'versions') return range.versions.some((x) => parse(x)?.compare(v) === 0);
    if (range.introduced !== '0') {
      const lo = parse(range.introduced);
      if (!lo || v.compare(lo) < 0) return false;
    }
    // OSV limits: affected only if below at least one; "*" (or none) = unlimited. Older stored rows carry one
    // `limit`. An unparseable limit can't be evaluated, so it doesn't narrow the range (never hides an affected
    // version).
    const limits = range.limits ?? (range.limit != null ? [range.limit] : []);
    if (limits.length > 0 && !limits.includes('*')) {
      const parsed = limits.map(parse).filter((l): l is semver.SemVer => l !== null);
      if (parsed.length === limits.length && !parsed.some((l) => v.compare(l) < 0)) return false;
    }
    if (range.fixed !== null) {
      const fixed = parse(range.fixed);
      return fixed !== null && v.compare(fixed) < 0;
    }
    if (range.lastAffected !== null) {
      const last = parse(range.lastAffected);
      return last !== null && v.compare(last) <= 0;
    }
    return true; // open range: every later version is affected
  },
};
