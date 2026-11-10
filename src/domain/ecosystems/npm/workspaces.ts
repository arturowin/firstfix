/**
 * Which folders are this project's workspaces, from the root entry's `workspaces` field (an array of globs, or
 * `{ packages: [...] }`). Only links into these are project code; any other `link: true` entry (e.g. a
 * `file:../local` dependency) is a real dependency from a non-registry source.
 *
 * Glob syntax: a whole `**` segment matches zero or more path segments; `*` inside a segment matches any run of
 * characters except `/`; everything else is literal. No regular expressions: the patterns come from an
 * untrusted lockfile, and a crafted one (e.g. `*a*a*a…b`) could make a backtracking regex run for seconds.
 *
 * Work bound: every character comparison counts against one budget shared by all patterns and all locations
 * asked about (MAX_MATCH_WORK), results are cached per location, and patterns are capped in number and length.
 * Segment matching is the linear-backtrack wildcard algorithm (at most pattern × text steps per segment), and
 * the segment-level `**` matching is a table of pattern segments × path segments, so a single match is
 * polynomially bounded and the budget bounds the total. Once the budget runs out, the answer is "not a
 * workspace": the link is then reported as an unchecked dependency, never hidden.
 */

/** Total character comparisons for one lockfile, across all patterns and locations. */
export const MAX_MATCH_WORK = 1_000_000;
const MAX_PATTERNS = 1000;
const MAX_PATTERN_LENGTH = 1024;

function patternsOf(root: unknown): string[] {
  if (typeof root !== 'object' || root === null) return [];
  const ws = (root as Record<string, unknown>)['workspaces'];
  const list = Array.isArray(ws)
    ? ws
    : typeof ws === 'object' && ws !== null && Array.isArray((ws as Record<string, unknown>)['packages'])
      ? ((ws as Record<string, unknown>)['packages'] as unknown[])
      : [];
  // Patterns over the limits are ignored: matching nothing means "report as a dependency", the safe side.
  return list
    .filter((p): p is string => typeof p === 'string' && p.length > 0 && p.length <= MAX_PATTERN_LENGTH)
    .slice(0, MAX_PATTERNS);
}

/** "./packages/*" and "packages/*\/" both mean "packages/*". Empty segments (a//b) are dropped. */
function segments(path: string): string[] {
  return path
    .replace(/^\.\//, '')
    .split('/')
    .filter((s) => s !== '' && s !== '.');
}

interface Budget {
  left: number;
}

/** Spends `n` units; false once the budget is gone. */
function spend(budget: Budget, n: number): boolean {
  budget.left -= n;
  return budget.left >= 0;
}

/**
 * One segment against one pattern segment with `*` wildcards (no `/` in either). Greedy with a single
 * backtrack point: each step advances the text or the star position, so it is O(pattern × text) at worst,
 * and every step is paid for from the budget. Returns null when the budget runs out.
 */
function matchSegment(pattern: string, text: string, budget: Budget): boolean | null {
  let p = 0;
  let t = 0;
  let star = -1;
  let afterStar = 0;
  while (t < text.length) {
    if (!spend(budget, 1)) return null;
    if (p < pattern.length && pattern[p] !== '*' && pattern[p] === text[t]) {
      p++;
      t++;
    } else if (p < pattern.length && pattern[p] === '*') {
      star = p++;
      afterStar = t;
    } else if (star !== -1) {
      p = star + 1;
      t = ++afterStar;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === '*') p++;
  return p === pattern.length;
}

/**
 * Pattern segments against path segments, where a `**` segment matches zero or more path segments.
 * Dynamic programming over (pattern index, path index), (P + 1) x (S + 1) cells. The whole table's cost is
 * charged to the budget before anything is allocated, and only two rows of S + 1 cells are kept, so working
 * memory is O(S) and bounded by the budget. Returns null when the budget can't cover it.
 */
function matchPath(pattern: string[], path: string[], budget: Budget): boolean | null {
  const P = pattern.length;
  const S = path.length;
  if (!spend(budget, (P + 1) * (S + 1))) return null; // can't afford it: decide before allocating
  // next[j]: pattern[i+1..] matches path[j..]; cur[j]: pattern[i..] matches path[j..]. Filled from the end.
  let next = new Uint8Array(S + 1);
  let cur = new Uint8Array(S + 1);
  next[S] = 1;
  for (let i = P - 1; i >= 0; i--) {
    const seg = pattern[i] ?? '';
    for (let j = S; j >= 0; j--) {
      let ok = false;
      if (seg === '**') {
        // zero segments, or consume this path segment and stay on `**`
        ok = next[j] === 1 || (j < S && cur[j + 1] === 1);
      } else if (j < S && next[j + 1] === 1) {
        const m = matchSegment(seg, path[j] ?? '', budget);
        if (m === null) return null;
        ok = m;
      }
      cur[j] = ok ? 1 : 0;
    }
    [next, cur] = [cur, next];
  }
  return next[0] === 1;
}

export function workspaceMatcher(rootEntry: unknown): (location: string) => boolean {
  const patterns = patternsOf(rootEntry).map(segments);
  const budget: Budget = { left: MAX_MATCH_WORK };
  const cache = new Map<string, boolean>();

  return (location) => {
    const cached = cache.get(location);
    if (cached !== undefined) return cached;
    let result = false;
    const path = segments(location);
    // The project root and anything outside the repository are never workspaces.
    if (location !== '' && path.length > 0 && !path.includes('..')) {
      for (const pattern of patterns) {
        if (budget.left <= 0) break; // spent: "not a workspace" without starting (or allocating) anything
        const m = matchPath(pattern, path, budget);
        if (m === null) break; // budget gone: "not a workspace", so the link is reported, not hidden
        if (m) {
          result = true;
          break;
        }
      }
    }
    cache.set(location, result);
    return result;
  };
}
