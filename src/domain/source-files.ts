/**
 * Which repository files the source check reads (docs/ARCHITECTURE.md "Source checks"). Pure: a tree listing
 * in, a bounded selection and the counts of what was left out.
 */
import type { SourceCounts } from './source-rules.ts';
import { NO_SOURCE_COUNTS } from './source-rules.ts';

export interface TreeEntry {
  path: string;
  /** "blob", "tree" or "commit" (a submodule). */
  type: string;
  /** Git file mode: "100644"/"100755" files, "120000" symbolic link, "160000" submodule. */
  mode: string;
  /** Bytes, for blobs; null when GitHub didn't say. */
  size: number | null;
  /** The blob SHA: content-addressed, so reading it is pinned to the scanned commit. */
  sha: string;
}

export interface SourceLimits {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
}

export const DEFAULT_SOURCE_LIMITS: SourceLimits = { maxFiles: 200, maxFileBytes: 256 * 1024, maxTotalBytes: 10 * 1024 * 1024 };

const EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx'];

/** Dependency, generated and build output directories, excluded wherever they appear in a path. */
export const EXCLUDED_DIRECTORIES = new Set([
  'node_modules', 'bower_components', 'jspm_packages', 'vendor', 'dist', 'build', 'out', 'coverage',
  '.next', '.nuxt', '.svelte-kit', '.output', '.vercel', '.turbo', '.cache', '.yarn', 'storybook-static',
  'generated', '__generated__',
]);

/** A JavaScript/TypeScript source file we check: by extension, not a declaration/minified/bundle file, not excluded. */
export function isEligiblePath(path: string): boolean {
  const lower = path.toLowerCase();
  if (!EXTENSIONS.some((ext) => lower.endsWith(ext))) return false;
  if (lower.endsWith('.d.ts') || lower.endsWith('.min.js') || lower.endsWith('.bundle.js')) return false;
  const dirs = lower.split('/').slice(0, -1);
  return !dirs.some((d) => EXCLUDED_DIRECTORIES.has(d));
}

/**
 * Which stored examples come first when there are more matches than are kept: higher severity, then code
 * outside tests, then path, line and column. Deterministic, whatever order files were fetched in.
 */
export function bySourcePriority(
  a: { severity: string; path: string; start: { line: number; column: number } },
  b: { severity: string; path: string; start: { line: number; column: number } },
): number {
  const sev = (s: string) => (s === 'high' ? 0 : 1);
  return (
    sev(a.severity) - sev(b.severity) ||
    Number(isTestPath(a.path)) - Number(isTestPath(b.path)) ||
    (a.path < b.path ? -1 : a.path > b.path ? 1 : 0) ||
    a.start.line - b.start.line ||
    a.start.column - b.start.column
  );
}

/** Test code: still checked, but labelled, since TLS shortcuts there are common and lower risk. */
export function isTestPath(path: string): boolean {
  const lower = path.toLowerCase();
  const segments = lower.split('/');
  const file = segments.at(-1) ?? '';
  return (
    segments.slice(0, -1).some((d) => d === 'test' || d === 'tests' || d === '__tests__' || d === '__mocks__') ||
    /\.(test|spec)\.[cm]?[jt]sx?$/.test(file)
  );
}

/**
 * Eligible files in path order, taken until a limit is reached. Over-size files are skipped from the listing's
 * size without fetching. Symbolic links and submodules are never followed, only counted.
 */
export function selectSourceFiles(
  entries: readonly TreeEntry[],
  limits: SourceLimits,
  listingTruncated: boolean,
): { selected: TreeEntry[]; counts: SourceCounts } {
  const counts: SourceCounts = { ...NO_SOURCE_COUNTS, listingTruncated };
  const candidates: TreeEntry[] = [];
  for (const e of entries) {
    if (e.type === 'commit' || e.mode === '160000') {
      counts.skippedLinks++;
      continue;
    }
    if (e.type !== 'blob' || !isEligiblePath(e.path)) continue;
    if (e.mode === '120000') {
      counts.skippedLinks++;
      continue;
    }
    candidates.push(e);
  }
  candidates.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  counts.eligible = candidates.length;

  const selected: TreeEntry[] = [];
  let total = 0;
  for (const e of candidates) {
    const size = e.size ?? 0;
    if (size > limits.maxFileBytes) {
      counts.skippedSize++;
      continue;
    }
    if (selected.length >= limits.maxFiles || total + size > limits.maxTotalBytes) {
      counts.skippedLimit++;
      continue;
    }
    selected.push(e);
    total += size;
  }
  return { selected, counts };
}
