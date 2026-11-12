/**
 * The source check (docs/ARCHITECTURE.md "Source checks"): list the commit's tree, pick eligible files within the
 * limits, fetch them with bounded concurrency inside a time budget, and run the pure rules on each. File contents
 * live only in memory here; only matches (with bounded excerpts) are returned.
 *
 * Errors: a shared failure (lost access, repository gone, job cancelled) propagates unchanged. A single file
 * that can't be fetched is counted (partial coverage); none at all is a TransientError, retried like any other.
 */
import { bySourcePriority, DEFAULT_SOURCE_LIMITS, isTestPath, selectSourceFiles, type SourceLimits, type TreeEntry } from '../domain/source-files.ts';
import { isPartial, sourceRule } from '../domain/source-rules.ts';
import { scanSource } from '../domain/source-scan.ts';
import { PermanentError, TransientError } from '../ports/errors.ts';
import type { RepoAccess, RepoSource } from '../ports/repo-source.ts';
import type { SourceCheck, SourceFinding } from '../ports/scan-repository.ts';

export interface SourceCheckOptions {
  limits: SourceLimits;
  /** Files fetched at the same time. */
  concurrency: number;
  /** The whole check's time budget; files not reached in time are counted as skipped. */
  budgetMs: number;
  /** Matches stored per scan, highest priority first; every match is still counted per rule. */
  maxFindings: number;
}

export const DEFAULT_SOURCE_CHECK: SourceCheckOptions = { limits: DEFAULT_SOURCE_LIMITS, concurrency: 8, budgetMs: 60_000, maxFindings: 500 };

export interface SourceCheckInput {
  repo: { owner: string; name: string };
  access: RepoAccess;
  commitSha: string;
  treeSha: string;
}

export async function runSourceCheck(
  source: RepoSource,
  input: SourceCheckInput,
  options: SourceCheckOptions,
  signal: AbortSignal,
): Promise<{ check: SourceCheck; findings: SourceFinding[] }> {
  const listing = await source.listTree(input.repo, input.access, input.treeSha, signal);
  signal.throwIfAborted();
  const { selected, counts } = selectSourceFiles(listing.entries, options.limits, listing.truncated);
  if (counts.eligible === 0) {
    return { check: { status: listing.truncated ? 'partial' : 'no_files', counts, error: null }, findings: [] };
  }

  // Every match is counted per rule; only the highest-priority examples are kept (bounded memory, any fetch order).
  const perRule = new Map<string, { matches: number; files: Set<string>; inTestFiles: number }>();
  const kept: SourceFinding[] = [];
  const prune = () => {
    kept.sort(bySourcePriority);
    if (kept.length > options.maxFindings) kept.length = options.maxFindings;
  };
  const budget = AbortSignal.timeout(options.budgetMs);
  // Stops the remaining fetches once one of them hits a shared failure.
  const stop = new AbortController();
  const fetchSignal = AbortSignal.any([signal, budget, stop.signal]);
  let nextIndex = 0;

  const checkFile = async (entry: TreeEntry): Promise<void> => {
    let text: string | null;
    try {
      text = await source.readSourceFile(input.repo, input.access, input.commitSha, entry.path, options.limits.maxFileBytes, fetchSignal);
    } catch (err) {
      if (signal.aborted) throw err; // the job itself was cancelled
      if (budget.aborted) {
        counts.skippedTime++;
        return;
      }
      if (err instanceof PermanentError && err.code === 'source_file_too_large') {
        counts.skippedSize++;
        return;
      }
      if (err instanceof TransientError) {
        counts.fetchFailed++;
        return;
      }
      stop.abort(); // lost access, repository gone, or a bug: nothing else is worth fetching
      throw err;
    }
    if (text === null) {
      counts.fetchFailed++;
      return;
    }
    let scanned: ReturnType<typeof scanSource>;
    try {
      scanned = scanSource(text);
    } catch {
      // Defence in depth: no input may fail the scan. The file counts as not checked.
      counts.skippedParse++;
      return;
    }
    if (scanned.unparsed) {
      counts.skippedParse++;
      return;
    }
    counts.checked++;
    const test = isTestPath(entry.path);
    for (const m of scanned.matches) {
      const rule = sourceRule(m.ruleId, m.ruleVersion);
      if (!rule) continue;
      const tally = perRule.get(m.ruleId) ?? { matches: 0, files: new Set<string>(), inTestFiles: 0 };
      tally.matches++;
      tally.files.add(entry.path);
      if (test) tally.inTestFiles++;
      perRule.set(m.ruleId, tally);
      kept.push({ ruleId: m.ruleId, ruleVersion: m.ruleVersion, severity: rule.severity, path: entry.path, start: m.start, end: m.end, excerpt: m.excerpt });
      if (kept.length > 2 * options.maxFindings) prune();
    }
  };

  const worker = async (): Promise<void> => {
    for (;;) {
      const entry = selected[nextIndex++];
      if (!entry) return;
      signal.throwIfAborted(); // the job was cancelled: stop, don't count anything
      if (budget.aborted) {
        counts.skippedTime++;
        continue;
      }
      await checkFile(entry);
    }
  };
  await Promise.all(Array.from({ length: Math.min(options.concurrency, selected.length) }, worker));

  // Nothing could be read because of GitHub (every file failed to fetch or ran out of time): transient, retried.
  // Files that were read but couldn't be checked are not GitHub's fault: they make coverage partial instead.
  if (selected.length > 0 && counts.checked === 0 && counts.fetchFailed + counts.skippedTime === selected.length - counts.skippedSize) {
    // Nothing could be read: almost always GitHub being unavailable. Retried like any transient error.
    throw new TransientError(
      budget.aborted ? 'source_timeout' : 'source_fetch_failed',
      budget.aborted
        ? `GitHub did not deliver any of the ${String(selected.length)} source files within the time budget`
        : `None of the ${String(selected.length)} source files could be fetched from GitHub`,
    );
  }
  prune();
  const total = [...perRule.values()].reduce((n, r) => n + r.matches, 0);
  counts.findingsTruncated = total > kept.length;
  counts.rules = Object.fromEntries([...perRule].map(([id, r]) => [id, { matches: r.matches, files: r.files.size, inTestFiles: r.inTestFiles }]));
  const findings = kept;
  return { check: { status: isPartial(counts) ? 'partial' : 'complete', counts, error: null }, findings };
}
