/**
 * The source-check rule catalog (docs/ARCHITECTURE.md "Source checks"). Explanations and next actions are
 * deterministic text looked up by rule id and version; a stored finding keeps the version it was found with.
 * These are targeted textual checks: a match never proves that the code runs or that it can be exploited.
 */
export type SourceRuleId = 'FF-TLS-001' | 'FF-TLS-002';
export type SourceSeverity = 'high' | 'medium';

export interface SourceRule {
  id: SourceRuleId;
  version: number;
  severity: SourceSeverity;
  title: string;
  explanation: string;
  nextAction: string;
}

export const SOURCE_RULES: readonly SourceRule[] = [
  {
    id: 'FF-TLS-001',
    version: 1,
    severity: 'high',
    title: 'TLS certificate verification disabled for the whole process',
    explanation:
      'Setting NODE_TLS_REJECT_UNAUTHORIZED to "0" makes Node.js accept any certificate on every HTTPS or TLS connection the process opens, if this line runs. Someone on the network path could then read or change that traffic.',
    nextAction:
      'Remove this assignment. If a server uses a private or self-signed certificate, trust its CA instead (NODE_EXTRA_CA_CERTS, or the `ca` option of the client). If it is only for local development, make sure it can never run in production.',
  },
  {
    id: 'FF-TLS-002',
    version: 1,
    severity: 'medium',
    title: 'TLS certificate verification turned off for a client',
    explanation:
      'rejectUnauthorized: false makes the TLS or HTTPS client or agent it configures accept any certificate, so its connections can be intercepted. This is often meant for development or tests: review where this configuration is used.',
    nextAction:
      'Remove the option or set it to true (the default), and trust the server’s CA with the `ca` option if it uses a private certificate. If the code only runs in tests, confirm it can’t reach production.',
  },
];

/** The rule a stored finding refers to; null for an id or version this code doesn't know (shown generically). */
export function sourceRule(id: string, version: number): SourceRule | null {
  return SOURCE_RULES.find((r) => r.id === id && r.version === version) ?? null;
}

export type SourceCheckStatus = 'complete' | 'partial' | 'no_files' | 'failed';

/** What the source check covered. Counts are of JavaScript/TypeScript files. */
export interface SourceCounts {
  /** Eligible files in the repository (extension, not excluded). */
  eligible: number;
  /** Files actually read and checked. */
  checked: number;
  /** Not checked: over the file-count or total-size limit. */
  skippedLimit: number;
  /** Not checked: a single file over the per-file size limit. */
  skippedSize: number;
  /** Not followed: symbolic links and submodules. */
  skippedLinks: number;
  /** Not checked: the check's time budget ran out. */
  skippedTime: number;
  /** Could not be fetched from GitHub. */
  fetchFailed: number;
  /** Fetched but not checked: could not be read as code (e.g. nesting beyond the tokenizer's limit). */
  skippedParse: number;
  /** GitHub cut the file listing short (very large repository). */
  listingTruncated: boolean;
  /** More matches than are stored; the rest are not shown (they are still counted in `rules`). */
  findingsTruncated: boolean;
  /**
   * Every match found, per rule: counted before any storage limit, so a rule never reads as "no match" because
   * its examples were dropped. Absent on scans from before this was recorded (counts come from stored findings).
   */
  rules?: Record<string, { matches: number; files: number; inTestFiles: number }>;
}

export const NO_SOURCE_COUNTS: SourceCounts = {
  eligible: 0,
  checked: 0,
  skippedLimit: 0,
  skippedSize: 0,
  skippedLinks: 0,
  skippedTime: 0,
  fetchFailed: 0,
  skippedParse: 0,
  listingTruncated: false,
  findingsTruncated: false,
};

/**
 * Coverage is partial when an eligible file may have gone unchecked. Matches beyond the storage cap don't make it
 * partial (every file was checked); the summary says more were found than are shown.
 */
export function isPartial(c: SourceCounts): boolean {
  return c.skippedLimit + c.skippedSize + c.skippedTime + c.fetchFailed + c.skippedParse > 0 || c.listingTruncated;
}

const plural = (n: number, one: string, many: string) => `${String(n)} ${n === 1 ? one : many}`;

/**
 * The deterministic one-line source summary. Never says "secure": a clean result is "no issues found by the
 * supported checks", and a scan from before source checks says they were not run.
 */
export function sourceSummaryLine(
  source: { status: SourceCheckStatus; counts: SourceCounts; error: { message: string } | null } | null,
  findings: readonly { severity: SourceSeverity }[],
): string {
  if (source === null) return 'Source checks were not run for this scan.';
  const { status, counts } = source;
  if (status === 'failed') return `Source checks failed: ${source.error?.message ?? 'unknown error'}`;
  if (status === 'no_files') return 'Source checks: no JavaScript/TypeScript files to check.';
  const scope = `${String(counts.checked)} of ${plural(counts.eligible, 'JavaScript/TypeScript file', 'JavaScript/TypeScript files')}`;
  const prefix = status === 'partial' ? 'Partial source check: ' : 'Source checks: ';
  // Every match counts, also those whose examples weren't stored; older scans only have the stored findings.
  const totals = counts.rules
    ? SOURCE_RULES.map((r) => ({ severity: r.severity, matches: counts.rules?.[r.id]?.matches ?? 0 }))
    : findings.map((f) => ({ severity: f.severity, matches: 1 }));
  const high = totals.filter((t) => t.severity === 'high').reduce((n, t) => n + t.matches, 0);
  const total = totals.reduce((n, t) => n + t.matches, 0);
  const medium = total - high;
  if (total === 0) return `${prefix}no issues found by the ${String(SOURCE_RULES.length)} supported checks in ${scope}.`;
  const parts = [high > 0 ? `${String(high)} high` : '', medium > 0 ? `${String(medium)} medium` : ''].filter(Boolean).join(', ');
  const more = counts.findingsTruncated ? ' More matches were found than are shown.' : '';
  return `${prefix}${plural(total, 'finding', 'findings')} (${parts}) in ${scope}.${more}`;
}
