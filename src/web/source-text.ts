/**
 * Short wording about the source check for places outside its own section: the report headline and the
 * source badge. Pure, so it is unit-tested apart from the DOM.
 */

export interface SourceResultJson {
  status: 'complete' | 'partial' | 'no_files' | 'failed' | null;
  counts?: { checked: number } | null;
  findings: { severity: 'high' | 'medium'; testFile: boolean }[];
  rules?: { severity: 'high' | 'medium'; matches: number; inTestFiles: number }[];
}

export type Tone = 'ok' | 'warn' | 'danger' | 'muted';

export interface SourceTotals {
  total: number;
  high: number;
  inTests: number;
}

/** Every match found (per-rule counts), not just the examples shown; older scans only have the stored findings. */
export function sourceTotals(src: SourceResultJson): SourceTotals {
  if (src.rules) {
    return {
      total: src.rules.reduce((n, r) => n + r.matches, 0),
      high: src.rules.filter((r) => r.severity === 'high').reduce((n, r) => n + r.matches, 0),
      inTests: src.rules.reduce((n, r) => n + r.inTestFiles, 0),
    };
  }
  return {
    total: src.findings.length,
    high: src.findings.filter((f) => f.severity === 'high').length,
    inTests: src.findings.filter((f) => f.testFile).length,
  };
}

const findings = (n: number) => `${String(n)} ${n === 1 ? 'finding' : 'findings'}`;

/** Where the matches are, when any are in test files: "all in test files", "2 in test files", or nothing. */
function whereInTests({ total, inTests }: SourceTotals): string | null {
  if (inTests === 0) return null;
  if (inTests >= total) return total === 1 ? 'in a test file' : 'all in test files';
  return inTests === 1 ? '1 in a test file' : `${String(inTests)} in test files`;
}

/** The source badge when there are matches: "3 findings", or "3 findings · all in tests". */
export function sourceBadgeLabel(totals: SourceTotals): string {
  const label = findings(totals.total);
  if (totals.inTests === 0) return label;
  return totals.inTests >= totals.total ? `${label} · all in tests` : `${label} · ${String(totals.inTests)} in tests`;
}

/**
 * Where the source check stands, as a short label and a colour. Never "secure", and green only for a complete
 * check with no matches: no matches in a partial check, or in no files at all, is not a clean result.
 */
export function sourceBadge(src: SourceResultJson | null | undefined): { label: string; tone: Tone } {
  if (!src || src.status === null) return { label: 'Not run', tone: 'muted' };
  if (src.status === 'failed') return { label: 'Check failed', tone: 'danger' };
  if (src.status === 'no_files') return { label: 'No JS/TS files', tone: 'muted' };
  const totals = sourceTotals(src);
  // Severity sets the colour even in tests; the label says where the matches are.
  if (totals.total > 0) return { label: sourceBadgeLabel(totals), tone: totals.high > 0 ? 'danger' : 'warn' };
  if (src.counts?.checked === 0) return { label: 'No files checked', tone: 'warn' };
  if (src.status === 'partial') return { label: 'No findings in checked files', tone: 'warn' };
  return { label: 'No issues found', tone: 'ok' };
}

/**
 * A sentence added to a dependency headline when the source check found something, so a clean dependency
 * result never reads as clean overall. Empty when there is nothing to add: no source result, no matches,
 * or a check that didn't run (the source card says why).
 */
export function sourceHeadline(src: SourceResultJson | null | undefined): string {
  if (!src || (src.status !== 'complete' && src.status !== 'partial')) return '';
  const totals = sourceTotals(src);
  if (totals.total === 0) return '';
  const where = whereInTests(totals);
  return ` Source checks: ${findings(totals.total)}${where ? `, ${where}` : ''}.`;
}
