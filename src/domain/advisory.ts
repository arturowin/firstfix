export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

/** An advisory as it applies to one npm package. Built by the vulnerability-database adapter. */
export interface Advisory {
  id: string;
  aliases: string[];
  title: string | null;
  severity: Severity;
  isMalicious: boolean;
  /** OSV `affected[].ranges` for this package only (raw events; interpreted in M2). */
  affectedRanges: unknown[];
  references: { type: string; url: string }[];
}

/**
 * GitHub's advisory label (OSV `database_specific.severity`). No CVSS parsing in this version:
 * anything else is 'unknown', which is shown, never hidden.
 */
export function severityFromLabel(label: unknown): Severity {
  if (typeof label !== 'string') return 'unknown';
  switch (label.toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MODERATE':
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'unknown';
  }
}

/** OpenSSF malicious-packages records. GitHub's own malware GHSAs are recognised by package grouping in M2. */
export function isMaliciousId(id: string): boolean {
  return id.startsWith('MAL-');
}
