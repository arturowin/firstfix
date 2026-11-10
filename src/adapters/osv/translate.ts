/**
 * OSV record → provider-neutral Advisory. All OSV-specific knowledge (event syntax, severity labels,
 * malicious markers, ecosystem names) stays in this adapter.
 */
import type { Advisory, AffectedRange, Severity } from '../../domain/advisory.ts';

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}
export interface OsvAffected {
  package?: { ecosystem?: string; name?: string };
  ranges?: { type?: string; events?: OsvEvent[] }[];
  versions?: string[];
}
export interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  references?: { type?: string; url?: string }[];
  database_specific?: { severity?: unknown; cwe_ids?: unknown };
  affected?: OsvAffected[];
}

/** CWE-506 "Embedded Malicious Code": how GitHub marks its malware advisories (e.g. GHSA-9x64-5r7x-2q53). */
const MALICIOUS_CWE = 'CWE-506';

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

/** OpenSSF malicious-packages records (`MAL-` ids), or a GitHub advisory tagged with CWE-506. */
export function isMalicious(v: OsvVuln): boolean {
  if (v.id.startsWith('MAL-')) return true;
  const cwes = v.database_specific?.cwe_ids;
  return Array.isArray(cwes) && cwes.includes(MALICIOUS_CWE);
}

/**
 * OSV events, in order, → ranges. Each `introduced` opens a range; the next `fixed` or `last_affected`
 * closes it; one left open affects every later version. `limit` is a search bound, not a fix: it closes the
 * range without a fixed version. GIT ranges (commit hashes) say nothing about package versions: skipped.
 */
export function toRanges(entry: OsvAffected): AffectedRange[] {
  const out: AffectedRange[] = [];
  for (const range of entry.ranges ?? []) {
    if (range.type === 'GIT') continue;
    let open: string | null = null;
    for (const e of range.events ?? []) {
      if (e.introduced !== undefined) {
        if (open !== null) out.push({ kind: 'range', introduced: open, fixed: null, lastAffected: null });
        open = e.introduced;
      } else if (open !== null && (e.fixed !== undefined || e.last_affected !== undefined || e.limit !== undefined)) {
        out.push({ kind: 'range', introduced: open, fixed: e.fixed ?? null, lastAffected: e.last_affected ?? null });
        open = null;
      }
    }
    if (open !== null) out.push({ kind: 'range', introduced: open, fixed: null, lastAffected: null });
  }
  // Entries without usable ranges may list the affected versions explicitly.
  if (out.length === 0 && entry.versions && entry.versions.length > 0) {
    out.push({ kind: 'versions', versions: [...entry.versions] });
  }
  return out;
}

/** Only the parts of an OSV record that apply to this package (same ecosystem, exact name). */
export function toAdvisory(v: OsvVuln, pkg: { ecosystem: string; name: string }): Advisory {
  const ranges = (v.affected ?? [])
    .filter((a) => a.package?.ecosystem === pkg.ecosystem && a.package.name === pkg.name)
    .flatMap(toRanges);
  return {
    id: v.id,
    aliases: v.aliases ?? [],
    title: v.summary ?? null,
    severity: severityFromLabel(v.database_specific?.severity),
    isMalicious: isMalicious(v),
    affectedRanges: ranges,
    references: (v.references ?? []).flatMap((r) => (typeof r.url === 'string' ? [{ type: r.type ?? 'WEB', url: r.url }] : [])),
  };
}
