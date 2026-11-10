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

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === 'string';
const optArrayOf = (v: unknown, item: (x: unknown) => boolean) => v === undefined || (Array.isArray(v) && v.every(item));
const optStr = (v: unknown) => v === undefined || isStr(v);

/**
 * Is this a record we can translate? Checked inside the fetch's retry/failure boundary, so a malformed record
 * fails only the packages citing it (like a failed fetch) instead of the whole lookup. Unknown extra fields
 * are fine; wrong shapes for the fields we read are not.
 */
export function isOsvVuln(v: unknown, expectedId: string): v is OsvVuln {
  if (!isObj(v) || v['id'] !== expectedId) return false;
  if (!optStr(v['summary']) || !optArrayOf(v['aliases'], isStr)) return false;
  if (!optArrayOf(v['references'], (r) => isObj(r) && optStr(r['type']) && optStr(r['url']))) return false;
  if (v['database_specific'] !== undefined && !isObj(v['database_specific'])) return false;
  return optArrayOf(v['affected'], (a) => {
    if (!isObj(a)) return false;
    const pkg = a['package'];
    if (pkg !== undefined && !(isObj(pkg) && optStr(pkg['ecosystem']) && optStr(pkg['name']))) return false;
    if (!optArrayOf(a['versions'], isStr)) return false;
    return optArrayOf(a['ranges'], (r) => {
      if (!isObj(r) || !optStr(r['type'])) return false;
      return optArrayOf(r['events'], (e) => {
        if (!isObj(e)) return false;
        return optStr(e['introduced']) && optStr(e['fixed']) && optStr(e['last_affected']) && optStr(e['limit']);
      });
    });
  });
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
 * closes it; one left open affects every later version. `limit` is an upper bound, not a fix: it closes the
 * range with `limit` set and no fixed version. An explicit `versions` list is kept too, even next to ranges. GIT ranges (commit hashes) say nothing about package versions: skipped.
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
      } else if (open !== null && (e.fixed !== undefined || e.last_affected !== undefined)) {
        out.push({ kind: 'range', introduced: open, fixed: e.fixed ?? null, lastAffected: e.last_affected ?? null });
        open = null;
      } else if (open !== null && e.limit !== undefined) {
        // A limit bounds the range but isn't a fix: keep the bound, leave the fix unknown.
        out.push({ kind: 'range', introduced: open, fixed: null, lastAffected: null, limit: e.limit });
        open = null;
      }
    }
    if (open !== null) out.push({ kind: 'range', introduced: open, fixed: null, lastAffected: null });
  }
  // OSV: a version is affected if it is in a range OR in the explicit list, so the list is kept alongside ranges.
  if (entry.versions && entry.versions.length > 0) {
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
