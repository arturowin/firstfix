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
 * closes it; one left open affects every later version. `limit` events bound the whole range (OSV: affected only
 * below some limit; "*" = unlimited) and are never a fix. An explicit `versions` list is kept too, even next to
 * ranges. GIT ranges (commit hashes) say nothing about package versions: skipped.
 */
/** How an ecosystem orders versions; used to put a range's events in version order. */
export interface VersionOrder {
  isValid(version: string): boolean;
  compare(a: string, b: string): number;
}

/**
 * Events in version order (OSV evaluates them sorted, whatever order the record lists them in). "0" is the
 * lowest; ties keep their listed order. If any version can't be ordered (or no ordering is known for the
 * ecosystem), the listed order is kept rather than guessed.
 */
function sortedEvents(events: OsvEvent[], order: VersionOrder | null): OsvEvent[] {
  if (!order) return events;
  // Limits apply to the whole range wherever they appear: kept aside so the comparison below is a total order.
  const limits = events.filter((e) => e.introduced === undefined && e.fixed === undefined && e.last_affected === undefined);
  const keyed = events
    .map((e, index) => ({ e, index, v: e.introduced ?? e.fixed ?? e.last_affected }))
    .filter((k): k is { e: OsvEvent; index: number; v: string } => k.v !== undefined);
  if (!keyed.every((k) => k.v === '0' || order.isValid(k.v))) return events;
  const rank = (v: string, w: string): number => (v === w ? 0 : v === '0' ? -1 : w === '0' ? 1 : order.compare(v, w));
  return [...keyed.sort((a, b) => rank(a.v, b.v) || a.index - b.index).map((k) => k.e), ...limits];
}

export function toRanges(entry: OsvAffected, order: VersionOrder | null = null): AffectedRange[] {
  const out: AffectedRange[] = [];
  for (const range of entry.ranges ?? []) {
    if (range.type === 'GIT') continue;
    const events = sortedEvents(range.events ?? [], order);
    // OSV evaluation: `limit` events apply to the whole range (every interval in it), not just the interval
    // they follow; a version is affected only if it is below at least one limit; "*" means unlimited.
    const limitEvents = events.flatMap((e) => (e.limit !== undefined ? [e.limit] : []));
    const limits = limitEvents.length === 0 || limitEvents.includes('*') ? null : limitEvents;
    const interval = (introduced: string, fixed: string | null, lastAffected: string | null): AffectedRange =>
      limits === null
        ? { kind: 'range', introduced, fixed, lastAffected }
        : { kind: 'range', introduced, fixed, lastAffected, limits: [...limits] };
    let open: string | null = null;
    for (const e of events) {
      if (e.introduced !== undefined) {
        if (open !== null) out.push(interval(open, null, null));
        open = e.introduced;
      } else if (open !== null && (e.fixed !== undefined || e.last_affected !== undefined)) {
        out.push(interval(open, e.fixed ?? null, e.last_affected ?? null));
        open = null;
      }
      // A `limit` event closes nothing: it bounds the whole range (above).
    }
    if (open !== null) out.push(interval(open, null, null));
  }
  // OSV: a version is affected if it is in a range OR in the explicit list, so the list is kept alongside ranges.
  if (entry.versions && entry.versions.length > 0) {
    out.push({ kind: 'versions', versions: [...entry.versions] });
  }
  return out;
}

/** Only the parts of an OSV record that apply to this package (same ecosystem, exact name). */
export function toAdvisory(v: OsvVuln, pkg: { ecosystem: string; name: string }, order: VersionOrder | null = null): Advisory {
  const ranges = (v.affected ?? [])
    .filter((a) => a.package?.ecosystem === pkg.ecosystem && a.package.name === pkg.name)
    .flatMap((a) => toRanges(a, order));
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
