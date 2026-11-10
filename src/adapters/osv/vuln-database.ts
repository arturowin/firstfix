import { isMaliciousId, severityFromLabel, type Advisory } from '../../domain/advisory.ts';
import { TransientError } from '../../ports/errors.ts';
import { packageKey, type AdvisoryLookup, type PackageRef, type VulnDatabase } from '../../ports/vuln-database.ts';
import { fetchWithTimeout, USER_AGENT } from '../http.ts';

export interface OsvOptions {
  baseUrl?: string;
  timeoutMs?: number;
  /** OSV's documented maximum is 1000 queries per batch. */
  batchSize?: number;
  detailConcurrency?: number;
}

interface BatchQuery {
  package: { ecosystem: string; name: string };
  version: string;
  page_token?: string;
}
interface BatchResult {
  vulns?: { id: string }[];
  next_page_token?: string;
}
interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  references?: { type?: string; url?: string }[];
  database_specific?: { severity?: unknown };
  affected?: { package?: { ecosystem?: string; name?: string }; ranges?: unknown[] }[];
}

/** OSV.dev: querybatch for ids (chunked, paginated per query), then one detail call per unique id. */
export class OsvVulnDatabase implements VulnDatabase {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly batchSize: number;
  private readonly detailConcurrency: number;

  constructor(options: OsvOptions = {}) {
    this.baseUrl = options.baseUrl ?? 'https://api.osv.dev';
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.batchSize = options.batchSize ?? 1000;
    this.detailConcurrency = options.detailConcurrency ?? 8;
  }

  async lookup(packages: PackageRef[], signal: AbortSignal): Promise<AdvisoryLookup> {
    const idsByPackage = await this.queryIds(packages, signal);

    const uniqueIds = [...new Set([...idsByPackage.values()].flat())].sort();
    const details = new Map<string, OsvVuln>();
    await mapWithConcurrency(uniqueIds, this.detailConcurrency, async (id) => {
      details.set(id, await this.fetchVuln(id, signal));
    });

    const result: AdvisoryLookup = new Map();
    for (const pkg of packages) {
      const ids = idsByPackage.get(packageKey(pkg)) ?? [];
      if (ids.length === 0) continue;
      result.set(
        packageKey(pkg),
        ids.map((id) => toAdvisory(details.get(id) ?? { id }, pkg)),
      );
    }
    return result;
  }

  private async queryIds(packages: PackageRef[], signal: AbortSignal): Promise<Map<string, string[]>> {
    const ids = new Map<string, string[]>();
    let pending: { pkg: PackageRef; pageToken?: string }[] = packages.map((pkg) => ({ pkg }));

    // Each round sends at most batchSize queries; queries that returned a page token go into the next round.
    while (pending.length > 0) {
      const next: typeof pending = [];
      for (let i = 0; i < pending.length; i += this.batchSize) {
        const chunk = pending.slice(i, i + this.batchSize);
        const queries: BatchQuery[] = chunk.map(({ pkg, pageToken }) => ({
          // Our ecosystem ids are OSV's names, so they pass through unchanged.
          package: { ecosystem: pkg.ecosystem, name: pkg.name },
          version: pkg.version,
          ...(pageToken ? { page_token: pageToken } : {}),
        }));
        const res = await this.post('/v1/querybatch', { queries }, signal);
        const body = (await res.json()) as { results?: BatchResult[] };
        if (!Array.isArray(body.results) || body.results.length !== chunk.length) {
          throw new TransientError('osv_bad_response', 'OSV returned a batch result that does not match the query');
        }
        body.results.forEach((r, j) => {
          const entry = chunk[j];
          if (!entry) return;
          const key = packageKey(entry.pkg);
          const list = ids.get(key) ?? [];
          for (const v of r.vulns ?? []) if (!list.includes(v.id)) list.push(v.id);
          ids.set(key, list);
          if (r.next_page_token) next.push({ pkg: entry.pkg, pageToken: r.next_page_token });
        });
      }
      pending = next;
    }
    return ids;
  }

  private async fetchVuln(id: string, signal: AbortSignal): Promise<OsvVuln> {
    const res = await this.request(`/v1/vulns/${encodeURIComponent(id)}`, { method: 'GET' }, signal);
    return (await res.json()) as OsvVuln;
  }

  private post(path: string, body: unknown, signal: AbortSignal): Promise<Response> {
    return this.request(
      path,
      { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } },
      signal,
    );
  }

  private async request(path: string, init: RequestInit, signal: AbortSignal): Promise<Response> {
    const res = await fetchWithTimeout(`${this.baseUrl}${path}`, {
      ...init,
      headers: { ...(init.headers as Record<string, string> | undefined), 'user-agent': USER_AGENT },
      timeoutMs: this.timeoutMs,
      signal,
      service: 'osv',
    });
    if (!res.ok) {
      // Any OSV failure is retried as a whole for now; partial coverage is M4.
      throw new TransientError('osv_unavailable', `OSV answered ${res.status} for ${path}`);
    }
    return res;
  }
}

/** Only the parts of an OSV record that apply to this package (same ecosystem, exact name). */
export function toAdvisory(v: OsvVuln, pkg: { ecosystem: string; name: string }): Advisory {
  const ranges = (v.affected ?? [])
    .filter((a) => a.package?.ecosystem === pkg.ecosystem && a.package.name === pkg.name)
    .flatMap((a) => a.ranges ?? []);
  return {
    id: v.id,
    aliases: v.aliases ?? [],
    title: v.summary ?? null,
    severity: severityFromLabel(v.database_specific?.severity),
    isMalicious: isMaliciousId(v.id),
    affectedRanges: ranges,
    references: (v.references ?? []).flatMap((r) => (typeof r.url === 'string' ? [{ type: r.type ?? 'WEB', url: r.url }] : [])),
  };
}

async function mapWithConcurrency<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const item = items[next++];
      if (item !== undefined) await fn(item);
    }
  });
  await Promise.all(workers);
}
