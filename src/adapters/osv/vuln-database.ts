import { TransientError } from '../../ports/errors.ts';
import { packageKey, type LookupResult, type PackageRef, type VulnDatabase } from '../../ports/vuln-database.ts';
import { fetchWithTimeout, USER_AGENT } from '../http.ts';
import { defaultRegistry } from '../../domain/ecosystems/registry.ts';
import { isOsvVuln, toAdvisory, type OsvVuln, type VersionOrder } from './translate.ts';

export interface OsvOptions {
  baseUrl?: string;
  timeoutMs?: number;
  /** OSV's documented maximum is 1000 queries per batch. */
  batchSize?: number;
  detailConcurrency?: number;
  /** Pause before the one retry of a failed call. */
  retryDelayMs?: number;
  /** Version ordering per ecosystem, to sort range events (default: the ecosystem registry's schemes). */
  versionOrder?: (ecosystem: string) => VersionOrder | null;
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

/** OSV.dev: querybatch for ids (chunked, paginated per query), then one detail call per unique id. */
export class OsvVulnDatabase implements VulnDatabase {
  readonly source = { name: 'OSV.dev', url: 'https://osv.dev' };
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly batchSize: number;
  private readonly detailConcurrency: number;
  private readonly retryDelayMs: number;
  private readonly versionOrder: (ecosystem: string) => VersionOrder | null;

  constructor(options: OsvOptions = {}) {
    this.baseUrl = options.baseUrl ?? 'https://api.osv.dev';
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.batchSize = options.batchSize ?? 1000;
    this.detailConcurrency = options.detailConcurrency ?? 8;
    this.retryDelayMs = options.retryDelayMs ?? 500;
    this.versionOrder = options.versionOrder ?? ((e) => defaultRegistry.ecosystems.get(e)?.versionScheme ?? null);
  }

  async lookup(packages: PackageRef[], signal: AbortSignal): Promise<LookupResult> {
    const { ids: idsByPackage, failed, partial } = await this.queryIds(packages, signal);

    // Details once per advisory id, shared across packages; a failed id fails every package that cites it.
    const uniqueIds = [...new Set([...idsByPackage.values()].flat())].sort();
    const details = new Map<string, OsvVuln>();
    const failedIds = new Set<string>();
    await mapWithConcurrency(uniqueIds, this.detailConcurrency, async (id) => {
      try {
        details.set(id, await this.withRetry(() => this.fetchVuln(id, signal), signal));
      } catch (err) {
        if (signal.aborted) throw err;
        failedIds.add(id);
      }
    });

    const result: LookupResult = { advisories: new Map(), failed: [], incomplete: [] };
    for (const pkg of packages) {
      const key = packageKey(pkg);
      if (failed.has(key)) {
        result.failed.push(pkg);
        continue;
      }
      // Advisories whose details arrived are kept even if another one's didn't: a confirmed finding (say, a
      // malware record) must never disappear because a different request failed.
      const confirmed = [];
      let missing = false;
      for (const id of idsByPackage.get(key) ?? []) {
        const detail = details.get(id);
        if (failedIds.has(id) || !detail) {
          missing = true;
          continue;
        }
        try {
          confirmed.push(toAdvisory(detail, pkg, this.versionOrder(pkg.ecosystem)));
        } catch {
          missing = true; // validated records shouldn't fail to translate; if one does, only it is lost
        }
      }
      if (confirmed.length > 0) result.advisories.set(key, confirmed);
      if (missing || partial.has(key)) result.incomplete.push(pkg);
    }
    return result;
  }

  private async queryIds(
    packages: PackageRef[],
    signal: AbortSignal,
  ): Promise<{ ids: Map<string, string[]>; failed: Set<string>; partial: Set<string> }> {
    const ids = new Map<string, string[]>();
    const failed = new Set<string>();
    // A later results page failed: earlier pages' ids are real evidence, so the package is incomplete, not failed.
    const partial = new Set<string>();
    const lose = (entry: { pkg: PackageRef; pageToken?: string }) =>
      (entry.pageToken === undefined ? failed : partial).add(packageKey(entry.pkg));
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
        let results: BatchResult[];
        try {
          results = await this.withRetry(async () => {
            const res = await this.post('/v1/querybatch', { queries }, signal);
            const body = (await res.json()) as { results?: BatchResult[] };
            if (!Array.isArray(body.results) || body.results.length !== chunk.length) {
              throw new TransientError('osv_bad_response', 'OSV returned a batch result that does not match the query');
            }
            return body.results;
          }, signal);
        } catch (err) {
          if (signal.aborted) throw err;
          // This chunk (or this page of it) couldn't be checked; other chunks still count.
          for (const entry of chunk) lose(entry);
          continue;
        }
        results.forEach((r, j) => {
          const entry = chunk[j];
          if (!entry) return;
          const key = packageKey(entry.pkg);
          // A malformed entry fails its own package only; positions still line up for the rest.
          if (!isBatchResult(r)) {
            lose(entry);
            return;
          }
          const list = ids.get(key) ?? [];
          for (const v of r.vulns ?? []) if (!list.includes(v.id)) list.push(v.id);
          ids.set(key, list);
          if (r.next_page_token) next.push({ pkg: entry.pkg, pageToken: r.next_page_token });
        });
      }
      pending = next;
    }
    return { ids, failed, partial };
  }

  /** One quick retry per call: a single dropped request shouldn't cost a package its check. */
  private async withRetry<T>(call: () => Promise<T>, signal: AbortSignal): Promise<T> {
    try {
      return await call();
    } catch (err) {
      if (signal.aborted) throw err;
      await new Promise((r) => setTimeout(r, this.retryDelayMs));
      signal.throwIfAborted();
      return call();
    }
  }

  /** Validated inside the retry boundary: a malformed record counts as a failed fetch for that advisory. */
  private async fetchVuln(id: string, signal: AbortSignal): Promise<OsvVuln> {
    const res = await this.request(`/v1/vulns/${encodeURIComponent(id)}`, { method: 'GET' }, signal);
    const body: unknown = await res.json();
    if (!isOsvVuln(body, id)) throw new TransientError('osv_bad_response', `OSV returned a malformed record for ${id}`);
    return body;
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
      // Failures are counted per package by lookup(); this error never leaves the adapter.
      throw new TransientError('osv_unavailable', `OSV answered ${res.status} for ${path}`);
    }
    return res;
  }
}

function isBatchResult(r: unknown): r is BatchResult {
  if (typeof r !== 'object' || r === null || Array.isArray(r)) return false;
  const { vulns, next_page_token: token } = r as Record<string, unknown>;
  if (token !== undefined && typeof token !== 'string') return false;
  return (
    vulns === undefined ||
    (Array.isArray(vulns) && vulns.every((v) => typeof v === 'object' && v !== null && typeof (v as { id?: unknown }).id === 'string'))
  );
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
