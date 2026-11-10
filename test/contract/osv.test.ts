import { readFileSync } from 'node:fs';
import path from 'node:path';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { OsvVulnDatabase } from '../../src/adapters/osv/vuln-database.ts';
import { vulnDatabaseContract } from './vuln-database.contract.ts';

const OSV = 'https://api.osv.dev';
const FIXTURES = path.join(import.meta.dirname, '..', 'fixtures', 'osv');
// Fixtures are trusted test data; the type argument documents the expected shape at each call site.
// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters
const fixture = <T>(name: string): T => JSON.parse(readFileSync(path.join(FIXTURES, name), 'utf8')) as T;
const signal = () => new AbortController().signal;

interface Query {
  package: { ecosystem: string; name: string };
  version?: string;
  page_token?: string;
}
interface Batch {
  queries: Query[];
}
interface BatchResponse {
  results: { vulns?: { id: string }[]; next_page_token?: string }[];
}

const server = setupServer();
beforeAll(() => {
  server.listen({ onUnhandledFrame: 'error' });
});
afterEach(() => {
  server.resetHandlers();
});
afterAll(() => {
  server.close();
});

/** Serves /v1/vulns/{id} from saved fixtures, counting calls per id. */
function serveVulnFixtures(calls: Map<string, number>) {
  server.use(
    http.get(`${OSV}/v1/vulns/:id`, ({ params }) => {
      const id = String(params['id']);
      calls.set(id, (calls.get(id) ?? 0) + 1);
      try {
        return HttpResponse.json(fixture(`${id}.json`));
      } catch {
        return HttpResponse.json({ id, summary: `stub ${id}`, affected: [] });
      }
    }),
  );
}

describe('OsvVulnDatabase', () => {
  it('maps the recorded batch + details: severity label, malicious flag, ranges for this package only', async () => {
    // Real recorded batch: queries[2] request, [4] flatmap-stream, [5] left-pad and their positional results.
    const req = fixture<Batch>('querybatch.request.json');
    const res = fixture<BatchResponse>('querybatch.response.json');
    const pick = [2, 4, 5];
    let sent: Batch | undefined;
    server.use(
      http.post(`${OSV}/v1/querybatch`, async ({ request }) => {
        sent = (await request.json()) as Batch;
        return HttpResponse.json({ results: pick.map((i) => res.results[i]) });
      }),
    );
    serveVulnFixtures(new Map());

    const packages = pick.map((i) => {
      const q = req.queries[i];
      return { ecosystem: 'npm', name: q?.package.name ?? '', version: q?.version ?? '' };
    });
    const lookup = await new OsvVulnDatabase().lookup(packages, signal());

    expect(sent).toEqual({ queries: pick.map((i) => req.queries[i]) });
    expect(lookup.advisories.has('npm:left-pad@1.3.0')).toBe(false);

    const request = lookup.advisories.get('npm:request@2.88.2');
    expect(request).toEqual([
      {
        id: 'GHSA-p8p7-x288-28g6',
        aliases: ['CVE-2023-28155'],
        title: 'Server-Side Request Forgery in Request',
        severity: 'medium', // MODERATE
        isMalicious: false,
        // only the `request` entry, not `@cypress/request` from the same advisory
        affectedRanges: [{ kind: 'range', introduced: '0', fixed: null, lastAffected: '2.88.2' }],
        references: expect.arrayContaining([expect.objectContaining({ url: expect.stringMatching(/^https:/) as string })]) as unknown,
      },
    ]);

    const flatmap = lookup.advisories.get('npm:flatmap-stream@0.1.1') ?? [];
    expect(flatmap.map((a) => [a.id, a.severity, a.isMalicious]).sort()).toEqual([
      ['GHSA-9x64-5r7x-2q53', 'critical', true], // CWE-506
      ['GHSA-mh6f-8j2x-4483', 'critical', true], // CWE-506
      ['MAL-2025-20690', 'unknown', true],
    ]);
    expect(flatmap.find((a) => a.id === 'MAL-2025-20690')).toMatchObject({ aliases: [], references: [] });
  });

  it('chunks queries to the batch size and keeps positional mapping per chunk', async () => {
    const batches: string[][] = [];
    server.use(
      http.post(`${OSV}/v1/querybatch`, async ({ request }) => {
        const { queries } = (await request.json()) as Batch;
        batches.push(queries.map((q) => q.package.name));
        return HttpResponse.json({ results: queries.map((q) => ({ vulns: [{ id: `ID-${q.package.name}` }] })) });
      }),
    );
    serveVulnFixtures(new Map());
    const pkgs = ['a', 'b', 'c', 'd', 'e'].map((name) => ({ ecosystem: 'npm', name, version: '1.0.0' }));
    const lookup = await new OsvVulnDatabase({ batchSize: 2 }).lookup(pkgs, signal());
    expect(batches).toEqual([['a', 'b'], ['c', 'd'], ['e']]);
    for (const p of pkgs) expect(lookup.advisories.get(`npm:${p.name}@1.0.0`)?.map((a) => a.id)).toEqual([`ID-${p.name}`]);
  });

  it('follows next_page_token by re-sending only the paginated query (recorded pagination shape)', async () => {
    const page1 = fixture<BatchResponse>('pagination.page1.response.json');
    const page2 = fixture<BatchResponse>('pagination.page2.response.json');
    const token1 = page1.results[0]?.next_page_token;
    const token2 = page2.results[0]?.next_page_token;
    const rounds: Query[][] = [];
    server.use(
      http.post(`${OSV}/v1/querybatch`, async ({ request }) => {
        const { queries } = (await request.json()) as Batch;
        rounds.push(queries);
        const token = queries[0]?.page_token;
        if (token === undefined) return HttpResponse.json({ results: page1.results });
        if (token === token1) return HttpResponse.json({ results: page2.results });
        if (token === token2) return HttpResponse.json({ results: [{ vulns: [{ id: 'LAST-PAGE' }] }] });
        return new HttpResponse(null, { status: 400 });
      }),
    );
    serveVulnFixtures(new Map());

    const lookup = await new OsvVulnDatabase().lookup(
      [
        { ecosystem: 'npm', name: 'big', version: '1.0.0' },
        { ecosystem: 'npm', name: 'lodash', version: '4.17.20' },
      ],
      signal(),
    );

    expect(rounds.map((r) => r.length)).toEqual([2, 1, 1]);
    expect(rounds[1]?.[0]).toMatchObject({ package: { name: 'big' }, page_token: token1 });
    const big = lookup.advisories.get('npm:big@1.0.0')?.map((a) => a.id) ?? [];
    expect(big).toHaveLength(3 + 3 + 1);
    expect(new Set(big).size).toBe(big.length); // pages don't overlap
    expect(lookup.advisories.get('npm:lodash@4.17.20')).toHaveLength(4);
  });

  it('fetches each advisory once, even when several packages share it', async () => {
    server.use(
      http.post(`${OSV}/v1/querybatch`, async ({ request }) => {
        const { queries } = (await request.json()) as Batch;
        return HttpResponse.json({ results: queries.map(() => ({ vulns: [{ id: 'GHSA-29mw-wpgm-hmr9' }] })) });
      }),
    );
    const calls = new Map<string, number>();
    serveVulnFixtures(calls);
    const lookup = await new OsvVulnDatabase().lookup(
      [
        { ecosystem: 'npm', name: 'lodash', version: '4.17.20' },
        { ecosystem: 'npm', name: 'lodash-es', version: '4.17.20' },
      ],
      signal(),
    );
    expect(calls.get('GHSA-29mw-wpgm-hmr9')).toBe(1);
    // same advisory, different package → ranges filtered per package
    expect(lookup.advisories.get('npm:lodash@4.17.20')?.[0]?.affectedRanges).toHaveLength(1);
    expect(lookup.advisories.get('npm:lodash-es@4.17.20')?.[0]?.affectedRanges).toHaveLength(1);
  });

  it('passes the ecosystem through and filters `affected` by ecosystem and exact name', async () => {
    let sent: Batch | undefined;
    server.use(
      http.post(`${OSV}/v1/querybatch`, async ({ request }) => {
        sent = (await request.json()) as Batch;
        return HttpResponse.json({ results: sent.queries.map(() => ({ vulns: [{ id: 'GHSA-29mw-wpgm-hmr9' }] })) });
      }),
    );
    serveVulnFixtures(new Map());
    const lookup = await new OsvVulnDatabase().lookup(
      [
        { ecosystem: 'RubyGems', name: 'lodash-rails', version: '4.17.20' },
        // Same name in another ecosystem: the advisory's RubyGems entry must not apply to it.
        { ecosystem: 'npm', name: 'lodash-rails', version: '4.17.20' },
      ],
      signal(),
    );
    expect(sent?.queries.map((q) => q.package)).toEqual([
      { ecosystem: 'RubyGems', name: 'lodash-rails' },
      { ecosystem: 'npm', name: 'lodash-rails' },
    ]);
    expect(lookup.advisories.get('RubyGems:lodash-rails@4.17.20')?.[0]?.affectedRanges).toEqual([
      { kind: 'range', introduced: '4.0.0', fixed: '4.17.21', lastAffected: null },
    ]);
    expect(lookup.advisories.get('npm:lodash-rails@4.17.20')?.[0]?.affectedRanges).toEqual([]);
  });

  const pkg = (name: string) => ({ ecosystem: 'npm', name, version: '1.0.0' });

  it.each([
    ['batch 503', () => new HttpResponse(null, { status: 503 })],
    ['batch result count mismatch', () => HttpResponse.json({ results: [] })],
    ['network error', () => HttpResponse.error()],
  ])('%s, twice → the batch’s packages are failed after exactly one retry', async (_label, respond) => {
    let calls = 0;
    server.use(
      http.post(`${OSV}/v1/querybatch`, () => {
        calls++;
        return respond();
      }),
    );
    const r = await new OsvVulnDatabase({ retryDelayMs: 0 }).lookup([pkg('a')], signal());
    expect(r).toEqual({ advisories: new Map(), failed: [pkg('a')] });
    expect(calls).toBe(2);
  });

  it('one dropped call is absorbed by the retry', async () => {
    let calls = 0;
    server.use(
      http.post(`${OSV}/v1/querybatch`, () =>
        ++calls === 1 ? new HttpResponse(null, { status: 503 }) : HttpResponse.json({ results: [{}] }),
      ),
    );
    expect(await new OsvVulnDatabase({ retryDelayMs: 0 }).lookup([pkg('a')], signal())).toEqual({ advisories: new Map(), failed: [] });
  });

  it('one failing chunk fails only its packages; other chunks are checked', async () => {
    server.use(
      http.post(`${OSV}/v1/querybatch`, async ({ request }) => {
        const { queries } = (await request.json()) as Batch;
        if (queries.some((q) => q.package.name === 'c')) return new HttpResponse(null, { status: 500 });
        return HttpResponse.json({ results: queries.map(() => ({ vulns: [{ id: 'GHSA-29mw-wpgm-hmr9' }] })) });
      }),
    );
    serveVulnFixtures(new Map());
    const r = await new OsvVulnDatabase({ batchSize: 2, retryDelayMs: 0 }).lookup(['a', 'b', 'c', 'd'].map(pkg), signal());
    expect(r.failed).toEqual([pkg('c'), pkg('d')]);
    expect([...r.advisories.keys()]).toEqual(['npm:a@1.0.0', 'npm:b@1.0.0']);
  });

  it('a failing detail call fails every package citing that advisory, and only those', async () => {
    serveVulnFixtures(new Map()); // registered first: msw tries the later BAD-1 handler before it
    server.use(
      http.post(`${OSV}/v1/querybatch`, () =>
        HttpResponse.json({ results: [{ vulns: [{ id: 'BAD-1' }] }, { vulns: [{ id: 'BAD-1' }, { id: 'GHSA-29mw-wpgm-hmr9' }] }, { vulns: [{ id: 'GHSA-29mw-wpgm-hmr9' }] }] }),
      ),
      http.get(`${OSV}/v1/vulns/BAD-1`, () => new HttpResponse(null, { status: 500 })),
    );
    const r = await new OsvVulnDatabase({ retryDelayMs: 0 }).lookup([pkg('a'), pkg('b'), pkg('c')], signal());
    expect(r.failed).toEqual([pkg('a'), pkg('b')]);
    expect([...r.advisories.keys()]).toEqual(['npm:c@1.0.0']);
  });

  it('no packages → no calls', async () => {
    expect(await new OsvVulnDatabase().lookup([], signal())).toEqual({ advisories: new Map(), failed: [] });
  });
});

vulnDatabaseContract('OSV.dev', {
  create: () => new OsvVulnDatabase({ retryDelayMs: 0 }),
  serveRecorded(idsByPackage) {
    server.use(
      http.post(`${OSV}/v1/querybatch`, async ({ request }) => {
        const { queries } = (await request.json()) as Batch;
        return HttpResponse.json({
          results: queries.map((q) => {
            const ids = idsByPackage[`${q.package.ecosystem}:${q.package.name}@${q.version ?? ''}`];
            return ids ? { vulns: ids.map((id) => ({ id, modified: '2026-01-01T00:00:00Z' })) } : {};
          }),
        });
      }),
      http.get(`${OSV}/v1/vulns/:id`, ({ params }) => {
        try {
          return HttpResponse.json(fixture(`${String(params['id'])}.json`));
        } catch {
          // Recorded: OSV answers an unknown id with 404.
          return HttpResponse.json({ code: 5, message: 'Bug not found.' }, { status: 404 });
        }
      }),
    );
  },
  serveUnknownId(id) {
    server.use(
      http.post(`${OSV}/v1/querybatch`, async ({ request }) => {
        const { queries } = (await request.json()) as Batch;
        return HttpResponse.json({ results: queries.map(() => ({ vulns: [{ id }] })) });
      }),
      // Recorded: OSV answers an unknown id with 404.
      http.get(`${OSV}/v1/vulns/:id`, () => HttpResponse.json({ code: 5, message: 'Bug not found.' }, { status: 404 })),
    );
  },
  serveOutage(kind) {
    server.use(
      http.post(`${OSV}/v1/querybatch`, () => (kind === 'network' ? HttpResponse.error() : new HttpResponse(null, { status: 503 }))),
    );
  },
});
