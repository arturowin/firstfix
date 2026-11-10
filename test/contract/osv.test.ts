import { readFileSync } from 'node:fs';
import path from 'node:path';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { OsvVulnDatabase } from '../../src/adapters/osv/vuln-database.ts';
import { TransientError } from '../../src/ports/errors.ts';

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
    expect(lookup.has('npm:left-pad@1.3.0')).toBe(false);

    const request = lookup.get('npm:request@2.88.2');
    expect(request).toEqual([
      {
        id: 'GHSA-p8p7-x288-28g6',
        aliases: ['CVE-2023-28155'],
        title: 'Server-Side Request Forgery in Request',
        severity: 'medium', // MODERATE
        isMalicious: false,
        // only the `request` entry, not `@cypress/request` from the same advisory
        affectedRanges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { last_affected: '2.88.2' }] }],
        references: expect.arrayContaining([expect.objectContaining({ url: expect.stringMatching(/^https:/) as string })]) as unknown,
      },
    ]);

    const flatmap = lookup.get('npm:flatmap-stream@0.1.1') ?? [];
    expect(flatmap.map((a) => [a.id, a.severity, a.isMalicious]).sort()).toEqual([
      ['GHSA-9x64-5r7x-2q53', 'critical', false],
      ['GHSA-mh6f-8j2x-4483', 'critical', false],
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
    for (const p of pkgs) expect(lookup.get(`npm:${p.name}@1.0.0`)?.map((a) => a.id)).toEqual([`ID-${p.name}`]);
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
    const big = lookup.get('npm:big@1.0.0')?.map((a) => a.id) ?? [];
    expect(big).toHaveLength(3 + 3 + 1);
    expect(new Set(big).size).toBe(big.length); // pages don't overlap
    expect(lookup.get('npm:lodash@4.17.20')).toHaveLength(4);
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
    expect(lookup.get('npm:lodash@4.17.20')?.[0]?.affectedRanges).toHaveLength(1);
    expect(lookup.get('npm:lodash-es@4.17.20')?.[0]?.affectedRanges).toHaveLength(1);
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
    expect(lookup.get('RubyGems:lodash-rails@4.17.20')?.[0]?.affectedRanges).toEqual([
      { type: 'ECOSYSTEM', events: [{ introduced: '4.0.0' }, { fixed: '4.17.21' }] },
    ]);
    expect(lookup.get('npm:lodash-rails@4.17.20')?.[0]?.affectedRanges).toEqual([]);
  });

  it.each([
    ['batch 503', () => new HttpResponse(null, { status: 503 }), 'osv_unavailable'],
    ['batch result count mismatch', () => HttpResponse.json({ results: [] }), 'osv_bad_response'],
    ['network error', () => HttpResponse.error(), 'osv_unreachable'],
  ])('transient: %s', async (_label, respond, code) => {
    server.use(http.post(`${OSV}/v1/querybatch`, respond));
    const err: unknown = await new OsvVulnDatabase()
      .lookup([{ ecosystem: 'npm', name: 'a', version: '1.0.0' }], signal())
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TransientError);
    expect(err).toMatchObject({ code });
  });

  it('a failed detail call is transient', async () => {
    server.use(
      http.post(`${OSV}/v1/querybatch`, () => HttpResponse.json({ results: [{ vulns: [{ id: 'X-1' }] }] })),
      http.get(`${OSV}/v1/vulns/:id`, () => new HttpResponse(null, { status: 500 })),
    );
    await expect(new OsvVulnDatabase().lookup([{ ecosystem: 'npm', name: 'a', version: '1.0.0' }], signal())).rejects.toBeInstanceOf(
      TransientError,
    );
  });

  it('no packages → no calls', async () => {
    expect((await new OsvVulnDatabase().lookup([], signal())).size).toBe(0);
  });
});
