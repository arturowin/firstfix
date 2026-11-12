/**
 * A later OSV results page failing, through the real pipeline, OSV adapter (network mocked) and Postgres: the
 * scan report shows the confirmed finding and the incomplete coverage together.
 */
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { OsvVulnDatabase } from '../../src/adapters/osv/vuln-database.ts';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { ScanPipeline } from '../../src/application/scan-pipeline.ts';
import type { RepoSource } from '../../src/ports/repo-source.ts';
import { createTestEnv, type TestEnv } from '../support/env.ts';

const OSV = 'https://api.osv.dev';
const MAL = JSON.parse(readFileSync(path.join(import.meta.dirname, '..', 'fixtures', 'osv', 'MAL-2025-20690.json'), 'utf8')) as object;

const lock = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { dependencies: { 'flatmap-stream': '0.1.1' } },
    'node_modules/flatmap-stream': { version: '0.1.1', resolved: 'https://registry.npmjs.org/flatmap-stream/-/flatmap-stream-0.1.1.tgz' },
  },
});
const source: RepoSource = {
  resolveDefaultCommit: () => Promise.resolve({ sha: 'a'.repeat(40), branch: 'main' }),
  readFile: (_r, _a, _s, p) => Promise.resolve(p === 'package-lock.json' ? lock : null),
};

const server = setupServer(
  http.post(`${OSV}/v1/querybatch`, async ({ request }) => {
    const { queries } = (await request.json()) as { queries: { page_token?: string }[] };
    if (queries[0]?.page_token === undefined) {
      return HttpResponse.json({ results: [{ vulns: [{ id: 'MAL-2025-20690' }], next_page_token: 'page-2' }] });
    }
    return new HttpResponse(null, { status: 503 });
  }),
  http.get(`${OSV}/v1/vulns/MAL-2025-20690`, () => HttpResponse.json(MAL)),
);

describe('a later OSV results page fails, end to end', () => {
  let env: TestEnv;
  let scans: PostgresScanRepository;

  beforeAll(async () => {
    server.listen({ onUnhandledFrame: 'error' });
    env = await createTestEnv();
    scans = new PostgresScanRepository(env.pool);
  });

  afterAll(async () => {
    await env.close();
    server.close();
  });

  it('the report shows the confirmed malware finding and partial coverage together', async () => {
    const id = randomUUID();
    await env.pool.query(
      `INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized) VALUES ($1, 'o', 'r', 'https://github.com/o/r')`,
      [id],
    );
    const pipeline = new ScanPipeline({ scans, source, vulns: new OsvVulnDatabase({ retryDelayMs: 0 }) });
    expect(await pipeline.run(id, new AbortController().signal)).toBe('completed');

    const report = await scans.getReport(id);
    expect(report?.findings.map((f) => [f.package, f.advisoryId, f.isMalicious])).toEqual([['flatmap-stream', 'MAL-2025-20690', true]]);
    expect(report?.scan).toMatchObject({ coverage: 'partial', counts: { totalDeps: 1, checkedDeps: 0, failedLookups: 1 } });
    expect(report?.unchecked).toEqual([{ ecosystem: 'npm', package: 'flatmap-stream', version: '0.1.1', reason: 'lookup_failed' }]);
    expect(report?.scan.summaryLine).toMatch(/^1 known malicious package in 0 of 1 dependency checked\. 1 dependency could not be fully checked/);
  });
});
