/**
 * Submit → queue → worker → report, with the real Postgres, pg-boss, adapters and pipeline.
 * Only the network is mocked: GitHub and OSV answer from recorded data (demo lockfile, OSV fixtures).
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GitHubRepoSource } from '../../src/adapters/github/repo-source.ts';
import { OsvVulnDatabase } from '../../src/adapters/osv/vuln-database.ts';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { PostgresScanSubmission } from '../../src/adapters/postgres/scan-submission.ts';
import { SCAN_QUEUE, type ScanJobData } from '../../src/adapters/pgboss/queue.ts';
import { ScanPipeline } from '../../src/application/scan-pipeline.ts';
import { ScanService } from '../../src/application/scan-service.ts';
import { TemplateExplainer } from '../../src/adapters/template-explainer.ts';
import { createTestEnv, type TestEnv } from '../support/env.ts';

const FIXTURES = path.join(import.meta.dirname, '..', 'fixtures');
const SHA = 'c0ffee'.padEnd(40, '0');
const demoLock = readFileSync(path.join(FIXTURES, 'lockfiles', 'demo.package-lock.json'), 'utf8');

// Which demo packages OSV reports, using advisories we have recorded details for.
const OSV_IDS: Record<string, string[]> = {
  'lodash@4.17.20': ['GHSA-29mw-wpgm-hmr9'],
  'request@2.88.2': ['GHSA-p8p7-x288-28g6'],
  'flatmap-stream@0.1.1': ['GHSA-9x64-5r7x-2q53', 'GHSA-mh6f-8j2x-4483', 'MAL-2025-20690'],
};

const server = setupServer(
  http.get('https://api.github.com/repos/demo/scan-review-demo', () => HttpResponse.json({ default_branch: 'main' })),
  http.get('https://api.github.com/repos/demo/scan-review-demo/commits/main', () => HttpResponse.json({ sha: SHA })),
  http.get(`https://raw.githubusercontent.com/demo/scan-review-demo/${SHA}/package-lock.json`, () =>
    HttpResponse.text(demoLock),
  ),
  http.get('https://api.github.com/repos/demo/gone', () => new HttpResponse(null, { status: 404 })),
  http.post('https://api.osv.dev/v1/querybatch', async ({ request }) => {
    const { queries } = (await request.json()) as { queries: { package: { name: string }; version: string }[] };
    return HttpResponse.json({
      results: queries.map((q) => {
        const ids = OSV_IDS[`${q.package.name}@${q.version}`];
        return ids ? { vulns: ids.map((id) => ({ id, modified: '2026-01-01T00:00:00Z' })) } : {};
      }),
    });
  }),
  http.get('https://api.osv.dev/v1/vulns/:id', ({ params }) =>
    HttpResponse.json(
      JSON.parse(readFileSync(path.join(FIXTURES, 'osv', `${String(params['id'])}.json`), 'utf8')) as Record<string, unknown>,
    ),
  ),
);

describe('end to end: submit → worker → report', () => {
  let env: TestEnv;
  let service: ScanService;

  beforeAll(async () => {
    server.listen({ onUnhandledFrame: 'error' });
    env = await createTestEnv();
    const scans = new PostgresScanRepository(env.pool);
    service = new ScanService(new PostgresScanSubmission(env.pool, env.boss), scans);
    const pipeline = new ScanPipeline({
      scans,
      source: new GitHubRepoSource(),
      vulns: new OsvVulnDatabase(),
      // As the worker wires it; the AI explainer fails, so the template must carry the report.
      explain: { ai: { explain: () => Promise.reject(new Error('provider down')) }, template: new TemplateExplainer(), timeoutMs: 1000 },
    });
    await env.boss.work<ScanJobData>(SCAN_QUEUE, { pollingIntervalSeconds: 0.5 }, async ([job]) => {
      if (job) await pipeline.run(job.data.scanId, job.signal);
    });
  });

  afterAll(async () => {
    await env.close();
    server.close();
  });

  async function waitForTerminal(scanId: string) {
    const deadline = Date.now() + 20_000;
    for (;;) {
      const scan = await service.get(scanId);
      if (scan && ['completed', 'failed', 'unsupported'].includes(scan.status)) return scan;
      if (Date.now() > deadline) throw new Error(`scan still ${scan?.status ?? 'missing'}`);
      await new Promise((r) => setTimeout(r, 200));
    }
  }

  it('scans the demo fixture repo and reports its findings', async () => {
    const submitted = await service.submit('https://github.com/demo/scan-review-demo', 'e2e-1');
    if (submitted.kind !== 'created') throw new Error(submitted.kind);

    const scan = await waitForTerminal(submitted.scanId);
    expect(scan).toMatchObject({
      status: 'completed',
      commitSha: SHA,
      lockfilePath: 'package-lock.json',
      advisorySource: 'OSV.dev',
      coverage: 'full',
      counts: { totalDeps: 107, checkedDeps: 106, unsupportedDeps: 1, failedLookups: 0 },
    });

    const report = await service.getReport(submitted.scanId);
    const byPackage = Object.groupBy(report?.findings ?? [], (f) => f.package);
    expect(Object.keys(byPackage).sort()).toEqual(['flatmap-stream', 'lodash', 'request']);
    expect(byPackage['flatmap-stream']?.find((f) => f.advisoryId === 'MAL-2025-20690')).toMatchObject({
      isMalicious: true,
      isDirect: true,
      scope: 'runtime',
    });
    expect(byPackage['lodash']?.[0]).toMatchObject({
      severity: 'medium',
      installedVersion: '4.17.20',
      candidateVersion: '4.17.21',
      fixStatus: 'candidate',
    });
    expect(byPackage['request']?.[0]).toMatchObject({ candidateVersion: null, fixStatus: 'no_fix' });
    expect(byPackage['flatmap-stream']?.every((f) => f.isMalicious && f.fixStatus === 'no_fix')).toBe(true);
    expect(report?.unchecked).toEqual([{ ecosystem: 'npm', package: 'slash', version: '5.1.0', reason: 'unsupported_source' }]);

    // The actionable report: what to do first, in plan order.
    expect(report?.summary).toBe(
      '1 known malicious package and 2 packages with known vulnerabilities (2 medium) in 106 of 107 dependencies checked. ' +
        'Start with: remove flatmap-stream (known malicious package).',
    );
    expect(report?.actions.map((a) => [a.rank, a.package, a.kind, a.onSummary])).toEqual([
      [1, 'flatmap-stream', 'remove_malicious', true],
      [2, 'lodash', 'upgrade', true],
      [3, 'request', 'no_fix', true],
    ]);
    expect(report?.actions[1]?.text?.steps).toEqual([
      'lodash 4.17.20 (direct, runtime): candidate 4.17.21 addresses 1 of 1 advisory on 4.17.20 according to advisory data.',
      '`npm install lodash@4.17.21`.',
    ]);
    expect(report?.findings[0]?.package).toBe('flatmap-stream'); // findings ranked too
    expect(report?.ciChecks).toEqual(['Dependabot alerts', '`npm audit` in CI']);
    expect(report?.agentPrompt).toContain(`at commit ${SHA}`);

    // AI failed → template prose, labelled, for the summary and every action; stored with the scan.
    expect(report?.explanation).toMatchObject({ source: 'template', text: expect.stringMatching(/^Start with the known malicious package/) as string });
    expect(report?.actions.every((a) => a.whyItMatters?.source === 'template')).toBe(true);
    const row = await env.pool.query<{ explanation_source: string; explanation: { fallbackReason?: string } }>(
      'SELECT explanation_source, explanation FROM scans WHERE id = $1',
      [submitted.scanId],
    );
    expect(row.rows[0]).toMatchObject({ explanation_source: 'template', explanation: { fallbackReason: 'error: Error: provider down' } });
  });

  it('a missing repository ends failed with a clear reason, without retries', async () => {
    const submitted = await service.submit('https://github.com/demo/gone', null);
    if (submitted.kind !== 'created') throw new Error(submitted.kind);
    const scan = await waitForTerminal(submitted.scanId);
    expect(scan).toMatchObject({ status: 'failed', error: { code: 'repo_not_found' } });
    const [job] = await env.boss.findJobs(SCAN_QUEUE, { id: submitted.scanId });
    expect(job).toMatchObject({ state: 'completed', retryCount: 0 }); // returned normally: no retry
  });
});
