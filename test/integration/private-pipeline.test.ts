/**
 * The worker's side of private repositories with real Postgres, the real pipeline and the real GitHub adapters.
 * GitHub and OSV are mocked (msw) with documented response shapes; a live run needs a real GitHub App.
 */
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { GitHubAppTokens } from '../../src/adapters/github/app-tokens.ts';
import { GitHubRepoSource } from '../../src/adapters/github/repo-source.ts';
import { OsvVulnDatabase } from '../../src/adapters/osv/vuln-database.ts';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { PostgresScanSubmission } from '../../src/adapters/postgres/scan-submission.ts';
import { ScanPipeline } from '../../src/application/scan-pipeline.ts';
import { ScanService } from '../../src/application/scan-service.ts';
import { TransientError } from '../../src/ports/errors.ts';
import { createTestEnv, type TestEnv } from '../support/env.ts';

const API = 'https://api.github.com';
const RAW = 'https://raw.githubusercontent.com';
const SHA = 'd'.repeat(40);
const FIXTURES = path.join(import.meta.dirname, '..', 'fixtures');
const lock = readFileSync(path.join(FIXTURES, 'lockfiles', 'demo.package-lock.json'), 'utf8');
const PEM = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

/** Every GitHub request, with whether it carried credentials. */
const requests: { url: string; auth: string | null }[] = [];

const server = setupServer(
  http.post('https://api.osv.dev/v1/querybatch', async ({ request }) => {
    const { queries } = (await request.json()) as { queries: { package: { name: string }; version: string }[] };
    return HttpResponse.json({
      results: queries.map((q) => (`${q.package.name}@${q.version}` === 'lodash@4.17.20' ? { vulns: [{ id: 'GHSA-29mw-wpgm-hmr9', modified: '2026-01-01T00:00:00Z' }] } : {})),
    });
  }),
  http.get('https://api.osv.dev/v1/vulns/:id', ({ params }) =>
    HttpResponse.json(JSON.parse(readFileSync(path.join(FIXTURES, 'osv', `${String(params['id'])}.json`), 'utf8')) as Record<string, unknown>),
  ),
);
server.events.on('request:start', ({ request }) => {
  if (request.url.includes('github')) requests.push({ url: request.url, auth: request.headers.get('authorization') });
});

/** GitHub for a private repository reachable through installation 70 as repository 4242. */
function privateGitHub(options: { mint?: number } = {}) {
  server.use(
    http.post(`${API}/app/installations/70/access_tokens`, () =>
      options.mint
        ? new HttpResponse(null, { status: options.mint })
        : HttpResponse.json({ token: 'ghs_scoped', expires_at: new Date(Date.now() + 3_600_000).toISOString() }, { status: 201 }),
    ),
    http.get(`${API}/installation/repositories`, () =>
      HttpResponse.json({ repositories: [{ id: 4242, full_name: 'acme/secret-app', default_branch: 'main', private: true }] }),
    ),
    http.get(`${API}/repos/acme/secret-app/commits/main`, () => HttpResponse.json({ sha: SHA })),
    http.get(`${API}/repos/acme/secret-app/contents/:file`, ({ params }) =>
      params['file'] === 'package-lock.json' ? HttpResponse.text(lock) : new HttpResponse(null, { status: 404 }),
    ),
  );
}

describe('private repositories in the worker', () => {
  let env: TestEnv;
  let scans: PostgresScanRepository;
  let submission: PostgresScanSubmission;
  let pipeline: ScanPipeline;

  /** A fresh worker (no cached installation tokens) for each test. */
  const newPipeline = () =>
    new ScanPipeline({
      scans,
      // A public-only token is configured, as in production; it must never reach private content.
      source: new GitHubRepoSource({ token: 'github_pat_public_only', appTokens: new GitHubAppTokens({ clientId: 'Iv1.c', privateKey: PEM }) }),
      vulns: new OsvVulnDatabase(),
    });

  beforeAll(async () => {
    server.listen({ onUnhandledFrame: 'error' });
    env = await createTestEnv();
    scans = new PostgresScanRepository(env.pool);
    submission = new PostgresScanSubmission(env.pool, env.boss);
  });
  beforeEach(() => {
    pipeline = newPipeline();
  });
  afterEach(() => {
    server.resetHandlers();
    requests.length = 0;
  });
  afterAll(async () => {
    await env.close();
    server.close();
  });

  const signal = () => new AbortController().signal;

  async function privateScan(): Promise<string> {
    const service = new ScanService(submission, scans);
    const r = await service.submit('https://github.com/acme/secret-app', null, {
      githubUserId: 1,
      privateTarget: () => Promise.resolve({ repositoryId: 4242, installationId: 70 }),
    });
    if (r.kind !== 'created') throw new Error(r.kind);
    return r.scanId;
  }

  async function publicScan(url: string): Promise<string> {
    const r = await new ScanService(submission, scans).submit(url, null);
    if (r.kind !== 'created') throw new Error(r.kind);
    return r.scanId;
  }

  it('scans a private repository with the scoped installation token and completes the normal report', async () => {
    privateGitHub();
    const id = await privateScan();
    expect(await pipeline.run(id, signal())).toBe('completed');
    const report = await scans.getReport(id);
    expect(report?.scan).toMatchObject({ status: 'completed', commitSha: SHA, visibility: { kind: 'private', repositoryId: 4242, installationId: 70 } });
    expect(report?.findings.map((f) => f.package)).toEqual(['lodash']);
    // Only the installation token was used for repository reads; the public token never.
    const reads = requests.filter((r) => !r.url.includes('/access_tokens'));
    expect(reads.length).toBeGreaterThan(0);
    expect(reads.every((r) => r.auth === 'Bearer ghs_scoped')).toBe(true);
  });

  it('a public repository that became private while queued fails without any credentialed read and with no findings', async () => {
    const id = await publicScan('https://github.com/acme/went-private');
    // What a public-only (or no) token sees for a private repository: 404.
    server.use(http.get(`${API}/repos/acme/went-private`, () => new HttpResponse(null, { status: 404 })));
    expect(await pipeline.run(id, signal())).toBe('failed');
    const report = await scans.getReport(id);
    expect(report?.scan).toMatchObject({ status: 'failed', visibility: { kind: 'public' }, error: { code: 'repo_not_found' } });
    expect(report?.findings).toEqual([]);
    expect(requests.some((r) => r.url.includes('/app/installations') || r.url.includes('/installation/'))).toBe(false);
    expect(requests.filter((r) => r.url.startsWith(RAW))).toEqual([]);
  });

  it('even if metadata says private (a token that could see it), the public path stops before reading any file', async () => {
    const id = await publicScan('https://github.com/acme/flagged-private');
    server.use(http.get(`${API}/repos/acme/flagged-private`, () => HttpResponse.json({ default_branch: 'main', private: true })));
    expect(await pipeline.run(id, signal())).toBe('failed');
    expect(requests.filter((r) => r.url.startsWith(RAW) || r.url.includes('/contents/'))).toEqual([]);
    expect((await scans.getReport(id))?.findings).toEqual([]);
  });

  it('lost app access is permanent: recorded as failed, not retried', async () => {
    privateGitHub({ mint: 404 });
    const id = await privateScan();
    expect(await pipeline.run(id, signal())).toBe('failed'); // returned normally: pg-boss won't retry
    expect((await scans.get(id))?.error?.code).toBe('app_access_revoked');
  });

  it('access revoked while a token is cached: GitHub refuses it, the retry mints again and fails permanently', async () => {
    privateGitHub();
    expect(await pipeline.run(await privateScan(), signal())).toBe('completed'); // token now cached
    const id = await privateScan();
    server.use(
      http.get(`${API}/installation/repositories`, () => new HttpResponse(null, { status: 401 })),
      http.post(`${API}/app/installations/70/access_tokens`, () => new HttpResponse(null, { status: 404 })),
    );
    await expect(pipeline.run(id, signal())).rejects.toBeInstanceOf(TransientError);
    expect(await pipeline.run(id, signal())).toBe('failed');
    expect((await scans.get(id))?.error?.code).toBe('app_access_revoked');
  });

  it('access removed mid-scan (after the commit, before the lockfile) fails as access lost, never "unsupported"', async () => {
    privateGitHub();
    let removed = false;
    server.use(
      http.get(`${API}/repos/acme/secret-app/contents/:file`, () => {
        removed = true; // the owner takes the repository out of the installation right now
        return new HttpResponse(null, { status: 404 });
      }),
      http.get(`${API}/installation/repositories`, () =>
        HttpResponse.json({ repositories: removed ? [] : [{ id: 4242, full_name: 'acme/secret-app', default_branch: 'main', private: true }] }),
      ),
    );
    const id = await privateScan();
    expect(await pipeline.run(id, signal())).toBe('failed');
    const scan = await scans.get(id);
    expect(scan?.status).toBe('failed');
    expect(scan?.error?.code).toBe('app_access_revoked');
    expect(scan?.error?.message).toMatch(/no longer has access/);
  });

  it('a GitHub outage is transient: retrying, then the scan recovers', async () => {
    privateGitHub({ mint: 502 });
    const id = await privateScan();
    await expect(pipeline.run(id, signal())).rejects.toBeInstanceOf(TransientError);
    expect((await scans.get(id))?.status).toBe('retrying');
    server.resetHandlers();
    privateGitHub();
    expect(await pipeline.run(id, signal())).toBe('completed');
  });
});
