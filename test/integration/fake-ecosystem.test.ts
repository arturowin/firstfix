/**
 * Proof of the ecosystem seams (docs/ARCHITECTURE.md "Ecosystems"): a test-only ecosystem with its own
 * lockfile format goes through the real pipeline, GitHub and OSV adapters (network mocked) and Postgres.
 * Nothing outside the registry passed to the pipeline knows about it.
 */
import { randomUUID } from 'node:crypto';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GitHubRepoSource } from '../../src/adapters/github/repo-source.ts';
import { OsvVulnDatabase } from '../../src/adapters/osv/vuln-database.ts';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { ScanPipeline } from '../../src/application/scan-pipeline.ts';
import { npm } from '../../src/domain/ecosystems/npm/index.ts';
import { packageLockFormat } from '../../src/domain/ecosystems/npm/package-lock.ts';
import type { Ecosystem, EcosystemRegistry, LockfileFormat } from '../../src/domain/ecosystems/types.ts';
import type { LockedPackage, UncheckablePackage } from '../../src/domain/lockfile.ts';
import { createTestEnv, type TestEnv } from '../support/env.ts';

const SHA = 'f'.repeat(40);
const ECOSYSTEM = 'Fakeco';

/** `name==version` per line; `name @ path` is a local source we cannot check. */
const fakeFormat: LockfileFormat = {
  ecosystem: ECOSYSTEM,
  fileNames: ['fake.lock'],
  parse(text) {
    const packages: LockedPackage[] = [];
    const uncheckable: UncheckablePackage[] = [];
    for (const line of text.split('\n').map((l) => l.trim()).filter(Boolean)) {
      const [name, version] = line.split('==');
      if (name && version) packages.push({ name, installedAs: [], version, scope: 'runtime', isDirect: true, directParents: [], installPaths: [[name]] });
      else uncheckable.push({ name: line.split(' @ ')[0] ?? line, version: null, reason: 'unsupported_source' });
    }
    return { kind: 'ok', packages, uncheckable };
  },
};

const fake: Ecosystem = {
  id: ECOSYSTEM,
  label: 'Fakeco',
  versionScheme: null, // no scheme: findings still reported, without candidates
  hints: {
    upgradeCommand: (p, v) => `fake add ${p}==${v}`,
    inspectCommand: (p) => `fake why ${p}`,
    transitiveFix: 'a fake constraint',
    ciChecks: ['fake audit'],
  },
};

const registry: EcosystemRegistry = {
  formats: [packageLockFormat, fakeFormat],
  ecosystems: new Map([
    [npm.id, npm],
    [fake.id, fake],
  ]),
};

const osvQueries: { package: { ecosystem: string; name: string }; version: string }[] = [];

const server = setupServer(
  http.get('https://api.github.com/repos/o/:repo', () => HttpResponse.json({ default_branch: 'main' })),
  http.get('https://api.github.com/repos/o/:repo/commits/main', () => HttpResponse.json({ sha: SHA })),
  http.get(`https://raw.githubusercontent.com/o/fakeco/${SHA}/fake.lock`, () =>
    HttpResponse.text('widget==1.2.0\nclean==2.0.0\nlocal @ ./vendor/local\n'),
  ),
  // Every other file (package-lock.json here, anything in o/nothing) is absent.
  http.get('https://raw.githubusercontent.com/o/*', () => new HttpResponse(null, { status: 404 })),
  http.post('https://api.osv.dev/v1/querybatch', async ({ request }) => {
    const { queries } = (await request.json()) as { queries: typeof osvQueries };
    osvQueries.push(...queries);
    return HttpResponse.json({
      results: queries.map((q) => (q.package.name === 'widget' ? { vulns: [{ id: 'FAKE-2026-1' }] } : {})),
    });
  }),
  http.get('https://api.osv.dev/v1/vulns/FAKE-2026-1', () =>
    HttpResponse.json({
      id: 'FAKE-2026-1',
      summary: 'Widget does something bad',
      database_specific: { severity: 'HIGH' },
      affected: [
        { package: { ecosystem: ECOSYSTEM, name: 'widget' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.3.0' }] }] },
        { package: { ecosystem: 'npm', name: 'widget' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.0.0' }] }] },
      ],
    }),
  ),
);

describe('a test-only ecosystem through the real pipeline', () => {
  let env: TestEnv;
  let scans: PostgresScanRepository;
  let pipeline: ScanPipeline;

  beforeAll(async () => {
    server.listen({ onUnhandledFrame: 'error' });
    env = await createTestEnv();
    scans = new PostgresScanRepository(env.pool);
    pipeline = new ScanPipeline({ scans, source: new GitHubRepoSource(), vulns: new OsvVulnDatabase(), registry });
  });

  afterAll(async () => {
    await env.close();
    server.close();
  });

  async function newScan(repo: string): Promise<string> {
    const id = randomUUID();
    await env.pool.query(
      `INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized) VALUES ($1, 'o', $2, $3)`,
      [id, repo, `https://github.com/o/${repo}`],
    );
    return id;
  }

  it('finds its lockfile after npm’s is absent, queries OSV in its ecosystem, stores findings under it', async () => {
    const id = await newScan('fakeco');
    expect(await pipeline.run(id, new AbortController().signal)).toBe('completed');

    expect(osvQueries.map((q) => q.package.ecosystem)).toEqual([ECOSYSTEM, ECOSYSTEM]);
    const report = await scans.getReport(id);
    expect(report?.scan).toMatchObject({
      status: 'completed',
      lockfilePath: 'fake.lock',
      counts: { totalDeps: 3, checkedDeps: 2, unsupportedDeps: 1 },
    });
    expect(report?.findings.map((f) => [f.ecosystem, f.package, f.installedVersion, f.advisoryId, f.severity])).toEqual([
      [ECOSYSTEM, 'widget', '1.2.0', 'FAKE-2026-1', 'high'],
    ]);
    // No version scheme for this ecosystem: no candidate is guessed.
    expect(report?.findings[0]).toMatchObject({ candidateVersion: null, fixStatus: 'unknown' });
    const ranges = await env.pool.query<{ affected_ranges: unknown }>('SELECT affected_ranges FROM findings WHERE scan_id = $1', [id]);
    // Only the Fakeco entry of the advisory applies, not the npm package of the same name.
    expect(ranges.rows[0]?.affected_ranges).toEqual([{ kind: 'range', introduced: '0', fixed: '1.3.0', lastAffected: null }]);
    expect(report?.unchecked).toEqual([{ ecosystem: ECOSYSTEM, package: 'local', version: null, reason: 'unsupported_source' }]);
  });

  it('no registered lockfile → unsupported, naming every supported file', async () => {
    const id = await newScan('nothing');
    expect(await pipeline.run(id, new AbortController().signal)).toBe('unsupported');
    expect((await scans.get(id))?.error).toEqual({
      code: 'no_lockfile',
      message: 'No package-lock.json or fake.lock at the repository root (commit fffffff). Only npm, Fakeco lockfiles are supported.',
    });
  });
});
