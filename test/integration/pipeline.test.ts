import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { ScanPipeline } from '../../src/application/scan-pipeline.ts';
import type { Advisory } from '../../src/domain/advisory.ts';
import { PermanentError, TransientError } from '../../src/ports/errors.ts';
import type { RepoSource } from '../../src/ports/repo-source.ts';
import type { AdvisoryLookup, VulnDatabase } from '../../src/ports/vuln-database.ts';
import { createTestEnv, type TestEnv } from '../support/env.ts';

const SHA = 'b'.repeat(40);
const signal = () => new AbortController().signal;

function lockfile(packages: Record<string, unknown>, lockfileVersion = 3): string {
  return JSON.stringify({ name: 'x', lockfileVersion, packages: { '': { dependencies: { a: '1.0.0' } }, ...packages } });
}

function source(lock: string | null | Error): RepoSource {
  return {
    resolveDefaultCommit: () => Promise.resolve({ sha: SHA, branch: 'main' }),
    readFile: (_repo, _sha, path) =>
      lock instanceof Error ? Promise.reject(lock) : Promise.resolve(path === 'package-lock.json' ? lock : null),
  };
}

const advisory = (id: string): Advisory => ({
  id,
  aliases: [],
  title: `title ${id}`,
  severity: 'high',
  isMalicious: id.startsWith('MAL-'), // this fake plays the adapter, which owns the malicious flag
  affectedRanges: [],
  references: [],
});

function vulns(result: AdvisoryLookup | Error, onLookup?: () => Promise<void>): VulnDatabase {
  return {
    source: { name: 'Test advisories', url: 'https://advisories.test' },
    lookup: async () => {
      await onLookup?.();
      if (result instanceof Error) throw result;
      return result;
    },
  };
}

describe('ScanPipeline (real Postgres, fake GitHub/OSV ports)', () => {
  let env: TestEnv;
  let scans: PostgresScanRepository;

  beforeAll(async () => {
    env = await createTestEnv();
    scans = new PostgresScanRepository(env.pool);
  });

  afterAll(async () => {
    await env.close();
  });

  async function newScan(): Promise<string> {
    const id = randomUUID();
    await env.pool.query(
      `INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized) VALUES ($1, 'o', 'r', 'https://github.com/o/r')`,
      [id],
    );
    return id;
  }

  const twoPackages = lockfile({
    'node_modules/a': { version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz' },
    'node_modules/b': { version: '2.0.0', dev: true },
    'node_modules/g': { version: '1.0.0', resolved: 'git+ssh://git@github.com/o/g.git#abc' },
  });

  it('completes: commit pinned, counts, findings per advisory, unchecked deps', async () => {
    const id = await newScan();
    const pipeline = new ScanPipeline({
      scans,
      source: source(twoPackages),
      vulns: vulns(new Map([['npm:a@1.0.0', [advisory('GHSA-1'), advisory('MAL-1')]]])),
    });
    expect(await pipeline.run(id, signal())).toBe('completed');

    const report = await scans.getReport(id);
    expect(report?.scan).toMatchObject({
      status: 'completed',
      commitSha: SHA,
      lockfilePath: 'package-lock.json',
      advisorySource: 'Test advisories',
      // a@1.0.0 carries MAL-1 (malicious by id in this fake): the summary leads with it.
      summaryLine: expect.stringMatching(/^1 known malicious package in 2 of 3 dependencies checked\. Start with: remove a/) as string,
      coverage: 'full',
      counts: { totalDeps: 3, checkedDeps: 2, unsupportedDeps: 1, failedLookups: 0 },
    });
    expect(report?.findings.map((f) => [f.package, f.advisoryId, f.scope, f.isDirect])).toEqual([
      ['a', 'GHSA-1', 'runtime', true],
      ['a', 'MAL-1', 'runtime', true],
    ]);
    expect(report?.unchecked).toEqual([{ ecosystem: 'npm', package: 'g', version: '1.0.0', reason: 'unsupported_source' }]);
  });

  it('zero dependencies → completed with nothing to check', async () => {
    const id = await newScan();
    const pipeline = new ScanPipeline({ scans, source: source(lockfile({})), vulns: vulns(new Map()) });
    expect(await pipeline.run(id, signal())).toBe('completed');
    expect(await scans.get(id)).toMatchObject({
      status: 'completed',
      counts: { totalDeps: 0, checkedDeps: 0 },
      summaryLine: 'No dependencies to check in package-lock.json.',
    });
  });

  it.each([
    ['no lockfile', null, 'no_lockfile', /No package-lock.json at the repository root \(commit bbbbbbb\)/],
    ['lockfile v1', lockfile({}, 1), 'unsupported_lockfile', /lockfileVersion 1/],
    ['invalid JSON', '{not json', 'invalid_lockfile', /not valid JSON/],
  ])('%s → unsupported with a reason; returns normally (no retry)', async (_l, lock, code, message) => {
    const id = await newScan();
    const pipeline = new ScanPipeline({ scans, source: source(lock), vulns: vulns(new Map()) });
    expect(await pipeline.run(id, signal())).toBe('unsupported');
    const scan = await scans.get(id);
    expect(scan).toMatchObject({ status: 'unsupported', commitSha: SHA, error: { code } });
    expect(scan?.error?.message).toMatch(message);
  });

  it('repository not found → failed; returns normally', async () => {
    const id = await newScan();
    const pipeline = new ScanPipeline({
      scans,
      source: {
        resolveDefaultCommit: () => Promise.reject(new PermanentError('repo_not_found', 'Repository not found or private')),
        readFile: () => Promise.resolve(null),
      },
      vulns: vulns(new Map()),
    });
    expect(await pipeline.run(id, signal())).toBe('failed');
    expect(await scans.get(id)).toMatchObject({
      status: 'failed',
      error: { code: 'repo_not_found', message: 'Repository not found or private' },
    });
  });

  it('a transient error propagates (pg-boss retries) and leaves the scan non-terminal', async () => {
    const id = await newScan();
    const pipeline = new ScanPipeline({
      scans,
      source: source(twoPackages),
      vulns: vulns(new TransientError('osv_unavailable', 'OSV answered 503')),
    });
    await expect(pipeline.run(id, signal())).rejects.toBeInstanceOf(TransientError);
    expect(await scans.get(id)).toMatchObject({ status: 'running', stage: 'scanning' });

    // The retry (next attempt) completes normally.
    const retry = new ScanPipeline({ scans, source: source(twoPackages), vulns: vulns(new Map()) });
    expect(await retry.run(id, signal())).toBe('completed');
  });

  it('if a newer attempt takes over mid-scan, the old one stops without writing', async () => {
    const id = await newScan();
    let newer: Awaited<ReturnType<typeof scans.claim>> = null;
    const pipeline = new ScanPipeline({
      scans,
      source: source(twoPackages),
      // While the old attempt waits on OSV, the job is re-delivered and claimed again.
      vulns: vulns(new Map([['npm:a@1.0.0', [advisory('GHSA-1')]]]), async () => {
        newer = await scans.claim(id);
      }),
    });
    expect(await pipeline.run(id, signal())).toBe('stale');
    expect(newer).toMatchObject({ attempt: 2 });
    expect(await scans.get(id)).toMatchObject({ status: 'running', stage: 'fetching' });
    const f = await env.pool.query('SELECT 1 FROM findings WHERE scan_id = $1', [id]);
    expect(f.rows).toHaveLength(0);
  });

  it('a duplicate delivery after completion does nothing', async () => {
    const id = await newScan();
    const pipeline = new ScanPipeline({ scans, source: source(twoPackages), vulns: vulns(new Map()) });
    expect(await pipeline.run(id, signal())).toBe('completed');
    expect(await pipeline.run(id, signal())).toBe('not_claimed');
  });
});
