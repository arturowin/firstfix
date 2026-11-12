/**
 * Lockfile strings PostgreSQL can't store as-is (NUL, lone UTF-16 surrogates) must not abort the report
 * transaction: they are normalised for display and the entries are still listed, alongside valid findings.
 */
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { ScanPipeline } from '../../src/application/scan-pipeline.ts';
import type { Advisory } from '../../src/domain/advisory.ts';
import type { RepoSource } from '../../src/ports/repo-source.ts';
import type { VulnDatabase } from '../../src/ports/vuln-database.ts';
import { createTestEnv, type TestEnv } from '../support/env.ts';

const reg = (n: string) => `https://registry.npmjs.org/${n}/-/${n}-1.0.0.tgz`;
// Built as an object and serialised, so the lockfile text carries real \u0000 and \ud800 escapes.
const lock = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { dependencies: { good: '1.0.0' } },
    'node_modules/good': { version: '1.0.0', resolved: reg('good') },
    'node_modules/bad\u0000name': { version: '1.0.0', resolved: reg('bad') },
    'node_modules/surrogate': { version: '1.0.0\ud800', resolved: reg('surrogate') },
    'node_modules/linked\u0000': { resolved: '../local\u0000', link: true },
    '../local\u0000': { version: '2.0.0\u0007' },
  },
});

const advisory: Advisory = { id: 'GHSA-1', aliases: [], title: 'bad', severity: 'high', isMalicious: false, affectedRanges: [], references: [] };

describe('malformed lockfile strings (review finding)', () => {
  let env: TestEnv;
  let scans: PostgresScanRepository;

  beforeAll(async () => {
    env = await createTestEnv();
    scans = new PostgresScanRepository(env.pool);
  });

  afterAll(async () => {
    await env.close();
  });

  it('a report with a NUL name, a lone-surrogate version and a malformed link saves, next to a valid finding', async () => {
    const id = randomUUID();
    await env.pool.query(
      `INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized) VALUES ($1, 'o', 'r', 'https://github.com/o/r')`,
      [id],
    );
    const source: RepoSource = {
      resolveDefaultCommit: () => Promise.resolve({ sha: 'a'.repeat(40), branch: 'main' }),
      readFile: (_r, _a, _s, p) => Promise.resolve(p === 'package-lock.json' ? lock : null),
    };
    const vulns: VulnDatabase = {
      source: { name: 'Test advisories', url: 'https://advisories.test' },
      lookup: () => Promise.resolve({ advisories: new Map([['npm:good@1.0.0', [advisory]]]), failed: [], incomplete: [] }),
    };
    expect(await new ScanPipeline({ scans, source, vulns }).run(id, new AbortController().signal)).toBe('completed');

    const report = await scans.getReport(id);
    expect(report?.findings.map((f) => [f.package, f.advisoryId])).toEqual([['good', 'GHSA-1']]);
    // Every malformed entry is still listed (never dropped), with a visible, storable form of its value.
    expect(report?.unchecked).toEqual(
      expect.arrayContaining([
        { ecosystem: 'npm', package: 'bad\\u0000name', version: '1.0.0', reason: 'invalid_name' },
        { ecosystem: 'npm', package: 'surrogate', version: '1.0.0�', reason: 'invalid_name' },
        { ecosystem: 'npm', package: 'linked\\u0000', version: '2.0.0\\u0007', reason: 'invalid_name' },
      ]),
    );
    expect(report?.unchecked).toHaveLength(3);
  });

  it('the repository itself stores any string safely (last line of defence, bypassing the parser)', async () => {
    const id = randomUUID();
    await env.pool.query(
      `INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized) VALUES ($1, 'o', 'r', 'https://github.com/o/r')`,
      [id],
    );
    const claim = await scans.claim(id);
    if (!claim) throw new Error('claim failed');
    const saved = await scans.complete(claim, {
      advisorySource: 'Test advisories',
      summaryLine: 'line',
      explanation: { source: 'template', summary: 'sum\u0000mary', actions: {} },
      counts: { totalDeps: 2, checkedDeps: 1, unsupportedDeps: 1, failedLookups: 0 },
      coverage: 'full',
      findings: [
        {
          ecosystem: 'npm', package: 'good', installedAs: [], directAs: ['good'], installedVersion: '1.0.0', scope: 'runtime',
          isDirect: true, directParents: [], installPaths: [['good']], contextTruncated: false, candidateVersion: null, fixStatus: 'unknown',
          advisory: { ...advisory, title: 'title with \u0000 and \ud800' },
        },
      ],
      unchecked: [{ ecosystem: 'npm', package: 'raw\u0000', version: '\udfff', reason: 'invalid_name' }],
    });
    expect(saved).toBe(true);
    const report = await scans.getReport(id);
    expect(report?.findings[0]?.title).toBe('title with \\u0000 and \ufffd');
    expect(report?.unchecked).toEqual([{ ecosystem: 'npm', package: 'raw\\u0000', version: '\ufffd', reason: 'invalid_name' }]);
  });
});
