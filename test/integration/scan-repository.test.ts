import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import type { Completion } from '../../src/ports/scan-repository.ts';
import { createTestEnv, type TestEnv } from '../support/env.ts';

describe('PostgresScanRepository: attempt ownership', () => {
  let env: TestEnv;
  let repo: PostgresScanRepository;

  beforeAll(async () => {
    env = await createTestEnv();
    repo = new PostgresScanRepository(env.pool);
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

  const completion: Completion = {
    counts: { totalDeps: 3, checkedDeps: 2, unsupportedDeps: 1, failedLookups: 0 },
    coverage: 'full',
    findings: [
      {
        package: 'lodash',
        installedVersion: '4.17.20',
        scope: 'runtime',
        isDirect: true,
        directParents: [],
        installPaths: [['lodash']],
        candidateVersion: null,
        advisory: {
          id: 'GHSA-29mw-wpgm-hmr9',
          aliases: ['CVE-2020-28500'],
          title: 'ReDoS in lodash',
          severity: 'medium',
          isMalicious: false,
          affectedRanges: [{ type: 'SEMVER', events: [{ introduced: '4.0.0' }, { fixed: '4.17.21' }] }],
          references: [{ type: 'ADVISORY', url: 'https://example.com' }],
        },
      },
    ],
    unchecked: [{ package: 'slash', version: '5.1.0', reason: 'unsupported_source' }],
  };

  it('claim starts attempt 1 as running/fetching; a new claim makes the old attempt stale', async () => {
    const id = await newScan();
    const first = await repo.claim(id);
    expect(first).toMatchObject({ scanId: id, attempt: 1 });
    expect(await repo.get(id)).toMatchObject({ status: 'running', stage: 'fetching' });

    const second = await repo.claim(id);
    expect(second?.attempt).toBe(2);
    if (!first || !second) return;

    // Every write from the stale attempt changes nothing.
    expect(await repo.recordProgress(first, { stage: 'scanning', commitSha: 'stale' })).toBe(false);
    expect(await repo.complete(first, completion)).toBe(false);
    expect(await repo.finish(first, { status: 'failed', code: 'x', message: 'stale' })).toBe(false);
    const scan = await repo.get(id);
    expect(scan).toMatchObject({ status: 'running', stage: 'fetching', commitSha: null });
    const f = await env.pool.query('SELECT 1 FROM findings WHERE scan_id = $1', [id]);
    expect(f.rows).toHaveLength(0);

    // The current attempt still can.
    expect(await repo.recordProgress(second, { stage: 'scanning', commitSha: 'abc', counts: { totalDeps: 3 } })).toBe(true);
    expect(await repo.get(id)).toMatchObject({ stage: 'scanning', commitSha: 'abc', counts: { totalDeps: 3 } });
  });

  it('complete writes findings, unchecked deps and the outcome atomically; the report reads them back', async () => {
    const id = await newScan();
    const claim = await repo.claim(id);
    if (!claim) throw new Error('claim failed');
    expect(await repo.complete(claim, completion)).toBe(true);

    const report = await repo.getReport(id);
    expect(report?.scan).toMatchObject({
      status: 'completed',
      stage: null,
      coverage: 'full',
      counts: completion.counts,
    });
    expect(report?.scan.completedAt).toBeInstanceOf(Date);
    expect(report?.findings).toEqual([
      {
        package: 'lodash',
        installedVersion: '4.17.20',
        scope: 'runtime',
        isDirect: true,
        directParents: [],
        advisoryId: 'GHSA-29mw-wpgm-hmr9',
        aliases: ['CVE-2020-28500'],
        severity: 'medium',
        isMalicious: false,
        title: 'ReDoS in lodash',
        candidateVersion: null,
        references: [{ type: 'ADVISORY', url: 'https://example.com' }],
      },
    ]);
    expect(report?.unchecked).toEqual(completion.unchecked);
  });

  it('a terminal scan cannot be claimed or completed again (duplicate delivery is a no-op)', async () => {
    const id = await newScan();
    const claim = await repo.claim(id);
    if (!claim) throw new Error('claim failed');
    await repo.finish(claim, { status: 'unsupported', code: 'no_lockfile', message: 'no package-lock.json' });

    expect(await repo.claim(id)).toBeNull();
    expect(await repo.complete(claim, completion)).toBe(false);
    expect(await repo.get(id)).toMatchObject({
      status: 'unsupported',
      error: { code: 'no_lockfile', message: 'no package-lock.json' },
    });
  });

  it('a failed completion transaction leaves no partial findings', async () => {
    const id = await newScan();
    const claim = await repo.claim(id);
    if (!claim) throw new Error('claim failed');
    const bad: Completion = {
      ...completion,
      // unchecked reason violates the CHECK constraint after findings were inserted
      unchecked: [{ package: 'x', version: null, reason: 'nope' as 'lookup_failed' }],
    };
    await expect(repo.complete(claim, bad)).rejects.toThrow(/check constraint/);
    const f = await env.pool.query('SELECT 1 FROM findings WHERE scan_id = $1', [id]);
    expect(f.rows).toHaveLength(0);
    expect(await repo.get(id)).toMatchObject({ status: 'running' });
  });

  it('unknown scan → null', async () => {
    expect(await repo.get(randomUUID())).toBeNull();
    expect(await repo.getReport(randomUUID())).toBeNull();
    expect(await repo.claim(randomUUID())).toBeNull();
  });
});
