import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { purgeExpired } from '../../src/application/retention.ts';
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
    advisorySource: 'OSV.dev',
    summaryLine: '1 package with known vulnerabilities (1 medium) in 2 of 3 dependencies checked.',
    explanation: null,
    counts: { totalDeps: 3, checkedDeps: 2, unsupportedDeps: 1, failedLookups: 0 },
    coverage: 'full',
    findings: [
      {
        ecosystem: 'npm',
        package: 'lodash',
        installedAs: ['lodash', 'my-lodash'],
        directAs: ['lodash', 'my-lodash'],
        installedVersion: '4.17.20',
        scope: 'runtime',
        isDirect: true,
        directParents: [],
        installPaths: [['lodash']],
        candidateVersion: '4.17.21',
        fixStatus: 'candidate',
        advisory: {
          id: 'GHSA-29mw-wpgm-hmr9',
          aliases: ['CVE-2020-28500'],
          title: 'ReDoS in lodash',
          severity: 'medium',
          isMalicious: false,
          affectedRanges: [{ kind: 'range', introduced: '4.0.0', fixed: '4.17.21', lastAffected: null }],
          references: [{ type: 'ADVISORY', url: 'https://example.com' }],
        },
      },
    ],
    unchecked: [{ ecosystem: 'npm', package: 'slash', version: '5.1.0', reason: 'unsupported_source' }],
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
        ecosystem: 'npm',
        package: 'lodash',
        installedAs: ['lodash', 'my-lodash'],
        directAs: ['lodash', 'my-lodash'],
        installedVersion: '4.17.20',
        scope: 'runtime',
        isDirect: true,
        directParents: [],
        installPaths: [['lodash']],
        advisoryId: 'GHSA-29mw-wpgm-hmr9',
        aliases: ['CVE-2020-28500'],
        severity: 'medium',
        isMalicious: false,
        title: 'ReDoS in lodash',
        candidateVersion: '4.17.21',
        fixStatus: 'candidate',
        affectedRanges: [{ kind: 'range', introduced: '4.0.0', fixed: '4.17.21', lastAffected: null }],
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

  it('ranges stored before they were provider-neutral read back as null (nothing claimed from them)', async () => {
    const id = await newScan();
    const claim = await repo.claim(id);
    if (!claim) throw new Error('claim failed');
    await repo.complete(claim, completion);
    await env.pool.query(
      `UPDATE findings SET affected_ranges = '[{"type":"SEMVER","events":[{"introduced":"0"}]}]' WHERE scan_id = $1`,
      [id],
    );
    expect((await repo.getReport(id))?.findings[0]?.affectedRanges).toBeNull();
  });

  it('retention: old finished scans go with their findings and keys; recent and unfinished ones stay; old keys expire', async () => {
    const old = await newScan();
    const recent = await newScan();
    const stuckOld = await newScan(); // not finished: never deleted, however old
    for (const id of [old, recent]) {
      const claim = await repo.claim(id);
      if (!claim) throw new Error('claim failed');
      await repo.complete(claim, completion);
    }
    await env.pool.query(`UPDATE scans SET completed_at = now() - interval '40 days' WHERE id = $1`, [old]);
    await env.pool.query(`UPDATE scans SET created_at = now() - interval '400 days' WHERE id = $1`, [stuckOld]);
    await env.pool.query(
      `INSERT INTO idempotency_keys (key, request_hash, scan_id, created_at) VALUES
         ('ret-old-key', 'h', $1, now() - interval '30 hours'), ('ret-new-key', 'h', $1, now())`,
      [recent],
    );

    const r = await purgeExpired(repo, { scanDays: 30, keyHours: 24 });
    expect(r.scans).toBeGreaterThanOrEqual(1);
    expect(await repo.get(old)).toBeNull();
    const orphans = await env.pool.query('SELECT 1 FROM findings WHERE scan_id = $1 UNION ALL SELECT 1 FROM unchecked_deps WHERE scan_id = $1', [old]);
    expect(orphans.rows).toHaveLength(0);
    expect(await repo.get(recent)).not.toBeNull();
    expect(await repo.get(stuckOld)).not.toBeNull();
    const keys = await env.pool.query<{ key: string }>(`SELECT key FROM idempotency_keys WHERE key LIKE 'ret-%' ORDER BY key`);
    expect(keys.rows.map((k) => k.key)).toEqual(['ret-new-key']);
  });

  it('a failed completion transaction leaves no partial findings', async () => {
    const id = await newScan();
    const claim = await repo.claim(id);
    if (!claim) throw new Error('claim failed');
    const bad: Completion = {
      ...completion,
      // unchecked reason violates the CHECK constraint after findings were inserted
      unchecked: [{ ecosystem: 'npm', package: 'x', version: null, reason: 'nope' as 'lookup_failed' }],
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
