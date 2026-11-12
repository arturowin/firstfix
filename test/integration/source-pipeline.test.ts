/**
 * Source checks inside the one scan job (docs/ARCHITECTURE.md "Source checks", status table a–f), with real
 * Postgres, the real pipeline and report, and fake GitHub/advisory ports.
 */
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { buildReport } from '../../src/application/report.ts';
import { ScanPipeline } from '../../src/application/scan-pipeline.ts';
import { purgeExpired } from '../../src/application/retention.ts';
import type { Advisory } from '../../src/domain/advisory.ts';
import { defaultRegistry } from '../../src/domain/ecosystems/registry.ts';
import type { TreeEntry } from '../../src/domain/source-files.ts';
import { PermanentError, TransientError } from '../../src/ports/errors.ts';
import type { RepoSource } from '../../src/ports/repo-source.ts';
import type { VulnDatabase } from '../../src/ports/vuln-database.ts';
import { TemplateExplainer } from '../../src/adapters/template-explainer.ts';
import type { ScanRepository } from '../../src/ports/scan-repository.ts';
import { createTestEnv, type TestEnv } from '../support/env.ts';

const SHA = 'b'.repeat(40);
const TREE = 'e'.repeat(40);
const signal = () => new AbortController().signal;
const flagged = readFileSync(path.join(import.meta.dirname, '..', 'fixtures', 'source', 'flagged.ts.txt'), 'utf8');
const blob = (p: string): TreeEntry => ({ path: p, type: 'blob', mode: '100644', size: 100, sha: `s-${p}` });

const LOCK = JSON.stringify({
  name: 'x',
  lockfileVersion: 3,
  packages: { '': { dependencies: { a: '1.0.0' } }, 'node_modules/a': { version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz' } },
});
const advisory: Advisory = { id: 'GHSA-aaaa-bbbb-cccc', aliases: [], title: 't', severity: 'high', isMalicious: false, affectedRanges: [], references: [] };

interface RepoOptions {
  lock?: string | null;
  files?: Record<string, string>;
  /** Thrown when listing the tree (source check). */
  listError?: Error;
}

function repo(o: RepoOptions): RepoSource {
  const files = o.files ?? {};
  return {
    resolveDefaultCommit: () => Promise.resolve({ sha: SHA, branch: 'main', treeSha: TREE }),
    readFile: (_r, _a, _s, p) => Promise.resolve(p === 'package-lock.json' ? (o.lock ?? null) : null),
    listTree: () => (o.listError ? Promise.reject(o.listError) : Promise.resolve({ entries: Object.keys(files).map(blob), truncated: false })),
    readSourceFile: (_r, _a, _s, p) => Promise.resolve(files[p] ?? null),
  };
}

function vulns(fail?: Error): VulnDatabase {
  return {
    source: { name: 'Test advisories', url: 'https://advisories.test' },
    lookup: () =>
      fail ? Promise.reject(fail) : Promise.resolve({ advisories: new Map([['npm:a@1.0.0', [advisory]]]), failed: [], incomplete: [] }),
  };
}

const down = () => new TransientError('github_unavailable', 'GitHub answered 502');

describe('source checks in the scan pipeline', () => {
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
    await env.pool.query(`INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized) VALUES ($1, 'acme', 'app', 'https://github.com/acme/app')`, [id]);
    return id;
  }

  const run = (source: RepoSource, v: VulnDatabase = vulns(), lastAttempt = false) =>
    newScan().then(async (id) => ({ id, result: await new ScanPipeline({ scans, source, vulns: v }).run(id, signal(), { lastAttempt }) }));

  const report = async (id: string) => {
    const data = await scans.getReport(id);
    if (!data) throw new Error('no report');
    return buildReport(data, defaultRegistry);
  };

  it('a. both checks succeed: separate sections, source findings kept apart from packages and upgrades', async () => {
    const { id, result } = await run(repo({ lock: LOCK, files: { 'src/flagged.ts': flagged, 'src/ok.ts': 'export const a = 1;' } }));
    expect(result).toBe('completed');
    const r = await report(id);
    expect(r.scan.checks).toMatchObject({ dependency: { status: 'complete' }, source: { status: 'complete', counts: { eligible: 2, checked: 2 } } });
    expect(r.actions.map((a) => a.package)).toEqual(['a']); // upgrades: dependencies only
    expect(r.summary).toMatch(/^1 package with known vulnerabilities/); // the dependency summary doesn't count source findings
    expect(r.source?.summary).toBe('Source checks: 3 findings (1 high, 2 medium) in 2 of 2 JavaScript/TypeScript files.');
    expect(r.source?.findings.map((f) => [f.ruleId, f.path, f.start.line])).toEqual([
      ['FF-TLS-001', 'src/flagged.ts', 5],
      ['FF-TLS-002', 'src/flagged.ts', 9],
      ['FF-TLS-002', 'src/flagged.ts', 13],
    ]);
    expect(r.source?.findings[0]).toMatchObject({
      severity: 'high',
      excerpt: "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'",
      url: `https://github.com/acme/app/blob/${SHA}/src/flagged.ts#L5`,
      testFile: false,
      title: 'TLS certificate verification disabled for the whole process',
    });
  });

  it('b. no lockfile, source checks succeed: completed, and the report says why dependencies weren’t checked', async () => {
    const { id, result } = await run(repo({ lock: null, files: { 'test/flagged.ts': flagged } }));
    expect(result).toBe('completed');
    const r = await report(id);
    expect(r.scan).toMatchObject({ status: 'completed', coverage: null, checks: { dependency: { status: 'unsupported', error: { code: 'no_lockfile' } } } });
    expect(r.dependencyNotChecked).toMatchObject({ status: 'unsupported', message: expect.stringMatching(/package-lock\.json/) as unknown });
    expect(r.summary).toBeNull();
    expect(r.actions).toEqual([]);
    expect(r.agentPrompt).toBeNull();
    expect(r.source?.findings).toHaveLength(3);
    expect(r.source?.findings.every((f) => f.testFile)).toBe(true); // in test code: labelled, still reported
  });

  it('c. dependencies succeed, source coverage partial', async () => {
    const files = { 'a.ts': 'x', 'b.ts': 'y', 'c.ts': 'z' };
    const pipeline = new ScanPipeline({
      scans,
      source: repo({ lock: LOCK, files }),
      vulns: vulns(),
      sourceCheck: { limits: { maxFiles: 2, maxFileBytes: 1000, maxTotalBytes: 10_000 }, concurrency: 2, budgetMs: 5000, maxFindings: 10 },
    });
    const id = await newScan();
    expect(await pipeline.run(id, signal())).toBe('completed');
    const r = await report(id);
    expect(r.scan.checks.source).toMatchObject({ status: 'partial', counts: { eligible: 3, checked: 2, skippedLimit: 1 } });
    expect(r.source?.summary).toBe('Partial source check: no issues found by the 2 supported checks in 2 of 3 JavaScript/TypeScript files.');
  });

  it('d1. source check fails on the last attempt: the dependency result is kept, source shown as failed', async () => {
    const { id, result } = await run(repo({ lock: LOCK, listError: down() }), vulns(), true);
    expect(result).toBe('completed');
    const r = await report(id);
    expect(r.actions).toHaveLength(1);
    expect(r.scan.checks.source).toMatchObject({ status: 'failed', error: { code: 'github_unavailable', message: 'Retries exhausted: GitHub answered 502' } });
    expect(r.source?.summary).toBe('Source checks failed: Retries exhausted: GitHub answered 502');
  });

  it('d2. dependency check fails on the last attempt: the source result is kept, dependencies shown as failed', async () => {
    const { id, result } = await run(repo({ lock: LOCK, files: { 'src/flagged.ts': flagged } }), vulns(new TransientError('osv_unavailable', 'OSV answered 503')), true);
    expect(result).toBe('completed');
    const r = await report(id);
    expect(r.dependencyNotChecked).toEqual({ status: 'failed', message: 'Retries exhausted: OSV answered 503' });
    expect(r.source?.findings).toHaveLength(3);
  });

  it('a transient failure before the last attempt retries the whole job (nothing saved halfway)', async () => {
    const id = await newScan();
    const pipeline = new ScanPipeline({ scans, source: repo({ lock: LOCK, listError: down() }), vulns: vulns() });
    await expect(pipeline.run(id, signal(), { lastAttempt: false })).rejects.toBeInstanceOf(TransientError);
    const scan = await scans.get(id);
    expect(scan).toMatchObject({ status: 'retrying', error: { code: 'github_unavailable' }, checks: { dependency: null, source: null } });
  });

  it('e. neither usable, one failed: failed with both reasons, and the error still reaches the queue', async () => {
    const id = await newScan();
    const pipeline = new ScanPipeline({ scans, source: repo({ lock: null, listError: down() }), vulns: vulns() });
    await expect(pipeline.run(id, signal(), { lastAttempt: true })).rejects.toBeInstanceOf(TransientError);
    const scan = await scans.get(id);
    expect(scan?.status).toBe('failed');
    expect(scan?.error?.code).toBe('github_unavailable');
    expect(scan?.error?.message).toMatch(/^Source checks failed: Retries exhausted: GitHub answered 502\. Dependencies: /);
    expect(scan?.checks).toMatchObject({ dependency: { status: 'unsupported' }, source: { status: 'failed' } });
  });

  it('e′. nothing to check at all (no lockfile, no source files): unsupported, as before source checks', async () => {
    const { id, result } = await run(repo({ lock: null, files: { 'README.md': '# hi' } }));
    expect(result).toBe('unsupported');
    expect(await scans.get(id)).toMatchObject({
      status: 'unsupported',
      error: { code: 'no_lockfile' },
      checks: { dependency: { status: 'unsupported' }, source: { status: 'no_files' } },
    });
  });

  it('f. no eligible source files: the dependency result decides; the report says so', async () => {
    const { id, result } = await run(repo({ lock: LOCK, files: {} }));
    expect(result).toBe('completed');
    expect((await report(id)).source?.summary).toBe('Source checks: no JavaScript/TypeScript files to check.');
  });

  it('a shared failure (access lost during the source check) ends the scan, as before', async () => {
    const revoked = new PermanentError('app_access_revoked', 'FirstFix no longer has access to this repository.');
    const { id, result } = await run(repo({ lock: LOCK, listError: revoked }), vulns(), true);
    expect(result).toBe('failed');
    expect((await scans.get(id))?.error?.code).toBe('app_access_revoked');
  });

  it('a file that breaks the tokenizer never fails the scan: dependency results kept, source partial', async () => {
    const deep = `${'`${'.repeat(3000)}\`${'}`'.repeat(3000)}`;
    const { id, result } = await run(repo({ lock: LOCK, files: { 'deep.ts': deep, 'src/flagged.ts': flagged } }));
    expect(result).toBe('completed');
    const r = await report(id);
    expect(r.actions.map((a) => a.package)).toEqual(['a']);
    expect(r.scan.checks.source).toMatchObject({ status: 'partial', counts: { checked: 1, skippedParse: 1 } });
    expect(r.source?.findings).toHaveLength(3);
  });

  it('the report counts every match, even beyond the stored examples, and keeps the high-severity one', async () => {
    const many = `${Array.from({ length: 30 }, () => '{ rejectUnauthorized: false }').join('\n')}\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';`;
    const pipeline = new ScanPipeline({
      scans,
      source: repo({ lock: LOCK, files: { 'a.ts': many } }),
      vulns: vulns(),
      sourceCheck: { limits: { maxFiles: 10, maxFileBytes: 100_000, maxTotalBytes: 1_000_000 }, concurrency: 2, budgetMs: 5000, maxFindings: 5 },
    });
    const id = await newScan();
    expect(await pipeline.run(id, signal())).toBe('completed');
    const r = await report(id);
    expect(r.source?.findings).toHaveLength(5);
    expect(r.source?.findings[0]?.ruleId).toBe('FF-TLS-001');
    expect(r.source?.rules.map((x) => [x.id, x.matches, x.shown])).toEqual([
      ['FF-TLS-001', 1, 1],
      ['FF-TLS-002', 30, 4],
    ]);
    expect(r.source?.summary).toBe(
      'Source checks: 31 findings (1 high, 30 medium) in 1 of 1 JavaScript/TypeScript file. More matches were found than are shown.',
    );
  });

  it('a stale attempt writes nothing, source findings included', async () => {
    const id = await newScan();
    const stale = await scans.claim(id);
    if (!stale) throw new Error('claim failed');
    await scans.claim(id); // a newer attempt owns the scan now
    const saved = await scans.complete(stale, {
      advisorySource: null,
      summaryLine: null,
      explanation: null,
      counts: { totalDeps: 0, checkedDeps: 0, unsupportedDeps: 0, failedLookups: 0 },
      coverage: null,
      findings: [],
      unchecked: [],
      dependency: { status: 'unsupported', error: { code: 'no_lockfile', message: 'x' } },
      source: { status: 'complete', counts: { eligible: 1, checked: 1, skippedLimit: 0, skippedSize: 0, skippedLinks: 0, skippedTime: 0, fetchFailed: 0, skippedParse: 0, listingTruncated: false, findingsTruncated: false }, error: null },
      sourceFindings: [{ ruleId: 'FF-TLS-002', ruleVersion: 1, severity: 'medium', path: 'a.ts', start: { line: 1, column: 1 }, end: { line: 1, column: 5 }, excerpt: 'x' }],
    });
    expect(saved).toBe(false);
    const { rows } = await env.pool.query<{ n: number }>('SELECT count(*)::int AS n FROM source_findings WHERE scan_id = $1', [id]);
    expect(rows[0]?.n).toBe(0);
  });

  it('older scans (no source data) say source checks were not run', async () => {
    const { id } = await run(repo({ lock: LOCK, files: {} }));
    await env.pool.query(`ALTER TABLE scans DISABLE TRIGGER USER`);
    try {
      await env.pool.query(`UPDATE scans SET source_status = NULL, source_counts = NULL, dependency_status = NULL WHERE id = $1`, [id]);
    } finally {
      await env.pool.query(`ALTER TABLE scans ENABLE TRIGGER USER`);
    }
    const r = await report(id);
    expect(r.scan.checks).toEqual({ dependency: null, source: null });
    expect(r.source).toMatchObject({ status: null, summary: 'Source checks were not run for this scan.', findings: [] });
    expect(r.actions).toHaveLength(1); // the dependency part reads exactly as before
  });

  it('stages run in order: read dependencies, check vulnerabilities, check source code, then prioritize', async () => {
    const stages: string[] = [];
    const recording = new Proxy(scans, {
      get(target, prop, receiver) {
        if (prop === 'recordProgress') {
          return (claim: Parameters<ScanRepository['recordProgress']>[0], update: Parameters<ScanRepository['recordProgress']>[1]) => {
            if (update.stage) stages.push(update.stage);
            return target.recordProgress(claim, update);
          };
        }
        return Reflect.get(target, prop, receiver) as unknown;
      },
    });
    const id = await newScan();
    const pipeline = new ScanPipeline({ scans: recording, source: repo({ lock: LOCK, files: { 'a.ts': 'x' } }), vulns: vulns() });
    expect(await pipeline.run(id, signal())).toBe('completed');
    expect(stages).toEqual(['scanning', 'source', 'analyzing']); // 'fetching' is set by the claim
  });

  it('source issues are explained: per-rule "why it matters" stored with the scan, also without a usable lockfile', async () => {
    const explain = { ai: null, template: new TemplateExplainer(), timeoutMs: 1000 };
    for (const lock of [LOCK, null]) {
      const id = await newScan();
      const pipeline = new ScanPipeline({ scans, source: repo({ lock, files: { 'src/flagged.ts': flagged } }), vulns: vulns(), explain });
      expect(await pipeline.run(id, signal())).toBe('completed');
      const r = await report(id);
      expect(r.explanation?.source).toBe('template');
      expect(r.source?.findings.map((f) => f.whyItMatters.source)).toEqual(['template', 'template', 'template']);
      expect(r.source?.findings[0]?.whyItMatters.text).toMatch(/NODE_TLS_REJECT_UNAUTHORIZED/);
      if (lock === null) {
        // Without dependencies, the summary paragraph is about the source findings.
        expect(r.explanation?.text).toMatch(/^Start with the process-wide TLS setting/);
      }
    }
  });

  it('retention deletes source findings with their scan', async () => {
    const { id } = await run(repo({ lock: LOCK, files: { 'src/flagged.ts': flagged } }));
    await env.pool.query(`UPDATE scans SET completed_at = now() - interval '40 days' WHERE id = $1`, [id]);
    await purgeExpired(scans, { scanDays: 30, keyHours: 24 });
    const { rows } = await env.pool.query<{ n: number }>('SELECT count(*)::int AS n FROM source_findings WHERE scan_id = $1', [id]);
    expect(rows[0]?.n).toBe(0);
  });
});
