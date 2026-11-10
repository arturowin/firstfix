import { randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { PostgresScanSubmission } from '../../src/adapters/postgres/scan-submission.ts';
import { buildApp } from '../../src/api/app.ts';
import { fixedWindowLimiter } from '../../src/api/rate-limit.ts';
import { ScanService } from '../../src/application/scan-service.ts';
import { createTestEnv, type TestEnv } from '../support/env.ts';

describe('HTTP API', () => {
  let env: TestEnv;
  let app: FastifyInstance;
  let webDir: string;
  let ready = true;

  beforeAll(async () => {
    env = await createTestEnv();
    webDir = await mkdtemp(path.join(tmpdir(), 'web-'));
    await writeFile(path.join(webDir, 'index.html'), '<!doctype html><title>AI Scan Review</title>');
    app = buildApp({
      scans: new ScanService(new PostgresScanSubmission(env.pool, env.boss), new PostgresScanRepository(env.pool)),
      checkReady: () => (ready ? Promise.resolve() : Promise.reject(new Error('down'))),
      webDir,
    });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
    await env.close();
    await rm(webDir, { recursive: true, force: true });
  });

  const post = (body: unknown, headers: Record<string, string> = {}) =>
    app.inject({ method: 'POST', url: '/scans', payload: body as object, headers });

  describe('POST /scans', () => {
    it('202 with the scan id and a Location header', async () => {
      const res = await post({ repoUrl: 'https://github.com/owner/repo' });
      expect(res.statusCode).toBe(202);
      const { scanId } = res.json<{ scanId: string }>();
      expect(scanId).toMatch(/^[0-9a-f-]{36}$/);
      expect(res.headers.location).toBe(`/scans/${scanId}`);
    });

    it.each([
      [{}, 'invalid_body'],
      [{ repoUrl: 42 }, 'invalid_body'],
      [{ repoUrl: 'https://github.com/a/b', extra: true }, 'invalid_body'],
      [{ repoUrl: 'https://gitlab.com/a/b' }, 'invalid_repo_url'],
      [{ repoUrl: 'https://github.com/a/b/tree/main' }, 'invalid_repo_url'],
    ])('400 for %j', async (body, code) => {
      const res = await post(body);
      expect(res.statusCode).toBe(400);
      expect(res.json<{ error: { code: string; message: string } }>().error.code).toBe(code);
    });

    it('400 tells the user what is wrong with the URL', async () => {
      const res = await post({ repoUrl: 'https://github.com/owner' });
      expect(res.json<{ error: { message: string } }>().error.message).toMatch(/owner and repository/);
    });

    it('Idempotency-Key: replay → 200 same id; different repo → 409', async () => {
      const first = await post({ repoUrl: 'https://github.com/a/idem' }, { 'idempotency-key': 'api-key-1' });
      const replay = await post({ repoUrl: 'https://github.com/A/idem.git' }, { 'idempotency-key': 'api-key-1' });
      const other = await post({ repoUrl: 'https://github.com/a/other' }, { 'idempotency-key': 'api-key-1' });
      expect(first.statusCode).toBe(202);
      expect(replay.statusCode).toBe(200);
      expect(replay.json()).toEqual(first.json());
      expect(other.statusCode).toBe(409);
      expect(other.json<{ error: { code: string } }>().error.code).toBe('idempotency_conflict');
    });

    it('400 for a malformed Idempotency-Key', async () => {
      const res = await post({ repoUrl: 'https://github.com/a/b' }, { 'idempotency-key': 'x'.repeat(201) });
      expect(res.statusCode).toBe(400);
      expect(res.json<{ error: { code: string } }>().error.code).toBe('invalid_idempotency_key');
    });
  });

  describe('admission control', () => {
    it('per-client limit → 429 with Retry-After; another client is unaffected', async () => {
      const limited = buildApp({
        scans: new ScanService(new PostgresScanSubmission(env.pool, env.boss), new PostgresScanRepository(env.pool)),
        checkReady: () => Promise.resolve(),
        webDir,
        submitLimiter: fixedWindowLimiter(2),
      });
      const send = (ip: string) =>
        limited.inject({ method: 'POST', url: '/scans', payload: { repoUrl: 'https://github.com/a/limited' }, remoteAddress: ip });
      expect((await send('10.0.0.1')).statusCode).toBe(202);
      expect((await send('10.0.0.1')).statusCode).toBe(202);
      const third = await send('10.0.0.1');
      expect(third.statusCode).toBe(429);
      expect(Number(third.headers['retry-after'])).toBeGreaterThan(0);
      expect(third.json<{ error: { code: string } }>().error.code).toBe('rate_limited');
      expect((await send('10.0.0.2')).statusCode).toBe(202);
      await limited.close();
    });

    it('outstanding-scan cap → 503 busy with Retry-After', async () => {
      const full = buildApp({
        scans: new ScanService(new PostgresScanSubmission(env.pool, env.boss, { maxOutstanding: 1 }), new PostgresScanRepository(env.pool)),
        checkReady: () => Promise.resolve(),
        webDir,
      });
      const res = await full.inject({ method: 'POST', url: '/scans', payload: { repoUrl: 'https://github.com/a/full' } });
      expect(res.statusCode).toBe(503);
      expect(res.headers['retry-after']).toBe('30');
      expect(res.json<{ error: { code: string } }>().error.code).toBe('busy');
      await full.close();
    });
  });

  describe('GET /scans/:id and /report', () => {
    it('returns the queued scan; the report is 409 until the scan finishes', async () => {
      const { scanId } = (await post({ repoUrl: 'https://github.com/a/status' })).json<{ scanId: string }>();
      const res = await app.inject({ url: `/scans/${scanId}` });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toMatchObject({
        id: scanId,
        status: 'queued',
        stage: null,
        repo: { url: 'https://github.com/a/status' },
        counts: { totalDeps: 0, checkedDeps: 0 },
      });
      const report = await app.inject({ url: `/scans/${scanId}/report` });
      expect(report.statusCode).toBe(409);
      expect(report.json<{ error: { code: string } }>().error.code).toBe('not_finished');
    });

    it('a finished scan has a report', async () => {
      const { scanId } = (await post({ repoUrl: 'https://github.com/a/done' })).json<{ scanId: string }>();
      await env.pool.query(`UPDATE scans SET status = 'completed', coverage = 'full' WHERE id = $1`, [scanId]);
      const res = await app.inject({ url: `/scans/${scanId}/report` });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toMatchObject({
        scan: { id: scanId, status: 'completed' },
        summary: expect.any(String) as string,
        actions: [],
        findings: [],
        unchecked: [],
        agentPrompt: null,
      });
    });

    it('a retrying scan shows the reason; its report is still 409', async () => {
      const { scanId } = (await post({ repoUrl: 'https://github.com/a/retry' })).json<{ scanId: string }>();
      const repo = new PostgresScanRepository(env.pool);
      const claim = await repo.claim(scanId);
      if (!claim) throw new Error('claim failed');
      await repo.markRetrying(claim, { code: 'osv_unavailable', message: 'OSV answered 503' });
      expect((await app.inject({ url: `/scans/${scanId}` })).json()).toMatchObject({
        status: 'retrying',
        stage: null,
        error: { code: 'osv_unavailable', message: 'OSV answered 503' },
      });
      const report = await app.inject({ url: `/scans/${scanId}/report` });
      expect(report.statusCode).toBe(409);
      expect(report.json<{ error: { message: string } }>().error.message).toMatch(/still retrying/);
    });

    it('a partial report over HTTP: coverage, both unchecked reasons, actions with text and labelled prose', async () => {
      const { scanId } = (await post({ repoUrl: 'https://github.com/a/partial' })).json<{ scanId: string }>();
      const repo = new PostgresScanRepository(env.pool);
      const claim = await repo.claim(scanId);
      if (!claim) throw new Error('claim failed');
      await repo.recordProgress(claim, { commitSha: 'd'.repeat(40), lockfilePath: 'package-lock.json' });
      await repo.complete(claim, {
        advisorySource: 'OSV.dev',
        summaryLine: 'stored summary line',
        explanation: {
          source: 'ai',
          summary: 'AI paragraph.',
          actions: { 'npm:lodash': { text: 'AI why.', source: 'ai' } },
        },
        counts: { totalDeps: 4, checkedDeps: 2, unsupportedDeps: 1, failedLookups: 1 },
        coverage: 'partial',
        findings: [
          {
            ecosystem: 'npm',
            package: 'lodash',
            installedAs: [],
            directAs: ['lodash'],
            installedVersion: '4.17.20',
            scope: 'runtime',
            isDirect: true,
            directParents: [],
            installPaths: [['lodash']],
            contextTruncated: false,
            candidateVersion: '4.17.21',
            fixStatus: 'candidate',
            advisory: {
              id: 'GHSA-29mw-wpgm-hmr9',
              aliases: [],
              title: 'ReDoS in lodash',
              severity: 'medium',
              isMalicious: false,
              affectedRanges: [{ kind: 'range', introduced: '4.0.0', fixed: '4.17.21', lastAffected: null }],
              references: [],
            },
          },
        ],
        unchecked: [
          { ecosystem: 'npm', package: 'slash', version: '5.1.0', reason: 'unsupported_source' },
          { ecosystem: 'npm', package: 'ms', version: '2.0.0', reason: 'lookup_failed' },
        ],
      });

      const res = await app.inject({ url: `/scans/${scanId}/report` });
      expect(res.statusCode).toBe(200);
      const body = res.json<Record<string, unknown>>();
      expect(body).toMatchObject({
        scan: {
          status: 'completed',
          coverage: 'partial',
          lockfilePath: 'package-lock.json',
          advisorySource: 'OSV.dev',
          counts: { totalDeps: 4, checkedDeps: 2, unsupportedDeps: 1, failedLookups: 1 },
          completedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/) as string,
        },
        summary: 'stored summary line',
        explanation: { source: 'ai', text: 'AI paragraph.' },
        actions: [
          {
            rank: 1,
            kind: 'upgrade',
            package: 'lodash',
            onSummary: true,
            whyItMatters: { source: 'ai', text: 'AI why.' },
            text: { headline: 'Upgrade lodash 4.17.20 to candidate 4.17.21' },
          },
        ],
        unchecked: [
          { package: 'ms', reason: 'lookup_failed' },
          { package: 'slash', reason: 'unsupported_source' },
        ],
        agentPrompt: expect.stringContaining('npm install lodash@4.17.21') as string,
      });
      // Scan JSON for polling stays small: no report data in it.
      expect(Object.keys((await app.inject({ url: `/scans/${scanId}` })).json<object>())).not.toContain('explanation');
    });

    it('failed and unsupported scans have a report with no plan', async () => {
      const { scanId } = (await post({ repoUrl: 'https://github.com/a/broken' })).json<{ scanId: string }>();
      const repo = new PostgresScanRepository(env.pool);
      const claim = await repo.claim(scanId);
      if (!claim) throw new Error('claim failed');
      await repo.finish(claim, { status: 'unsupported', code: 'no_lockfile', message: 'No package-lock.json' });
      const res = await app.inject({ url: `/scans/${scanId}/report` });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toMatchObject({
        scan: { status: 'unsupported', error: { code: 'no_lockfile' } },
        summary: null,
        explanation: null,
        actions: [],
        agentPrompt: null,
      });
    });

    it.each(['not-a-uuid', randomUUID()])('404 for %s', async (id) => {
      expect((await app.inject({ url: `/scans/${id}` })).statusCode).toBe(404);
      expect((await app.inject({ url: `/scans/${id}/report` })).statusCode).toBe(404);
    });

    it('a browser opening a shareable /scans/:id link gets the page, not JSON', async () => {
      const res = await app.inject({ url: `/scans/${randomUUID()}`, headers: { accept: 'text/html,*/*' } });
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toMatch(/text\/html/);
    });
  });

  describe('health', () => {
    it('live is always ok; ready reflects the database', async () => {
      expect((await app.inject({ url: '/health/live' })).statusCode).toBe(200);
      expect((await app.inject({ url: '/health/ready' })).statusCode).toBe(200);
      ready = false;
      expect((await app.inject({ url: '/health/ready' })).statusCode).toBe(503);
      ready = true;
    });
  });
});
