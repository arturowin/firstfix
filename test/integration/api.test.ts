import { randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { PostgresScanSubmission } from '../../src/adapters/postgres/scan-submission.ts';
import { buildApp } from '../../src/api/app.ts';
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
      expect(res.json()).toMatchObject({ scan: { id: scanId, status: 'completed' }, findings: [], unchecked: [] });
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
