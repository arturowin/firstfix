import { readFile } from 'node:fs/promises';
import path from 'node:path';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { ScanService } from '../application/scan-service.ts';
import type { ReportData, ScanView } from '../ports/scan-repository.ts';

export interface AppDeps {
  scans: ScanService;
  /** Readiness probe: resolves when dependencies (the database) answer. */
  checkReady: () => Promise<void>;
  /** Directory with index.html and the bundled app.js. */
  webDir: string;
  logger?: boolean;
}

const SubmitBody = z.object({ repoUrl: z.string().max(2048) }).strict();
// Opaque client-generated key; printable ASCII, bounded so it can't be used to bloat the table.
const IdempotencyKey = z.string().regex(/^[\x21-\x7e]{1,200}$/, 'must be 1-200 printable ASCII characters');
const ScanId = z.uuid();

const TERMINAL = new Set(['completed', 'unsupported', 'failed']);

function error(reply: FastifyReply, status: number, code: string, message: string) {
  return reply.code(status).send({ error: { code, message } });
}

function scanJson(s: ScanView) {
  return {
    id: s.id,
    repo: s.repo,
    commitSha: s.commitSha,
    lockfilePath: s.lockfilePath,
    advisorySource: s.advisorySource,
    status: s.status,
    stage: s.stage,
    counts: s.counts,
    coverage: s.coverage,
    error: s.error,
    createdAt: s.createdAt.toISOString(),
    updatedAt: s.updatedAt.toISOString(),
    completedAt: s.completedAt?.toISOString() ?? null,
  };
}

function reportJson(r: ReportData) {
  return { scan: scanJson(r.scan), findings: r.findings, unchecked: r.unchecked };
}

/** Browser navigation to a shareable /scans/:id link gets the page; fetch() from the page gets JSON. */
function wantsHtml(req: FastifyRequest): boolean {
  const accept = req.headers.accept ?? '';
  return accept.includes('text/html');
}

export function buildApp(deps: AppDeps): FastifyInstance {
  const app = Fastify({ logger: deps.logger ?? false, bodyLimit: 16 * 1024 });

  const sendIndex = async (reply: FastifyReply) => {
    const html = await readFile(path.join(deps.webDir, 'index.html'), 'utf8');
    return reply.type('text/html; charset=utf-8').header('cache-control', 'no-cache').send(html);
  };

  app.get('/', async (_req, reply) => sendIndex(reply));

  app.get('/app.js', async (_req, reply) => {
    try {
      const js = await readFile(path.join(deps.webDir, 'app.js'), 'utf8');
      return await reply.type('text/javascript; charset=utf-8').header('cache-control', 'no-cache').send(js);
    } catch {
      return error(reply, 404, 'not_built', 'UI bundle missing: run `npm run build:web`');
    }
  });

  app.post('/scans', async (req, reply) => {
    const body = SubmitBody.safeParse(req.body);
    if (!body.success) {
      return error(reply, 400, 'invalid_body', 'Send JSON like {"repoUrl": "https://github.com/owner/repo"}');
    }

    const rawKey = req.headers['idempotency-key'];
    let key: string | null = null;
    if (rawKey !== undefined) {
      const parsed = IdempotencyKey.safeParse(rawKey);
      if (!parsed.success) return error(reply, 400, 'invalid_idempotency_key', 'Idempotency-Key must be 1-200 printable ASCII characters');
      key = parsed.data;
    }

    const result = await deps.scans.submit(body.data.repoUrl, key);
    switch (result.kind) {
      case 'invalid':
        return error(reply, 400, 'invalid_repo_url', result.error);
      case 'conflict':
        return error(reply, 409, 'idempotency_conflict', 'This Idempotency-Key was already used for a different repository');
      case 'created':
        return reply.code(202).header('location', `/scans/${result.scanId}`).send({ scanId: result.scanId });
      case 'existing':
        return reply.code(200).header('location', `/scans/${result.scanId}`).send({ scanId: result.scanId });
    }
  });

  app.get<{ Params: { id: string } }>('/scans/:id', async (req, reply) => {
    if (wantsHtml(req)) return sendIndex(reply);
    if (!ScanId.safeParse(req.params.id).success) return error(reply, 404, 'not_found', 'No such scan');
    const scan = await deps.scans.get(req.params.id);
    if (!scan) return error(reply, 404, 'not_found', 'No such scan');
    return reply.header('cache-control', 'no-store').send(scanJson(scan));
  });

  app.get<{ Params: { id: string } }>('/scans/:id/report', async (req, reply) => {
    if (!ScanId.safeParse(req.params.id).success) return error(reply, 404, 'not_found', 'No such scan');
    const report = await deps.scans.getReport(req.params.id);
    if (!report) return error(reply, 404, 'not_found', 'No such scan');
    if (!TERMINAL.has(report.scan.status)) {
      return error(reply, 409, 'not_finished', `The scan is still ${report.scan.status}; poll GET /scans/${report.scan.id}`);
    }
    return reply.send(reportJson(report));
  });

  app.get('/health/live', (_req, reply) => reply.send({ status: 'ok' }));

  app.get('/health/ready', async (_req, reply) => {
    try {
      await deps.checkReady();
      return await reply.send({ status: 'ok' });
    } catch {
      return error(reply, 503, 'not_ready', 'Database unavailable');
    }
  });

  return app;
}
