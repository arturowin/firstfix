import { readFile } from 'node:fs/promises';
import path from 'node:path';
import cookie from '@fastify/cookie';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { z } from 'zod';
import { GitHubUnavailable, SessionInvalid, type AccessService, type ResolvedSession } from '../application/access-service.ts';
import type { Report } from '../application/report.ts';
import type { ScanService, Submitter } from '../application/scan-service.ts';
import type { ScanView } from '../ports/scan-repository.ts';
import type { RateLimiter } from './rate-limit.ts';

export interface AppDeps {
  scans: ScanService;
  /** Readiness probe: resolves when dependencies (the database) answer. */
  checkReady: () => Promise<void>;
  /** Directory with index.html and the bundled app.js. */
  webDir: string;
  logger?: boolean;
  /** Where logs go when `logger` is on (tests read them); default stdout. */
  logStream?: { write: (line: string) => void };
  /** Per-client limit on POST /scans; omitted = unlimited (tests that don't care). */
  submitLimiter?: RateLimiter;
  /** Trust X-Forwarded-For for the client IP (only behind a proxy you control). */
  trustProxy?: boolean;
  /**
   * GitHub sign-in and private repositories (docs/ARCHITECTURE.md "Private repositories"). Omitted: off, the
   * app serves public scans only, exactly as before.
   */
  signIn?: { access: AccessService; publicUrl: string } | null;
}

const SESSION_COOKIE = '__Host-firstfix_session';
const OAUTH_COOKIE = '__Host-firstfix_oauth';
const COOKIE_BASE = { path: '/', httpOnly: true, secure: true, sameSite: 'lax' } as const;

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
    visibility: s.visibility.kind,
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

/** Report layout order: summary + coverage (in scan), actions, findings + unchecked, agent prompt. */
function reportJson(r: Report) {
  return {
    scan: scanJson(r.scan),
    summary: r.summary,
    explanation: r.explanation,
    ciChecks: r.ciChecks,
    actions: r.actions,
    findings: r.findings,
    unchecked: r.unchecked,
    agentPrompt: r.agentPrompt,
  };
}

/** Browser navigation to a shareable /scans/:id link gets the page; fetch() from the page gets JSON. */
function wantsHtml(req: FastifyRequest): boolean {
  const accept = req.headers.accept ?? '';
  return accept.includes('text/html');
}

interface Denial {
  status: number;
  code: string;
  message: string;
  retryAfter?: string;
}
const NOT_FOUND: Denial = { status: 404, code: 'not_found', message: 'No such scan' };
const SESSION_EXPIRED: Denial = { status: 401, code: 'session_expired', message: 'Your session has expired. Sign in again to continue.' };
const GITHUB_DOWN: Denial = {
  status: 503,
  code: 'github_unavailable',
  message: 'GitHub is not answering right now. Try again in a moment.',
  retryAfter: '30',
};

function denialFor(err: unknown): Denial {
  if (err instanceof SessionInvalid) return SESSION_EXPIRED;
  if (err instanceof GitHubUnavailable) return GITHUB_DOWN;
  throw err;
}

/**
 * Deletes a cookie. A `__Host-` cookie can only be deleted with the attributes it was set with (Secure, Path=/):
 * without them browsers ignore the deletion and keep sending the old value.
 */
function expireCookie(reply: FastifyReply, name: string): void {
  reply.clearCookie(name, COOKIE_BASE);
}

function deny(reply: FastifyReply, d: Denial) {
  if (d.retryAfter !== undefined) reply.header('retry-after', d.retryAfter);
  // A dead session cookie is useless: drop it, so the next request is simply anonymous (public scans keep working).
  if (d === SESSION_EXPIRED) expireCookie(reply, SESSION_COOKIE);
  return error(reply, d.status, d.code, d.message);
}

/**
 * What request logs record: the path, never the query string. Sign-in callbacks carry the OAuth code and state
 * there, and no credential may reach the logs.
 */
export function logRequest(req: { method: string; url: string; ip?: string }): { method: string; url: string; remoteAddress?: string } {
  const path = req.url.split('?')[0] ?? '';
  return { method: req.method, url: path, ...(req.ip === undefined ? {} : { remoteAddress: req.ip }) };
}

/** Answers that depend on who asks: never cached by browsers or proxies. */
function private_(reply: FastifyReply): FastifyReply {
  return reply.header('cache-control', 'no-store').header('vary', 'Cookie');
}

export function buildApp(deps: AppDeps): FastifyInstance {
  const app = Fastify({
    logger:
      deps.logger === true
        ? { serializers: { req: logRequest }, ...(deps.logStream ? { stream: deps.logStream } : {}) }
        : false,
    bodyLimit: 16 * 1024,
    trustProxy: deps.trustProxy ?? false,
  });
  void app.register(cookie);
  const signIn = deps.signIn ?? null;
  const publicOrigin = signIn ? new URL(signIn.publicUrl).origin : null;

  const viewer = async (req: FastifyRequest): Promise<ResolvedSession> =>
    signIn ? signIn.access.resolve(req.cookies[SESSION_COOKIE]) : { state: 'none' };

  /** The two access failures every session-dependent route answers the same way; anything else is a bug. */
  const accessFailure = (reply: FastifyReply, err: unknown) => deny(reply, denialFor(err));
  const sessionExpired = (reply: FastifyReply) => deny(reply, SESSION_EXPIRED);

  // A POST that relies on the session cookie must come from our own pages (CSRF). Cookie-less API clients
  // carry no session, so they are unaffected.
  app.addHook('preHandler', async (req, reply) => {
    if (req.method !== 'POST' || !publicOrigin || req.cookies[SESSION_COOKIE] === undefined) return;
    if (req.headers.origin !== publicOrigin) {
      return error(reply, 403, 'bad_origin', 'This request must come from the FirstFix page.');
    }
  });

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
    const wait = deps.submitLimiter?.take(req.ip) ?? 0;
    if (wait > 0) {
      reply.header('retry-after', String(wait));
      return error(reply, 429, 'rate_limited', `Too many scans requested from this address. Try again in ${String(wait)} s.`);
    }
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

    const who = await viewer(req);
    if (who.state === 'expired') return private_(sessionExpired(reply));
    const submitter: Submitter | null =
      signIn && who.state === 'active'
        ? { githubUserId: who.session.githubUserId, privateTarget: (repo) => signIn.access.privateTarget(who.session, repo) }
        : null;
    let result;
    try {
      result = await deps.scans.submit(body.data.repoUrl, key, submitter);
    } catch (err) {
      return accessFailure(private_(reply), err);
    }
    switch (result.kind) {
      case 'invalid':
        return error(reply, 400, 'invalid_repo_url', result.error);
      case 'conflict':
        return error(reply, 409, 'idempotency_conflict', 'This Idempotency-Key was already used for a different repository');
      case 'busy':
        reply.header('retry-after', '30');
        return error(reply, 503, 'busy', 'Too many scans are waiting right now. Please try again in a minute.');
      case 'created':
        return reply.code(202).header('location', `/scans/${result.scanId}`).send({ scanId: result.scanId });
      case 'existing':
        return reply.code(200).header('location', `/scans/${result.scanId}`).send({ scanId: result.scanId });
    }
  });

  /**
   * The read rule for a scan (domain/access.ts): public → anyone; private → a viewer GitHub lets access its
   * recorded repository through its recorded installation. Missing and private look the same without a session.
   */
  const gate = async (req: FastifyRequest, scan: ScanView | null): Promise<Denial | null> => {
    if (scan?.visibility.kind === 'public') return null;
    const who = await viewer(req);
    try {
      const decision = signIn ? await signIn.access.readGate(scan?.visibility ?? null, who) : null;
      if (decision?.kind === 'allow') return null;
      return decision?.kind === 'deny' && decision.status === 401 ? SESSION_EXPIRED : NOT_FOUND;
    } catch (err) {
      return denialFor(err);
    }
  };

  app.get<{ Params: { id: string } }>('/scans/:id', async (req, reply) => {
    if (wantsHtml(req)) return sendIndex(reply);
    private_(reply);
    const scan = ScanId.safeParse(req.params.id).success ? await deps.scans.get(req.params.id) : null;
    const denied = await gate(req, scan);
    if (denied) return deny(reply, denied);
    if (!scan) return error(reply, 404, 'not_found', 'No such scan');
    return reply.send(scanJson(scan));
  });

  app.get<{ Params: { id: string } }>('/scans/:id/report', async (req, reply) => {
    private_(reply);
    const scan = ScanId.safeParse(req.params.id).success ? await deps.scans.get(req.params.id) : null;
    const denied = await gate(req, scan);
    if (denied) return deny(reply, denied);
    if (!scan) return error(reply, 404, 'not_found', 'No such scan');
    const report = await deps.scans.getReport(scan.id);
    if (!report) return error(reply, 404, 'not_found', 'No such scan');
    if (!TERMINAL.has(report.scan.status)) {
      return error(reply, 409, 'not_finished', `The scan is still ${report.scan.status}; poll GET /scans/${report.scan.id}`);
    }
    return reply.send(reportJson(report));
  });

  registerSignIn(app, signIn, { viewer, accessFailure, sessionExpired });

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

const InstallationId = z.coerce.number().int().positive().max(Number.MAX_SAFE_INTEGER);

/** Sign-in, installations and the repository picker. Not registered when sign-in is off. */
function registerSignIn(
  app: FastifyInstance,
  signIn: AppDeps['signIn'],
  h: {
    viewer: (req: FastifyRequest) => Promise<ResolvedSession>;
    accessFailure: (reply: FastifyReply, err: unknown) => unknown;
    sessionExpired: (reply: FastifyReply) => unknown;
  },
): void {
  app.get('/me', async (req, reply) => {
    private_(reply);
    if (!signIn) return reply.send({ signInEnabled: false, session: 'none', user: null, installations: null, installUrl: null });
    const who = await h.viewer(req);
    const base = { signInEnabled: true, installUrl: signIn.access.installUrl() };
    if (who.state === 'expired') expireCookie(reply, SESSION_COOKIE);
    if (who.state !== 'active') return reply.send({ ...base, session: who.state, user: null, installations: null });
    try {
      const installations = await signIn.access.installations(who.session);
      return await reply.send({ ...base, session: 'active', user: { login: who.session.githubLogin }, installations });
    } catch (err) {
      if (err instanceof SessionInvalid) {
        expireCookie(reply, SESSION_COOKIE);
        return reply.send({ ...base, session: 'expired', user: null, installations: null });
      }
      return h.accessFailure(reply, err);
    }
  });

  if (!signIn) return;
  const { access } = signIn;

  app.get<{ Querystring: { return_to?: string } }>('/auth/login', async (req, reply) => {
    private_(reply);
    const start = await access.startSignIn(req.query.return_to);
    reply.setCookie(OAUTH_COOKIE, start.binding, { ...COOKIE_BASE, maxAge: start.ttlSeconds });
    return reply.redirect(start.url, 302);
  });

  app.get<{ Querystring: { code?: string; state?: string; error?: string } }>('/auth/callback', async (req, reply) => {
    private_(reply);
    const result = await access.finishSignIn({
      code: req.query.code,
      state: req.query.state,
      error: req.query.error,
      binding: req.cookies[OAUTH_COOKIE],
    });
    expireCookie(reply, OAUTH_COOKIE);
    if (result.kind === 'error') return reply.redirect(`/?auth_error=${result.code}`, 302);
    reply.setCookie(SESSION_COOKIE, result.cookie, COOKIE_BASE);
    return reply.redirect(result.returnTo, 302);
  });

  app.post('/auth/logout', async (req, reply) => {
    private_(reply);
    await access.signOut(req.cookies[SESSION_COOKIE]);
    expireCookie(reply, SESSION_COOKIE);
    return reply.code(204).send();
  });

  app.get('/github/connect', async (req, reply) => {
    private_(reply);
    const who = await h.viewer(req);
    if (who.state !== 'active') return reply.redirect('/auth/login', 302);
    // Repository access is about to change on GitHub (GitHub may not redirect back): list it fresh afterwards.
    access.forgetAccess(who.session);
    return reply.redirect(access.installUrl(), 302);
  });

  // GitHub's setup URL. The installation_id parameter can be spoofed: it counts only if GitHub lists it among
  // the signed-in user's installations. GitHub doesn't document the redirect for an approval request, so
  // anything unverifiable gets the same truthful "check GitHub" message.
  app.get<{ Querystring: { installation_id?: string } }>('/github/setup', async (req, reply) => {
    private_(reply);
    const who = await h.viewer(req);
    if (who.state !== 'active') return reply.redirect('/auth/login', 302);
    const id = InstallationId.safeParse(req.query.installation_id);
    if (!id.success) return reply.redirect('/?connect=unverified', 302);
    try {
      const ok = await access.verifyInstallation(who.session, id.data);
      return await reply.redirect(ok ? '/?connect=installed' : '/?connect=unverified', 302);
    } catch (err) {
      if (err instanceof SessionInvalid) return reply.redirect('/auth/login', 302);
      if (err instanceof GitHubUnavailable) return reply.redirect('/?connect=unverified', 302);
      throw err;
    }
  });

  app.get<{ Params: { id: string } }>('/installations/:id/repos', async (req, reply) => {
    private_(reply);
    const who = await h.viewer(req);
    if (who.state === 'none') return error(reply, 401, 'signed_out', 'Sign in with GitHub to see your repositories.');
    if (who.state === 'expired') return h.sessionExpired(reply);
    const id = InstallationId.safeParse(req.params.id);
    if (!id.success) return error(reply, 404, 'not_found', 'No such installation');
    try {
      const list = await access.repositories(who.session, id.data);
      if (!list) return await error(reply, 404, 'not_found', 'No such installation');
      return await reply.send({
        repositories: list.repositories.map((r) => ({ id: r.id, owner: r.owner, name: r.name, fullName: `${r.owner}/${r.name}`, private: r.private })),
        truncated: list.truncated,
      });
    } catch (err) {
      return h.accessFailure(reply, err);
    }
  });
}
