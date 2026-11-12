/**
 * The API's sign-in and access rules with real Postgres, sessions and scan storage. GitHub is a fake that
 * implements the GitHubAuth port (its HTTP side is covered by test/contract/github-user-auth.test.ts).
 * A live check against github.com needs a real GitHub App (see docs/AGENT_LOG.md).
 */
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { PostgresScanRepository } from '../../src/adapters/postgres/scan-repository.ts';
import { PostgresScanSubmission } from '../../src/adapters/postgres/scan-submission.ts';
import { PostgresSessionStore } from '../../src/adapters/postgres/session-store.ts';
import { SecretBox } from '../../src/adapters/secret-box.ts';
import { buildApp } from '../../src/api/app.ts';
import { AccessService } from '../../src/application/access-service.ts';
import { ScanService } from '../../src/application/scan-service.ts';
import { PermanentError, TransientError } from '../../src/ports/errors.ts';
import {
  UserTokenRejected,
  type AccessibleRepository,
  type AppInstallation,
  type GitHubAuth,
  type RepositoryList,
} from '../../src/ports/github-auth.ts';
import { createTestEnv, type TestEnv } from '../support/env.ts';

const PUBLIC_URL = 'https://firstfix.test';
const ORIGIN = { origin: PUBLIC_URL };

/** Runs fn and turns its result or thrown error into a promise, like an async GitHub call. */
function settle<T>(fn: () => T): Promise<T> {
  try {
    return Promise.resolve(fn());
  } catch (e) {
    return Promise.reject(e instanceof Error ? e : new Error(String(e)));
  }
}

/** GitHub as the port sees it: per user token, the installations and repositories GitHub would list. */
class FakeGitHub implements GitHubAuth {
  users = new Map<string, { id: number; login: string; installations: AppInstallation[]; repos: Map<number, AccessibleRepository[]> }>();
  /** code → the user's token and the PKCE challenge GitHub saw when the code was issued. */
  codes = new Map<string, { token: string; challenge: string }>();
  down = false;
  /** GitHub doesn't answer at all: calls end only when the caller's deadline aborts them (like fetch). */
  hang = false;
  rejected = new Set<string>();
  calls = 0;

  authorizeUrl(i: { state: string; codeChallenge: string; redirectUri: string }): string {
    return `https://github.com/login/oauth/authorize?state=${i.state}&code_challenge=${i.codeChallenge}&redirect_uri=${encodeURIComponent(i.redirectUri)}`;
  }
  installUrl(): string {
    return 'https://github.com/apps/firstfix/installations/new';
  }
  private hanging<T>(signal: AbortSignal): Promise<T> {
    return new Promise<T>((_resolve, reject) => {
      signal.addEventListener('abort', () => {
        reject(signal.reason instanceof Error ? signal.reason : new Error('aborted'));
      });
    });
  }
  exchangeCode(i: { code: string; codeVerifier: string }, signal: AbortSignal): Promise<{ token: string; expiresAt: Date }> {
    if (this.hang) return this.hanging(signal);
    const c = this.codes.get(i.code);
    this.codes.delete(i.code);
    // PKCE: the verifier must hash to the challenge sent with the authorize request.
    const ok = c !== undefined && createHash('sha256').update(i.codeVerifier).digest('base64url') === c.challenge;
    if (!ok) return Promise.reject(new PermanentError('oauth_exchange_failed', 'bad code or verifier'));
    return Promise.resolve({ token: c.token, expiresAt: new Date(Date.now() + 8 * 3_600_000) });
  }
  private guard(token: string) {
    this.calls++;
    if (this.down) throw new TransientError('github_unavailable', 'down');
    if (this.rejected.has(token)) throw new UserTokenRejected();
    const u = this.users.get(token);
    if (!u) throw new UserTokenRejected();
    return u;
  }
  user(token: string) {
    return settle(() => {
      const u = this.guard(token);
      return { id: u.id, login: u.login };
    });
  }
  installations(token: string, signal: AbortSignal) {
    if (this.hang) return this.hanging<AppInstallation[]>(signal);
    return settle(() => this.guard(token).installations);
  }
  repositories(token: string, installationId: number): Promise<RepositoryList | null> {
    return settle(() => {
      const repos = this.guard(token).repos.get(installationId);
      return repos ? { repositories: repos, truncated: false } : null;
    });
  }
}

const SECRET_REPO: AccessibleRepository = { id: 4242, owner: 'Acme', name: 'Secret-App', private: true };
const OTHER_REPO: AccessibleRepository = { id: 777, owner: 'Acme', name: 'Docs', private: true };
const PUBLIC_REPO: AccessibleRepository = { id: 5, owner: 'Acme', name: 'Website', private: false };
const ORG: AppInstallation = { id: 70, account: 'Acme' };

describe('private repositories over HTTP', () => {
  let env: TestEnv;
  let app: FastifyInstance;
  let github: FakeGitHub;
  let webDir: string;
  let clock = Date.now();
  let codeSeq = 0;

  beforeAll(async () => {
    env = await createTestEnv();
    webDir = await mkdtemp(path.join(tmpdir(), 'web-'));
    await writeFile(path.join(webDir, 'index.html'), '<!doctype html><title>FirstFix</title>');
  });

  afterEach(async () => {
    await app.close();
  });

  beforeEach(async () => {
    github = new FakeGitHub();
    // Member: an ordinary organization member using the org's existing installation (they didn't install it).
    github.users.set('ghu_member', { id: 1, login: 'member', installations: [ORG], repos: new Map([[70, [SECRET_REPO, PUBLIC_REPO]]]) });
    // Colleague: same installation is visible to them, but GitHub doesn't give them the secret repository.
    github.users.set('ghu_colleague', { id: 2, login: 'colleague', installations: [ORG], repos: new Map([[70, [OTHER_REPO]]]) });
    // Outsider: no installation at all.
    github.users.set('ghu_outsider', { id: 3, login: 'outsider', installations: [], repos: new Map() });
    clock = Date.now();
    const access = new AccessService({
      github,
      sessions: new PostgresSessionStore(env.pool, new SecretBox('k'.repeat(32))),
      redirectUri: `${PUBLIC_URL}/auth/callback`,
      now: () => clock,
      timeoutMs: 200,
    });
    app = buildApp({
      scans: new ScanService(new PostgresScanSubmission(env.pool, env.boss), new PostgresScanRepository(env.pool)),
      checkReady: () => Promise.resolve(),
      webDir,
      signIn: { access, publicUrl: PUBLIC_URL },
    });
    await app.ready();
  });

  afterAll(async () => {
    await env.close();
    await rm(webDir, { recursive: true, force: true });
  });

  const cookieOf = (res: LightMyRequestResponse, name: string) => res.cookies.find((c) => c.name === name);

  /** Full browser flow: /auth/login → (GitHub issues a code for the challenge) → /auth/callback. */
  async function signInFlow(token: string, returnTo = '/'): Promise<LightMyRequestResponse> {
    const login = await app.inject({ method: 'GET', url: `/auth/login?return_to=${encodeURIComponent(returnTo)}` });
    const authorize = new URL(String(login.headers.location));
    const state = authorize.searchParams.get('state') ?? '';
    const binding = cookieOf(login, '__Host-firstfix_oauth')?.value ?? '';
    const code = `code-${String(++codeSeq)}`;
    github.codes.set(code, { token, challenge: authorize.searchParams.get('code_challenge') ?? '' });
    return app.inject({ method: 'GET', url: `/auth/callback?code=${code}&state=${encodeURIComponent(state)}`, cookies: { '__Host-firstfix_oauth': binding } });
  }

  /** Signs in and returns the session cookie header. */
  async function signIn(token: string): Promise<string> {
    const cb = await signInFlow(token);
    expect(cb.statusCode).toBe(302);
    const session = cookieOf(cb, '__Host-firstfix_session');
    expect(session?.value).toBeTruthy();
    return `__Host-firstfix_session=${session?.value ?? ''}`;
  }

  async function submitPrivate(cookie: string, url = 'https://github.com/acme/secret-app', key?: string): Promise<string> {
    const res = await app.inject({
      method: 'POST',
      url: '/scans',
      payload: { repoUrl: url },
      headers: { cookie, ...ORIGIN, ...(key ? { 'idempotency-key': key } : {}) },
    });
    expect(res.statusCode).toBe(202);
    return res.json<{ scanId: string }>().scanId;
  }

  const read = (id: string, cookie?: string, suffix = '') =>
    app.inject({ method: 'GET', url: `/scans/${id}${suffix}`, headers: { accept: 'application/json', ...(cookie ? { cookie } : {}) } });

  describe('sign-in', () => {
    it('login stores a one-time state, binds it to the browser with a short-lived cookie and sends PKCE S256', async () => {
      const res = await app.inject({ method: 'GET', url: '/auth/login?return_to=https://evil.example' });
      expect(res.statusCode).toBe(302);
      const loc = new URL(String(res.headers.location));
      expect(loc.searchParams.get('state')).toMatch(/^[\w-]{43}$/);
      expect(loc.searchParams.get('code_challenge')).toMatch(/^[\w-]{43}$/);
      const c = cookieOf(res, '__Host-firstfix_oauth');
      expect(c).toMatchObject({ httpOnly: true, secure: true, sameSite: 'Lax', path: '/', maxAge: 600 });
      expect(res.headers['cache-control']).toBe('no-store');
    });

    it('returns to a validated path only, and sets a Secure HttpOnly session cookie', async () => {
      const evil = await signInFlow('ghu_member', '//evil.example');
      expect(evil.headers.location).toBe('/');
      expect(cookieOf(evil, '__Host-firstfix_session')).toMatchObject({ httpOnly: true, secure: true, sameSite: 'Lax', path: '/' });
      const scan = '/scans/0b6c2f6e-3a5b-4c1d-9e8f-1a2b3c4d5e6f';
      expect((await signInFlow('ghu_member', scan)).headers.location).toBe(scan);
    });

    it('a wrong PKCE verifier (code from another sign-in) fails', async () => {
      const login = await app.inject({ method: 'GET', url: '/auth/login' });
      const state = new URL(String(login.headers.location)).searchParams.get('state') ?? '';
      github.codes.set('stolen', { token: 'ghu_member', challenge: 'not-this-browsers-challenge' });
      const cb = await app.inject({
        method: 'GET',
        url: `/auth/callback?code=stolen&state=${state}`,
        cookies: { '__Host-firstfix_oauth': cookieOf(login, '__Host-firstfix_oauth')?.value ?? '' },
      });
      expect(cb.headers.location).toBe('/?auth_error=sign_in_failed');
      expect(cookieOf(cb, '__Host-firstfix_session')).toBeUndefined();
    });

    it('a callback from another browser, a replayed state or a missing cookie fails', async () => {
      const login = await app.inject({ method: 'GET', url: '/auth/login' });
      const state = new URL(String(login.headers.location)).searchParams.get('state') ?? '';
      const other = await app.inject({ method: 'GET', url: `/auth/callback?code=x&state=${state}`, cookies: { '__Host-firstfix_oauth': 'someone-else' } });
      expect(other.headers.location).toBe('/?auth_error=invalid_state');
      // The forged attempt burned the state: the real browser can't use it any more either.
      const binding = cookieOf(login, '__Host-firstfix_oauth')?.value ?? '';
      const replay = await app.inject({ method: 'GET', url: `/auth/callback?code=x&state=${state}`, cookies: { '__Host-firstfix_oauth': binding } });
      expect(replay.headers.location).toBe('/?auth_error=invalid_state');
      const noCookie = await app.inject({ method: 'GET', url: `/auth/callback?code=x&state=${state}` });
      expect(noCookie.headers.location).toBe('/?auth_error=invalid_state');
    });

    it('/me lists the installations an ordinary member can use (installed by someone else)', async () => {
      const cookie = await signIn('ghu_member');
      const me = await app.inject({ method: 'GET', url: '/me', headers: { cookie } });
      expect(me.headers['cache-control']).toBe('no-store');
      expect(me.json()).toEqual({
        signInEnabled: true,
        session: 'active',
        user: { login: 'member' },
        installations: [{ id: 70, account: 'Acme' }],
        installUrl: 'https://github.com/apps/firstfix/installations/new',
      });
      expect(JSON.stringify(me.json())).not.toContain('ghu_');
    });

    it('/me without an installation still offers Connect GitHub', async () => {
      const cookie = await signIn('ghu_outsider');
      const me = await app.inject({ method: 'GET', url: '/me', headers: { cookie } });
      expect(me.json()).toMatchObject({ session: 'active', installations: [], installUrl: expect.stringContaining('/installations/new') as unknown });
    });
  });

  describe('setup URL', () => {
    it('trusts installation_id only if GitHub lists it for the signed-in user', async () => {
      const cookie = await signIn('ghu_member');
      const good = await app.inject({ method: 'GET', url: '/github/setup?installation_id=70&setup_action=install', headers: { cookie } });
      expect(good.headers.location).toBe('/?connect=installed');
      const spoofed = await app.inject({ method: 'GET', url: '/github/setup?installation_id=999&setup_action=install', headers: { cookie } });
      expect(spoofed.headers.location).toBe('/?connect=unverified');
      const requested = await app.inject({ method: 'GET', url: '/github/setup?setup_action=request', headers: { cookie } });
      expect(requested.headers.location).toBe('/?connect=unverified');
    });

    it('requires a session', async () => {
      const res = await app.inject({ method: 'GET', url: '/github/setup?installation_id=70' });
      expect(res.headers.location).toBe('/auth/login');
    });
  });

  describe('repository picker', () => {
    it('lists repositories both the user and the app can access, labelled by owner', async () => {
      const cookie = await signIn('ghu_member');
      const res = await app.inject({ method: 'GET', url: '/installations/70/repos', headers: { cookie } });
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.json()).toEqual({
        repositories: [
          { id: 4242, owner: 'Acme', name: 'Secret-App', fullName: 'Acme/Secret-App', private: true },
          { id: 5, owner: 'Acme', name: 'Website', fullName: 'Acme/Website', private: false },
        ],
        truncated: false,
      });
    });

    it('going to Connect GitHub drops the cached lists, so access changed on GitHub shows up at once', async () => {
      const cookie = await signIn('ghu_member');
      const list = async () =>
        (await app.inject({ method: 'GET', url: '/installations/70/repos', headers: { cookie } })).json<{ repositories: { id: number }[] }>().repositories.map((r) => r.id);
      expect(await list()).toEqual([4242, 5]);
      github.users.get('ghu_member')?.repos.set(70, [SECRET_REPO, PUBLIC_REPO, OTHER_REPO]); // repository added on GitHub
      expect(await list()).toEqual([4242, 5]); // still cached
      await app.inject({ method: 'GET', url: '/github/connect', headers: { cookie } });
      expect(await list()).toEqual([4242, 5, 777]);
    });

    it('an installation that is not the user’s is 404; signed out is 401', async () => {
      const cookie = await signIn('ghu_outsider');
      expect((await app.inject({ method: 'GET', url: '/installations/70/repos', headers: { cookie } })).statusCode).toBe(404);
      expect((await app.inject({ method: 'GET', url: '/installations/70/repos' })).statusCode).toBe(401);
    });
  });

  describe('private scans', () => {
    it('an organization member scans an authorized private repository: bound to its ids, readable by them', async () => {
      const cookie = await signIn('ghu_member');
      const id = await submitPrivate(cookie);
      const { rows } = await env.pool.query<{ visibility: string; github_repo_id: string; installation_id: string; submitted_by: string }>(
        'SELECT visibility, github_repo_id, installation_id, submitted_by FROM scans WHERE id = $1',
        [id],
      );
      expect(rows[0]).toEqual({ visibility: 'private', github_repo_id: '4242', installation_id: '70', submitted_by: '1' });

      const status = await read(id, cookie);
      expect(status.statusCode).toBe(200);
      expect(status.json()).toMatchObject({ id, visibility: 'private' });
      expect(status.headers['cache-control']).toBe('no-store');
      expect(status.headers['vary']).toBe('Cookie');
      expect((await read(id, cookie, '/report')).statusCode).toBe(409); // not finished yet, but allowed
    });

    it('a second account without access to that repository gets 404 for status and report, even with installation access', async () => {
      const id = await submitPrivate(await signIn('ghu_member'));
      const colleague = await signIn('ghu_colleague'); // same org installation, different repository access
      expect((await read(id, colleague)).statusCode).toBe(404);
      expect((await read(id, colleague, '/report')).statusCode).toBe(404);
      const outsider = await signIn('ghu_outsider');
      expect((await read(id, outsider)).statusCode).toBe(404);
    });

    it('without a valid session, a private scan and a missing scan get the same answer', async () => {
      const id = await submitPrivate(await signIn('ghu_member'));
      const missing = '00000000-0000-4000-8000-000000000000';
      // No cookie: 404 for both.
      for (const target of [id, missing]) {
        expect((await read(target)).statusCode).toBe(404);
        expect((await read(target, undefined, '/report')).statusCode).toBe(404);
      }
      // Expired or unknown session: 401 session_expired for both.
      const expired = 'made-up-or-expired';
      for (const target of [id, missing]) {
        const res = await read(target, `__Host-firstfix_session=${expired}`);
        expect(res.statusCode).toBe(401);
        expect(res.json<{ error: { code: string } }>().error.code).toBe('session_expired');
      }
    });

    it('a public repository picked by a signed-in user is a public scan, readable by anyone', async () => {
      const cookie = await signIn('ghu_member');
      const id = await submitPrivate(cookie, 'https://github.com/acme/website');
      expect((await read(id)).json()).toMatchObject({ visibility: 'public' });
    });

    it('a private repository the user cannot access is not bound to anything (public path, which cannot read it)', async () => {
      const cookie = await signIn('ghu_colleague');
      const id = await submitPrivate(cookie, 'https://github.com/acme/secret-app');
      const { rows } = await env.pool.query<{ visibility: string; github_repo_id: string | null }>('SELECT visibility, github_repo_id FROM scans WHERE id = $1', [id]);
      expect(rows[0]).toEqual({ visibility: 'public', github_repo_id: null });
    });

    it('the same Idempotency-Key from another user is a conflict, not their scan', async () => {
      await submitPrivate(await signIn('ghu_member'), undefined, 'shared-key-1');
      const res = await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { repoUrl: 'https://github.com/acme/secret-app' },
        headers: { cookie: await signIn('ghu_colleague'), ...ORIGIN, 'idempotency-key': 'shared-key-1' },
      });
      expect(res.statusCode).toBe(409);
    });

    it('a private scan stays private (visibility and binding cannot change)', async () => {
      const id = await submitPrivate(await signIn('ghu_member'));
      await expect(env.pool.query(`UPDATE scans SET visibility = 'public' WHERE id = $1`, [id])).rejects.toThrow(/cannot change/);
      await expect(env.pool.query(`UPDATE scans SET github_repo_id = 1 WHERE id = $1`, [id])).rejects.toThrow(/cannot change/);
    });
  });

  describe('cache, outages and revocation', () => {
    it('answers from the cache within 5 minutes, but never past it: an outage then is 503', async () => {
      const cookie = await signIn('ghu_member');
      const id = await submitPrivate(cookie);
      expect((await read(id, cookie)).statusCode).toBe(200);
      github.down = true;
      clock += 4 * 60_000;
      expect((await read(id, cookie)).statusCode).toBe(200); // live cache entry
      clock += 2 * 60_000;
      const res = await read(id, cookie);
      expect(res.statusCode).toBe(503);
      expect(res.json<{ error: { code: string } }>().error.code).toBe('github_unavailable');
    });

    it('revoked repository access is enforced once the cache entry ends', async () => {
      const cookie = await signIn('ghu_member');
      const id = await submitPrivate(cookie);
      expect((await read(id, cookie)).statusCode).toBe(200);
      github.users.get('ghu_member')?.repos.set(70, [PUBLIC_REPO]);
      clock += 5 * 60_000;
      expect((await read(id, cookie)).statusCode).toBe(404);
    });

    it('a token GitHub rejects ends the session: 401, then the session is gone', async () => {
      const cookie = await signIn('ghu_member');
      const id = await submitPrivate(cookie);
      clock += 5 * 60_000;
      github.rejected.add('ghu_member');
      expect((await read(id, cookie)).statusCode).toBe(401);
      expect((await app.inject({ method: 'GET', url: '/me', headers: { cookie } })).json()).toMatchObject({ session: 'expired' });
    });

    it('GitHub not answering in time: a private read is 503 (not 500), sign-in ends on the friendly error page', async () => {
      const cookie = await signIn('ghu_member');
      const id = await submitPrivate(cookie);
      clock += 5 * 60_000; // cache entry over: GitHub must be asked
      github.hang = true;
      const res = await read(id, cookie);
      expect(res.statusCode).toBe(503);
      expect(res.json<{ error: { code: string } }>().error.code).toBe('github_unavailable');
      expect((await app.inject({ method: 'GET', url: '/me', headers: { cookie } })).statusCode).toBe(503);
      const cb = await signInFlow('ghu_member');
      expect(cb.headers.location).toBe('/?auth_error=github_unavailable');
    });

    it('GitHub unavailable during a private submit is 503 (safe to resend with the same key)', async () => {
      const cookie = await signIn('ghu_member');
      clock += 5 * 60_000;
      github.down = true;
      const res = await app.inject({ method: 'POST', url: '/scans', payload: { repoUrl: 'https://github.com/acme/secret-app' }, headers: { cookie, ...ORIGIN, 'idempotency-key': 'k-503' } });
      expect(res.statusCode).toBe(503);
      github.down = false;
      expect(await submitPrivate(cookie, undefined, 'k-503')).toMatch(/^[0-9a-f-]{36}$/);
    });

    it('submitting with an expired session is 401', async () => {
      const res = await app.inject({ method: 'POST', url: '/scans', payload: { repoUrl: 'https://github.com/acme/secret-app' }, headers: { cookie: '__Host-firstfix_session=gone', ...ORIGIN } });
      expect(res.statusCode).toBe(401);
    });
  });

  describe('logout and CSRF', () => {
    it('logout deletes the session and its cached access', async () => {
      const cookie = await signIn('ghu_member');
      const id = await submitPrivate(cookie);
      expect((await read(id, cookie)).statusCode).toBe(200);
      const out = await app.inject({ method: 'POST', url: '/auth/logout', headers: { cookie, ...ORIGIN } });
      expect(out.statusCode).toBe(204);
      expect(cookieOf(out, '__Host-firstfix_session')?.value).toBe('');
      const calls = github.calls;
      expect((await read(id, cookie)).statusCode).toBe(401); // the old cookie no longer works
      expect(github.calls).toBe(calls); // no GitHub call: the session check comes first
    });

    /** What a browser needs to actually delete a __Host- cookie: same name, Secure, Path=/, already expired. */
    const deletes = (res: LightMyRequestResponse, name: string) => {
      const header = [res.headers['set-cookie'] ?? []].flat().find((h) => h.startsWith(`${name}=;`));
      return (
        header !== undefined &&
        /;\s*Secure/i.test(header) &&
        /;\s*Path=\//i.test(header) &&
        (/Expires=Thu, 01 Jan 1970/i.test(header) || /Max-Age=0/i.test(header))
      );
    };

    it('logout deletes the cookie in a way browsers accept for a __Host- cookie (Secure, Path=/)', async () => {
      const cookie = await signIn('ghu_member');
      const out = await app.inject({ method: 'POST', url: '/auth/logout', headers: { cookie, ...ORIGIN } });
      expect(deletes(out, '__Host-firstfix_session')).toBe(true);
    });

    it('a dead session cookie is dropped wherever it is noticed, so public scans keep working', async () => {
      const dead = '__Host-firstfix_session=logged-out-elsewhere';
      const me = await app.inject({ method: 'GET', url: '/me', headers: { cookie: dead } });
      expect(me.json()).toMatchObject({ session: 'expired' });
      expect(deletes(me, '__Host-firstfix_session')).toBe(true);

      const submit = await app.inject({ method: 'POST', url: '/scans', payload: { repoUrl: 'https://github.com/acme/website' }, headers: { cookie: dead, ...ORIGIN } });
      expect(submit.statusCode).toBe(401);
      expect(deletes(submit, '__Host-firstfix_session')).toBe(true);

      const read = await app.inject({ method: 'GET', url: '/scans/00000000-0000-4000-8000-000000000000', headers: { accept: 'application/json', cookie: dead } });
      expect(read.statusCode).toBe(401);
      expect(deletes(read, '__Host-firstfix_session')).toBe(true);
    });

    it('the sign-in callback deletes its one-time cookie properly too', async () => {
      const cb = await signInFlow('ghu_member');
      expect(deletes(cb, '__Host-firstfix_oauth')).toBe(true);
    });

    it('a session-authenticated POST from another origin is refused; cookie-less API clients are unaffected', async () => {
      const cookie = await signIn('ghu_member');
      const bad = await app.inject({ method: 'POST', url: '/scans', payload: { repoUrl: 'https://github.com/acme/secret-app' }, headers: { cookie, origin: 'https://evil.example' } });
      expect(bad.statusCode).toBe(403);
      const noOrigin = await app.inject({ method: 'POST', url: '/auth/logout', headers: { cookie } });
      expect(noOrigin.statusCode).toBe(403);
      const anon = await app.inject({ method: 'POST', url: '/scans', payload: { repoUrl: 'https://github.com/acme/website' } });
      expect(anon.statusCode).toBe(202);
    });
  });
});

describe('sign-in off (no GitHub App configured)', () => {
  it('serves public scans only, with no sign-in routes', async () => {
    const env = await createTestEnv();
    const webDir = await mkdtemp(path.join(tmpdir(), 'web-'));
    await writeFile(path.join(webDir, 'index.html'), '<!doctype html>');
    const app = buildApp({
      scans: new ScanService(new PostgresScanSubmission(env.pool, env.boss), new PostgresScanRepository(env.pool)),
      checkReady: () => Promise.resolve(),
      webDir,
    });
    try {
      expect((await app.inject({ method: 'GET', url: '/me' })).json()).toMatchObject({ signInEnabled: false });
      expect((await app.inject({ method: 'GET', url: '/auth/login' })).statusCode).toBe(404);
      const res = await app.inject({ method: 'POST', url: '/scans', payload: { repoUrl: 'https://github.com/a/b' }, headers: { cookie: '__Host-firstfix_session=x' } });
      expect(res.statusCode).toBe(202);
    } finally {
      await app.close();
      await env.close();
      await rm(webDir, { recursive: true, force: true });
    }
  });
});

describe('request logs', () => {
  it('never contain the OAuth code or state (query strings are dropped)', async () => {
    const env = await createTestEnv();
    const webDir = await mkdtemp(path.join(tmpdir(), 'web-'));
    await writeFile(path.join(webDir, 'index.html'), '<!doctype html>');
    const lines: string[] = [];
    const access = new AccessService({
      github: new FakeGitHub(),
      sessions: new PostgresSessionStore(env.pool, new SecretBox('k'.repeat(32))),
      redirectUri: `${PUBLIC_URL}/auth/callback`,
    });
    const app = buildApp({
      scans: new ScanService(new PostgresScanSubmission(env.pool, env.boss), new PostgresScanRepository(env.pool)),
      checkReady: () => Promise.resolve(),
      webDir,
      signIn: { access, publicUrl: PUBLIC_URL },
      logger: true,
      logStream: { write: (line) => lines.push(line) },
    });
    try {
      await app.inject({ method: 'GET', url: '/auth/callback?code=SECRET_CODE_123&state=SECRET_STATE_456' });
      await app.inject({ method: 'GET', url: '/github/setup?installation_id=70&setup_action=install' });
      const log = lines.join('');
      expect(log).toContain('"url":"/auth/callback"');
      expect(log).not.toContain('SECRET_CODE_123');
      expect(log).not.toContain('SECRET_STATE_456');
      expect(log).not.toContain('installation_id');
    } finally {
      await app.close();
      await env.close();
      await rm(webDir, { recursive: true, force: true });
    }
  });
});
