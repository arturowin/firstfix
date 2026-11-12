/**
 * Mocked GitHub (msw) for the worker's GitHub App path and the public path's credential rules. The shapes follow
 * GitHub's REST docs; a live check needs a real GitHub App.
 */
import { generateKeyPairSync, verify } from 'node:crypto';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { GitHubAppTokens } from '../../src/adapters/github/app-tokens.ts';
import { checkPublicOnlyToken } from '../../src/adapters/github/public-token.ts';
import { GitHubRepoSource } from '../../src/adapters/github/repo-source.ts';
import { PermanentError, TransientError } from '../../src/ports/errors.ts';
import type { RepoAccess } from '../../src/ports/repo-source.ts';

const API = 'https://api.github.com';
const RAW = 'https://raw.githubusercontent.com';
const SHA = 'b'.repeat(40);
const signal = () => new AbortController().signal;
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const PEM = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const PRIVATE: RepoAccess = { kind: 'installation', installationId: 7, repositoryId: 42 };
const repo = { owner: 'acme', name: 'secret-app' };

const server = setupServer();
beforeAll(() => {
  server.listen({ onUnhandledFrame: 'error' });
});
afterEach(() => {
  server.resetHandlers();
});
afterAll(() => {
  server.close();
});

interface Seen {
  mints: { auth: string; body: unknown }[];
  calls: { path: string; auth: string | null; accept: string | null }[];
}

function privateRepo(seen: Seen, options: { listedId?: number; mintStatus?: number; contents?: number } = {}) {
  server.use(
    http.post(`${API}/app/installations/7/access_tokens`, async ({ request }) => {
      seen.mints.push({ auth: request.headers.get('authorization') ?? '', body: await request.json() });
      if (options.mintStatus) return new HttpResponse(null, { status: options.mintStatus });
      return HttpResponse.json({ token: 'ghs_scoped', expires_at: new Date(Date.now() + 3_600_000).toISOString() }, { status: 201 });
    }),
    http.get(`${API}/installation/repositories`, ({ request }) => {
      seen.calls.push({ path: '/installation/repositories', auth: request.headers.get('authorization'), accept: null });
      return HttpResponse.json({
        repositories: [{ id: options.listedId ?? 42, full_name: 'Acme/Secret-App', default_branch: 'trunk', private: true }],
      });
    }),
    http.get(`${API}/repos/Acme/Secret-App/commits/trunk`, ({ request }) => {
      seen.calls.push({ path: 'commits', auth: request.headers.get('authorization'), accept: null });
      return HttpResponse.json({ sha: SHA });
    }),
    http.get(`${API}/repos/Acme/Secret-App/contents/:file`, ({ request, params }) => {
      const url = new URL(request.url);
      seen.calls.push({ path: `contents/${String(params['file'])}?ref=${url.searchParams.get('ref') ?? ''}`, auth: request.headers.get('authorization'), accept: request.headers.get('accept') });
      if (options.contents) return new HttpResponse(null, { status: options.contents });
      return params['file'] === 'package-lock.json' ? HttpResponse.text('{"lockfileVersion":3}') : new HttpResponse(null, { status: 404 });
    }),
  );
}

const newSeen = (): Seen => ({ mints: [], calls: [] });

describe('GitHubAppTokens', () => {
  it('signs an RS256 app JWT: iss = client id, iat 60 s back, expiry under 10 minutes', () => {
    const now = 1_800_000_000_000;
    const jwt = new GitHubAppTokens({ clientId: 'Iv1.client', privateKey: PEM, now: () => now }).appJwt();
    const [h, p, sig] = jwt.split('.') as [string, string, string];
    expect(JSON.parse(Buffer.from(h, 'base64url').toString())).toEqual({ alg: 'RS256', typ: 'JWT' });
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString()) as { iat: number; exp: number; iss: string };
    expect(claims.iss).toBe('Iv1.client');
    expect(claims.iat).toBe(now / 1000 - 60);
    expect(claims.exp - now / 1000).toBeLessThanOrEqual(600);
    expect(verify('sha256', Buffer.from(`${h}.${p}`), publicKey, Buffer.from(sig, 'base64url'))).toBe(true);
  });

  it('accepts a PEM with literal \\n sequences (env files)', () => {
    expect(() => new GitHubAppTokens({ clientId: 'c', privateKey: PEM.replaceAll('\n', '\\n') })).not.toThrow();
  });

  it('mints a token scoped to the one repository, read-only, and reuses it until near expiry', async () => {
    const seen = newSeen();
    privateRepo(seen);
    const tokens = new GitHubAppTokens({ clientId: 'Iv1.client', privateKey: PEM });
    expect(await tokens.token(7, 42, signal())).toBe('ghs_scoped');
    expect(await tokens.token(7, 42, signal())).toBe('ghs_scoped');
    expect(seen.mints).toHaveLength(1);
    expect(seen.mints[0]?.body).toEqual({ repository_ids: [42], permissions: { contents: 'read', metadata: 'read' } });
    expect(seen.mints[0]?.auth).toMatch(/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/);
  });

  it.each([404, 422, 403])('confirmed loss of access (%i) is permanent: app_access_revoked', async (status) => {
    privateRepo(newSeen(), { mintStatus: status });
    const err = await new GitHubAppTokens({ clientId: 'c', privateKey: PEM }).token(7, 42, signal()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PermanentError);
    expect((err as PermanentError).code).toBe('app_access_revoked');
  });

  it('rejected app credentials are permanent', async () => {
    privateRepo(newSeen(), { mintStatus: 401 });
    const err = await new GitHubAppTokens({ clientId: 'c', privateKey: PEM }).token(7, 42, signal()).catch((e: unknown) => e);
    expect((err as PermanentError).code).toBe('github_app_auth');
  });

  it.each([500, 502, 503])('a GitHub error (%i) while minting is transient (retried)', async (status) => {
    privateRepo(newSeen(), { mintStatus: status });
    await expect(new GitHubAppTokens({ clientId: 'c', privateKey: PEM }).token(7, 42, signal())).rejects.toBeInstanceOf(TransientError);
  });

  it('a rate limit while minting is transient', async () => {
    server.use(
      http.post(`${API}/app/installations/7/access_tokens`, () => new HttpResponse(null, { status: 403, headers: { 'retry-after': '60' } })),
    );
    await expect(new GitHubAppTokens({ clientId: 'c', privateKey: PEM }).token(7, 42, signal())).rejects.toBeInstanceOf(TransientError);
  });
});

describe('GitHubRepoSource, private path', () => {
  const source = () => new GitHubRepoSource({ appTokens: new GitHubAppTokens({ clientId: 'c', privateKey: PEM }) });

  it('resolves by repository id through the scoped token, then reads the lockfile at the SHA via the contents API', async () => {
    const seen = newSeen();
    privateRepo(seen);
    const gh = source();
    expect(await gh.resolveDefaultCommit(repo, PRIVATE, signal())).toEqual({ sha: SHA, branch: 'trunk' });
    expect(await gh.readFile(repo, PRIVATE, SHA, 'package-lock.json', signal())).toBe('{"lockfileVersion":3}');
    expect(await gh.readFile(repo, PRIVATE, SHA, 'yarn.lock', signal())).toBeNull();
    expect(seen.calls.every((c) => c.auth === 'Bearer ghs_scoped')).toBe(true);
    expect(seen.calls.find((c) => c.path.startsWith('contents/package-lock.json'))).toEqual({
      path: `contents/package-lock.json?ref=${SHA}`,
      auth: 'Bearer ghs_scoped',
      accept: 'application/vnd.github.raw+json',
    });
  });

  it('a renamed repository is found by its id (the recorded owner/name is not used)', async () => {
    const seen = newSeen();
    privateRepo(seen);
    await source().resolveDefaultCommit({ owner: 'old-owner', name: 'old-name' }, PRIVATE, signal());
    expect(seen.calls.map((c) => c.path)).toEqual(['/installation/repositories', 'commits']);
  });

  it('a file 404 while access still holds is a missing file', async () => {
    const seen = newSeen();
    privateRepo(seen);
    const gh = source();
    const { sha } = await gh.resolveDefaultCommit(repo, PRIVATE, signal());
    expect(await gh.readFile(repo, PRIVATE, sha, 'yarn.lock', signal())).toBeNull();
    // The 404 was double-checked against the scoped listing before concluding "missing".
    expect(seen.calls.map((c) => c.path)).toEqual(['/installation/repositories', 'commits', `contents/yarn.lock?ref=${SHA}`, '/installation/repositories']);
  });

  it('access lost between resolving the commit and reading the lockfile is app_access_revoked, not a missing lockfile', async () => {
    const seen = newSeen();
    privateRepo(seen);
    const gh = source();
    const { sha } = await gh.resolveDefaultCommit(repo, PRIVATE, signal());
    // The repository is removed from the installation: its file now 404s and the scoped listing is empty.
    server.use(
      http.get(`${API}/repos/Acme/Secret-App/contents/:file`, () => new HttpResponse(null, { status: 404 })),
      http.get(`${API}/installation/repositories`, () => HttpResponse.json({ total_count: 0, repositories: [] })),
    );
    const err = await gh.readFile(repo, PRIVATE, sha, 'package-lock.json', signal()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PermanentError);
    expect((err as PermanentError).code).toBe('app_access_revoked');
  });

  it('a different repository id than recorded is permanent: no access', async () => {
    privateRepo(newSeen(), { listedId: 99 });
    const err = await source().resolveDefaultCommit(repo, PRIVATE, signal()).catch((e: unknown) => e);
    expect((err as PermanentError).code).toBe('app_access_revoked');
  });

  it('without the GitHub App configured, a private scan fails permanently', async () => {
    const err = await new GitHubRepoSource().resolveDefaultCommit(repo, PRIVATE, signal()).catch((e: unknown) => e);
    expect((err as PermanentError).code).toBe('github_app_not_configured');
  });

  it('a GitHub outage while reading is transient', async () => {
    const seen = newSeen();
    privateRepo(seen, { contents: 503 });
    const gh = source();
    await gh.resolveDefaultCommit(repo, PRIVATE, signal());
    await expect(gh.readFile(repo, PRIVATE, SHA, 'package-lock.json', signal())).rejects.toBeInstanceOf(TransientError);
  });
});

describe('GitHubRepoSource, public path never uses private credentials', () => {
  it('reads the lockfile without any credentials, even with a (verified) token configured', async () => {
    const raw: (string | null)[] = [];
    const api: (string | null)[] = [];
    server.use(
      http.get(`${API}/repos/owner/repo`, ({ request }) => {
        api.push(request.headers.get('authorization'));
        return HttpResponse.json({ default_branch: 'main', private: false });
      }),
      http.get(`${API}/repos/owner/repo/commits/main`, () => HttpResponse.json({ sha: SHA })),
      http.get(`${RAW}/owner/repo/:sha/package-lock.json`, ({ request }) => {
        raw.push(request.headers.get('authorization'));
        return HttpResponse.text('{}');
      }),
    );
    const gh = new GitHubRepoSource({ token: 'github_pat_public', appTokens: new GitHubAppTokens({ clientId: 'c', privateKey: PEM }) });
    const { sha } = await gh.resolveDefaultCommit({ owner: 'owner', name: 'repo' }, { kind: 'public' }, signal());
    await gh.readFile({ owner: 'owner', name: 'repo' }, { kind: 'public' }, sha, 'package-lock.json', signal());
    expect(api).toEqual(['Bearer github_pat_public']);
    expect(raw).toEqual([null]);
    // No handler for /app/installations: any mint attempt would fail the test (onUnhandledFrame: 'error').
  });
});

describe('checkPublicOnlyToken', () => {
  const user = (scopes?: string) =>
    http.get(`${API}/user`, () => HttpResponse.json({ login: 'bot' }, { headers: scopes === undefined ? {} : { 'x-oauth-scopes': scopes } }));
  const privateRepos = (n: number) => http.get(`${API}/user/repos`, () => HttpResponse.json(Array.from({ length: n }, (_, i) => ({ id: i }))));

  it('a classic token with the repo scope is privileged', async () => {
    server.use(user('read:org, repo'));
    expect(await checkPublicOnlyToken('ghp_x')).toBe('privileged');
  });

  it('a token that lists a private repository is privileged', async () => {
    server.use(user(), privateRepos(1));
    expect(await checkPublicOnlyToken('github_pat_x')).toBe('privileged');
  });

  it('a token that sees no private repository is public-only', async () => {
    server.use(user('public_repo'), privateRepos(0));
    expect(await checkPublicOnlyToken('ghp_public')).toBe('public_only');
  });

  it('an invalid token is reported, and an unanswered check is not trusted', async () => {
    server.use(http.get(`${API}/user`, () => new HttpResponse(null, { status: 401 })));
    expect(await checkPublicOnlyToken('bad')).toBe('invalid');
    server.use(http.get(`${API}/user`, () => new HttpResponse(null, { status: 503 })));
    expect(await checkPublicOnlyToken('x')).toBe('unverified');
  });
});
