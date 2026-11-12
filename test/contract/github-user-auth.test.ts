/** Mocked GitHub (msw): the shapes follow GitHub's REST docs; a live check needs a real GitHub App. */
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { GitHubUserAuth } from '../../src/adapters/github/user-auth.ts';
import { PermanentError, TransientError } from '../../src/ports/errors.ts';
import { UserTokenRejected } from '../../src/ports/github-auth.ts';

const API = 'https://api.github.com';
const WEB = 'https://github.com';
const signal = () => new AbortController().signal;
const auth = (maxPages?: number) =>
  new GitHubUserAuth({ clientId: 'Iv1.client', clientSecret: 'shh', slug: 'firstfix', ...(maxPages ? { maxPages } : {}) });

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

const repo = (id: number, owner = 'acme', priv = true) => ({ id, name: `repo-${String(id)}`, private: priv, owner: { login: owner } });

/** 250 repositories over three pages, linked like GitHub does. */
function pagedRepos(seen: string[] = []) {
  server.use(
    http.get(`${API}/user/installations/7/repositories`, ({ request }) => {
      const url = new URL(request.url);
      seen.push(request.headers.get('authorization') ?? '');
      const page = Number(url.searchParams.get('page') ?? '1');
      const ids = Array.from({ length: page < 3 ? 100 : 50 }, (_, i) => (page - 1) * 100 + i + 1);
      const headers: Record<string, string> = {};
      if (page < 3) headers['link'] = `<${API}/user/installations/7/repositories?per_page=100&page=${String(page + 1)}>; rel="next"`;
      return HttpResponse.json({ total_count: 250, repositories: ids.map((id) => repo(id)) }, { headers });
    }),
  );
}

describe('GitHubUserAuth', () => {
  it('builds the authorize URL with state and PKCE S256', () => {
    const url = new URL(auth().authorizeUrl({ state: 'st', codeChallenge: 'ch', redirectUri: 'https://ff.example/auth/callback' }));
    expect(url.origin + url.pathname).toBe(`${WEB}/login/oauth/authorize`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: 'Iv1.client',
      redirect_uri: 'https://ff.example/auth/callback',
      state: 'st',
      code_challenge: 'ch',
      code_challenge_method: 'S256',
    });
  });

  it('exchanges the code with the PKCE verifier and reads the expiry', async () => {
    let body: Record<string, unknown> = {};
    server.use(
      http.post(`${WEB}/login/oauth/access_token`, async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ access_token: 'ghu_abc', expires_in: 28800, token_type: 'bearer' });
      }),
    );
    const before = Date.now();
    const token = await auth().exchangeCode({ code: 'c0de', codeVerifier: 'v3rifier', redirectUri: 'https://ff.example/auth/callback' }, signal());
    expect(body).toEqual({
      client_id: 'Iv1.client',
      client_secret: 'shh',
      code: 'c0de',
      redirect_uri: 'https://ff.example/auth/callback',
      code_verifier: 'v3rifier',
    });
    expect(token.token).toBe('ghu_abc');
    expect(token.expiresAt?.getTime()).toBeGreaterThanOrEqual(before + 28_800_000);
  });

  it('a refused code (200 with an error) is permanent', async () => {
    server.use(http.post(`${WEB}/login/oauth/access_token`, () => HttpResponse.json({ error: 'bad_verification_code' })));
    await expect(auth().exchangeCode({ code: 'x', codeVerifier: 'y', redirectUri: 'z' }, signal())).rejects.toBeInstanceOf(PermanentError);
  });

  it('a GitHub outage during the exchange is transient', async () => {
    server.use(http.post(`${WEB}/login/oauth/access_token`, () => new HttpResponse(null, { status: 502 })));
    await expect(auth().exchangeCode({ code: 'x', codeVerifier: 'y', redirectUri: 'z' }, signal())).rejects.toBeInstanceOf(TransientError);
  });

  it('a rejected user token is reported as such', async () => {
    server.use(http.get(`${API}/user`, () => new HttpResponse(null, { status: 401 })));
    await expect(auth().user('ghu_old', signal())).rejects.toBeInstanceOf(UserTokenRejected);
  });

  it('lists every installation across pages, including organization ones', async () => {
    server.use(
      http.get(`${API}/user/installations`, ({ request }) => {
        const page = new URL(request.url).searchParams.get('page');
        return page === '2'
          ? HttpResponse.json({ installations: [{ id: 2, account: { login: 'acme-org' } }] })
          : HttpResponse.json(
              { installations: [{ id: 1, account: { login: 'alice' } }] },
              { headers: { link: `<${API}/user/installations?per_page=100&page=2>; rel="next"` } },
            );
      }),
    );
    expect(await auth().installations('ghu_abc', signal())).toEqual([
      { id: 1, account: 'alice' },
      { id: 2, account: 'acme-org' },
    ]);
  });

  it('lists repositories beyond the first page, with the user token', async () => {
    const seen: string[] = [];
    pagedRepos(seen);
    const list = await auth().repositories('ghu_abc', 7, signal());
    expect(list?.repositories).toHaveLength(250);
    expect(list?.repositories.at(-1)).toEqual({ id: 250, owner: 'acme', name: 'repo-250', private: true });
    expect(list?.truncated).toBe(false);
    expect(seen).toEqual(['Bearer ghu_abc', 'Bearer ghu_abc', 'Bearer ghu_abc']);
  });

  it('reports a listing cut off at the page cap as truncated', async () => {
    pagedRepos();
    const list = await auth(2).repositories('ghu_abc', 7, signal());
    expect(list?.repositories).toHaveLength(200);
    expect(list?.truncated).toBe(true);
  });

  it('never follows a next link to another origin (the token stays with GitHub)', async () => {
    server.use(
      http.get(`${API}/user/installations/7/repositories`, () =>
        HttpResponse.json({ repositories: [repo(1)] }, { headers: { link: '<https://evil.example/steal?page=2>; rel="next"' } }),
      ),
    );
    const list = await auth().repositories('ghu_abc', 7, signal());
    expect(list?.repositories.map((r) => r.id)).toEqual([1]);
  });

  it.each([403, 404])('an installation the user cannot access (%i) lists nothing', async (status) => {
    server.use(http.get(`${API}/user/installations/9/repositories`, () => new HttpResponse(null, { status })));
    expect(await auth().repositories('ghu_abc', 9, signal())).toBeNull();
  });

  it('a rate limit is transient, not "no access"', async () => {
    server.use(
      http.get(`${API}/user/installations/9/repositories`, () => new HttpResponse(null, { status: 403, headers: { 'x-ratelimit-remaining': '0' } })),
    );
    await expect(auth().repositories('ghu_abc', 9, signal())).rejects.toBeInstanceOf(TransientError);
  });
});
