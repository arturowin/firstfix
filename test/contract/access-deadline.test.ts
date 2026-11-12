/**
 * AccessService with the real GitHub adapter and a GitHub (msw) that doesn't answer in time: the service's own
 * deadline really expires (no mocked TransientError). A slow GitHub must read as "GitHub unavailable" (503 /
 * the sign-in error redirect), never as a server error or "no access".
 */
import { http } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { GitHubUserAuth } from '../../src/adapters/github/user-auth.ts';
import { AccessService, GitHubUnavailable } from '../../src/application/access-service.ts';
import type { Session, SessionLookup, SessionStore } from '../../src/ports/session-store.ts';

const API = 'https://api.github.com';
const WEB = 'https://github.com';

/** Answers only when the request is aborted, like a GitHub that never responds. */
const never = ({ request }: { request: Request }) =>
  new Promise<Response>((_resolve, reject) => {
    request.signal.addEventListener('abort', () => {
      reject(new DOMException('aborted', 'AbortError'));
    });
  });

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

const session: Session = { key: 'k1', githubUserId: 1, githubLogin: 'member', token: 'ghu_x', expiresAt: new Date(Date.now() + 3_600_000) };

/** Just enough of a session store for these paths. */
class MemorySessions implements SessionStore {
  deleted: string[] = [];
  create() {
    return Promise.resolve({ cookie: 'c', key: 'k' });
  }
  lookup(): Promise<SessionLookup> {
    return Promise.resolve({ state: 'active', session });
  }
  delete() {
    return Promise.resolve(null);
  }
  deleteByKey(key: string) {
    this.deleted.push(key);
    return Promise.resolve();
  }
  createOAuthState() {
    return Promise.resolve('state');
  }
  consumeOAuthState() {
    return Promise.resolve({ codeVerifier: 'verifier', returnTo: '/' });
  }
}

function service(sessions = new MemorySessions()) {
  return new AccessService({
    github: new GitHubUserAuth({ clientId: 'Iv1.c', clientSecret: 's', slug: 'firstfix' }),
    sessions,
    redirectUri: 'https://ff.example/auth/callback',
    timeoutMs: 50,
  });
}

describe('AccessService when GitHub does not answer in time', () => {
  it('a private-scan access check is GitHubUnavailable (→ 503), and the session survives', async () => {
    server.use(http.get(`${API}/user/installations`, never));
    const sessions = new MemorySessions();
    const err = await service(sessions)
      .readGate({ kind: 'private', repositoryId: 42, installationId: 7 }, { state: 'active', session })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GitHubUnavailable);
    expect(sessions.deleted).toEqual([]);
  });

  it('a slow repository listing (after installations answered) is GitHubUnavailable too', async () => {
    server.use(
      http.get(`${API}/user/installations`, () => Response.json({ installations: [{ id: 7, account: { login: 'acme' } }] })),
      http.get(`${API}/user/installations/7/repositories`, never),
    );
    await expect(service().repositories(session, 7)).rejects.toBeInstanceOf(GitHubUnavailable);
  });

  it('the setup-URL check is GitHubUnavailable', async () => {
    server.use(http.get(`${API}/user/installations`, never));
    await expect(service().verifyInstallation(session, 7)).rejects.toBeInstanceOf(GitHubUnavailable);
  });

  it('a slow code exchange during sign-in ends in the github_unavailable error, not a thrown error', async () => {
    server.use(http.post(`${WEB}/login/oauth/access_token`, never));
    expect(await service().finishSignIn({ code: 'c0de', state: 'state', error: undefined, binding: 'b' })).toEqual({
      kind: 'error',
      code: 'github_unavailable',
    });
  });

  it('a slow user lookup after the exchange also ends in github_unavailable', async () => {
    server.use(
      http.post(`${WEB}/login/oauth/access_token`, () => Response.json({ access_token: 'ghu_new', expires_in: 28800 })),
      http.get(`${API}/user`, never),
    );
    expect(await service().finishSignIn({ code: 'c0de', state: 'state', error: undefined, binding: 'b' })).toEqual({
      kind: 'error',
      code: 'github_unavailable',
    });
  });
});
