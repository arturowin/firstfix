import { PermanentError, TransientError } from '../../ports/errors.ts';
import {
  UserTokenRejected,
  type AccessibleRepository,
  type AppInstallation,
  type GitHubAuth,
  type GitHubUser,
  type GitHubUserToken,
  type RepositoryList,
} from '../../ports/github-auth.ts';
import { fetchWithTimeout, USER_AGENT } from '../http.ts';
import { API_VERSION, nextPage, transientOrPermanent } from './common.ts';

export interface GitHubUserAuthOptions {
  clientId: string;
  clientSecret: string;
  /** The app's URL name, for its install page. */
  slug: string;
  apiBase?: string;
  webBase?: string;
  timeoutMs?: number;
  /** Pages of 100 per listing; beyond this the listing is reported as truncated. */
  maxPages?: number;
}

/** GitHub App user authorization (OAuth web flow with PKCE) and the user-token listings. */
export class GitHubUserAuth implements GitHubAuth {
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly slug: string;
  private readonly apiBase: string;
  private readonly webBase: string;
  private readonly timeoutMs: number;
  private readonly maxPages: number;

  constructor(options: GitHubUserAuthOptions) {
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.slug = options.slug;
    this.apiBase = options.apiBase ?? 'https://api.github.com';
    this.webBase = options.webBase ?? 'https://github.com';
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.maxPages = options.maxPages ?? 100;
  }

  authorizeUrl(input: { state: string; codeChallenge: string; redirectUri: string }): string {
    const url = new URL('/login/oauth/authorize', this.webBase);
    url.searchParams.set('client_id', this.clientId);
    url.searchParams.set('redirect_uri', input.redirectUri);
    url.searchParams.set('state', input.state);
    url.searchParams.set('code_challenge', input.codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    return url.toString();
  }

  installUrl(): string {
    return new URL(`/apps/${encodeURIComponent(this.slug)}/installations/new`, this.webBase).toString();
  }

  async exchangeCode(input: { code: string; codeVerifier: string; redirectUri: string }, signal: AbortSignal): Promise<GitHubUserToken> {
    const res = await fetchWithTimeout(new URL('/login/oauth/access_token', this.webBase).toString(), {
      method: 'POST',
      headers: { accept: 'application/json', 'content-type': 'application/json', 'user-agent': USER_AGENT },
      body: JSON.stringify({
        client_id: this.clientId,
        client_secret: this.clientSecret,
        code: input.code,
        redirect_uri: input.redirectUri,
        code_verifier: input.codeVerifier,
      }),
      timeoutMs: this.timeoutMs,
      signal,
      service: 'github',
    });
    if (!res.ok) throw transientOrPermanent(res, 'token exchange');
    // GitHub answers 200 with { error } for a bad, expired or reused code.
    const body = (await res.json()) as { access_token?: unknown; expires_in?: unknown; error?: unknown };
    if (typeof body.access_token !== 'string' || body.access_token === '') {
      throw new PermanentError('oauth_exchange_failed', `GitHub refused the sign-in code (${typeof body.error === 'string' ? body.error : 'no token'})`);
    }
    const expiresAt = typeof body.expires_in === 'number' && body.expires_in > 0 ? new Date(Date.now() + body.expires_in * 1000) : null;
    return { token: body.access_token, expiresAt };
  }

  async user(token: string, signal: AbortSignal): Promise<GitHubUser> {
    const res = await this.get(`${this.apiBase}/user`, token, signal);
    const body = (await res.json()) as { id?: unknown; login?: unknown };
    if (typeof body.id !== 'number' || typeof body.login !== 'string') throw new PermanentError('github_bad_response', 'GitHub returned a user without id or login');
    return { id: body.id, login: body.login };
  }

  async installations(token: string, signal: AbortSignal): Promise<AppInstallation[]> {
    const out: AppInstallation[] = [];
    await this.paginate(`${this.apiBase}/user/installations?per_page=100`, token, signal, (body) => {
      const items = (body as { installations?: unknown }).installations;
      for (const i of Array.isArray(items) ? (items as unknown[]) : []) {
        const inst = i as { id?: unknown; account?: { login?: unknown; slug?: unknown } | null };
        const account = inst.account?.login ?? inst.account?.slug;
        if (typeof inst.id === 'number' && typeof account === 'string') out.push({ id: inst.id, account });
      }
    });
    return out;
  }

  async repositories(token: string, installationId: number, signal: AbortSignal): Promise<RepositoryList | null> {
    const repositories: AccessibleRepository[] = [];
    const url = `${this.apiBase}/user/installations/${String(installationId)}/repositories?per_page=100`;
    const result = await this.paginate(
      url,
      token,
      signal,
      (body) => {
        const items = (body as { repositories?: unknown }).repositories;
        for (const r of Array.isArray(items) ? (items as unknown[]) : []) {
          const repo = r as { id?: unknown; name?: unknown; private?: unknown; owner?: { login?: unknown } | null };
          if (typeof repo.id === 'number' && typeof repo.name === 'string' && typeof repo.owner?.login === 'string') {
            repositories.push({ id: repo.id, owner: repo.owner.login, name: repo.name, private: repo.private === true });
          }
        }
      },
      // Not the user's installation (or no longer accessible): no repositories, not an error.
      [403, 404],
    );
    if (result === 'absent') return null;
    return { repositories, truncated: result === 'truncated' };
  }

  /** Follows Link rel="next" on the same origin, up to maxPages. */
  private async paginate(
    first: string,
    token: string,
    signal: AbortSignal,
    onPage: (body: unknown) => void,
    absentOn: number[] = [],
  ): Promise<'complete' | 'truncated' | 'absent'> {
    let url: string | null = first;
    for (let page = 0; url !== null; page++) {
      if (page >= this.maxPages) return 'truncated';
      const res = await this.get(url, token, signal, absentOn);
      if (res === null) return 'absent';
      onPage(await res.json());
      url = nextPage(res, this.apiBase);
    }
    return 'complete';
  }

  private async get(url: string, token: string, signal: AbortSignal): Promise<Response>;
  private async get(url: string, token: string, signal: AbortSignal, absentOn: number[]): Promise<Response | null>;
  private async get(url: string, token: string, signal: AbortSignal, absentOn: number[] = []): Promise<Response | null> {
    const res = await fetchWithTimeout(url, {
      headers: {
        accept: 'application/vnd.github+json',
        'x-github-api-version': API_VERSION,
        'user-agent': USER_AGENT,
        authorization: `Bearer ${token}`,
      },
      timeoutMs: this.timeoutMs,
      signal,
      service: 'github',
    });
    if (res.ok) return res;
    if (res.status === 401) throw new UserTokenRejected();
    const err = transientOrPermanent(res, new URL(url).pathname);
    if (absentOn.includes(res.status) && !(err instanceof TransientError)) return null;
    throw err;
  }
}
