import { createPrivateKey, sign, type KeyObject } from 'node:crypto';
import { PermanentError } from '../../ports/errors.ts';
import { fetchWithTimeout, USER_AGENT } from '../http.ts';
import { API_VERSION, isRateLimited, transientOrPermanent } from './common.ts';

/** What the repo source needs: a token for one installation, scoped to one repository. */
export interface InstallationTokens {
  token(installationId: number, repositoryId: number, signal: AbortSignal): Promise<string>;
  /** Drops a cached token GitHub no longer accepts. */
  invalidate(installationId: number, repositoryId: number): void;
}

export interface GitHubAppTokensOptions {
  /** `iss` for the app JWT; GitHub recommends the client id. */
  clientId: string;
  /** PEM. Literal "\n" sequences (common in env files) are accepted. */
  privateKey: string;
  apiBase?: string;
  timeoutMs?: number;
  now?: () => number;
}

const REFRESH_BEFORE_MS = 5 * 60 * 1000;

/**
 * Installation tokens for the worker, minted with the app's private key and scoped to a single repository with
 * read-only contents. Cached per (installation, repository) until 5 minutes before they expire.
 */
export class GitHubAppTokens implements InstallationTokens {
  private readonly clientId: string;
  private readonly key: KeyObject;
  private readonly apiBase: string;
  private readonly timeoutMs: number;
  private readonly now: () => number;
  private readonly cache = new Map<string, { token: string; expiresAt: number }>();

  constructor(options: GitHubAppTokensOptions) {
    this.clientId = options.clientId;
    // Fails at startup on a malformed key, not on the first private scan.
    this.key = createPrivateKey(options.privateKey.replaceAll('\\n', '\n'));
    this.apiBase = options.apiBase ?? 'https://api.github.com';
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.now = options.now ?? Date.now;
  }

  /** RS256 JWT: iat 60 s in the past (clock drift), 9-minute expiry (GitHub allows at most 10). */
  appJwt(): string {
    const seconds = Math.floor(this.now() / 1000);
    const encode = (v: object) => Buffer.from(JSON.stringify(v)).toString('base64url');
    const unsigned = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({ iat: seconds - 60, exp: seconds + 540, iss: this.clientId })}`;
    return `${unsigned}.${sign('sha256', Buffer.from(unsigned), this.key).toString('base64url')}`;
  }

  async token(installationId: number, repositoryId: number, signal: AbortSignal): Promise<string> {
    const cacheKey = `${String(installationId)}:${String(repositoryId)}`;
    const hit = this.cache.get(cacheKey);
    if (hit && hit.expiresAt - REFRESH_BEFORE_MS > this.now()) return hit.token;

    const res = await fetchWithTimeout(`${this.apiBase}/app/installations/${String(installationId)}/access_tokens`, {
      method: 'POST',
      headers: {
        accept: 'application/vnd.github+json',
        'x-github-api-version': API_VERSION,
        'user-agent': USER_AGENT,
        'content-type': 'application/json',
        authorization: `Bearer ${this.appJwt()}`,
      },
      body: JSON.stringify({ repository_ids: [repositoryId], permissions: { contents: 'read', metadata: 'read' } }),
      timeoutMs: this.timeoutMs,
      signal,
      service: 'github',
    });
    if (!res.ok) {
      if (res.status === 401) {
        throw new PermanentError('github_app_auth', "GitHub rejected FirstFix's GitHub App credentials; check the app's client id and private key");
      }
      // 404: installation gone; 422: repository not in it; 403 (not a rate limit): installation suspended.
      if (res.status === 404 || res.status === 422 || (res.status === 403 && !isRateLimited(res))) {
        throw revoked();
      }
      throw transientOrPermanent(res, 'installation token');
    }
    const body = (await res.json()) as { token?: unknown; expires_at?: unknown };
    const expiresAt = typeof body.expires_at === 'string' ? Date.parse(body.expires_at) : Number.NaN;
    if (typeof body.token !== 'string' || Number.isNaN(expiresAt)) {
      throw new PermanentError('github_bad_response', 'GitHub returned an installation token without token or expiry');
    }
    this.cache.set(cacheKey, { token: body.token, expiresAt });
    return body.token;
  }

  invalidate(installationId: number, repositoryId: number): void {
    this.cache.delete(`${String(installationId)}:${String(repositoryId)}`);
  }
}

export function revoked(): PermanentError {
  return new PermanentError(
    'app_access_revoked',
    'FirstFix no longer has access to this repository. Reconnect GitHub, or ask an organization owner to give the FirstFix app access to it.',
  );
}
