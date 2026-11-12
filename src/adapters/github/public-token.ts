import { fetchWithTimeout, USER_AGENT } from '../http.ts';
import { API_VERSION } from './common.ts';

export type PublicTokenCheck = 'public_only' | 'privileged' | 'invalid' | 'unverified';

/**
 * Public scans must never use credentials that can read private repositories. GITHUB_TOKEN is only used when
 * this check says `public_only`: a classic token with the `repo` scope, or any token that can list a private
 * repository, is `privileged`. Anything that can't be decided is `unverified` and the token isn't used.
 */
export async function checkPublicOnlyToken(
  token: string,
  options: { apiBase?: string; timeoutMs?: number } = {},
): Promise<PublicTokenCheck> {
  const apiBase = options.apiBase ?? 'https://api.github.com';
  const get = (path: string) =>
    fetchWithTimeout(`${apiBase}${path}`, {
      headers: {
        accept: 'application/vnd.github+json',
        'x-github-api-version': API_VERSION,
        'user-agent': USER_AGENT,
        authorization: `Bearer ${token}`,
      },
      timeoutMs: options.timeoutMs ?? 10_000,
      signal: new AbortController().signal,
      service: 'github',
    });
  try {
    const user = await get('/user');
    if (user.status === 401) return 'invalid';
    if (!user.ok) return 'unverified';
    // Classic tokens list their scopes; `repo` grants private repositories.
    const scopes = (user.headers.get('x-oauth-scopes') ?? '').split(',').map((s) => s.trim());
    if (scopes.includes('repo')) return 'privileged';

    const repos = await get('/user/repos?visibility=private&per_page=1');
    if (!repos.ok) return 'unverified';
    const list: unknown = await repos.json();
    if (!Array.isArray(list)) return 'unverified';
    return list.length > 0 ? 'privileged' : 'public_only';
  } catch {
    return 'unverified';
  }
}
