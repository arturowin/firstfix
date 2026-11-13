/** A GitHub repository (public or private), identified by lowercase owner/name. */
export interface RepoRef {
  owner: string;
  name: string;
  /** Canonical form used for idempotency and display: https://github.com/<owner>/<name> */
  url: string;
}

export type ParseRepoUrlResult = { ok: true; repo: RepoRef } | { ok: false; error: string };

// GitHub's own limits: owner 1-39 chars, alphanumeric or single hyphens, no leading/trailing hyphen;
// repository names use letters, digits, '.', '-', '_' (max 100).
const OWNER = /^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,38}$/;
const NAME = /^[a-z0-9._-]{1,100}$/;
const HOSTS = new Set(['github.com', 'www.github.com']);

/**
 * Accepts `https://github.com/owner/repo` with optional `www.`, missing scheme, trailing slash or `.git`.
 * Rejects other hosts, deeper paths (branches, files), query strings and fragments, so the user learns
 * exactly what is scanned: the default branch of that repository.
 */
export function parseRepoUrl(input: string): ParseRepoUrlResult {
  const raw = input.trim();
  if (raw === '') return { ok: false, error: 'Enter a GitHub repository URL, e.g. https://github.com/owner/repo' };

  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
  } catch {
    return { ok: false, error: 'This is not a valid URL' };
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return { ok: false, error: 'Use an https://github.com/owner/repo URL' };
  }
  if (!HOSTS.has(url.hostname.toLowerCase())) {
    return { ok: false, error: 'Only repositories on github.com are supported' };
  }
  if (url.username || url.password || url.port) {
    return { ok: false, error: 'Use a plain https://github.com/owner/repo URL' };
  }
  if (url.search || url.hash) {
    return { ok: false, error: 'Remove the query string or fragment: use https://github.com/owner/repo' };
  }

  const segments = url.pathname.split('/').filter((s) => s !== '');
  if (segments.length !== 2) {
    return {
      ok: false,
      error:
        segments.length < 2
          ? 'The URL must include both owner and repository: https://github.com/owner/repo'
          : 'Link to the repository itself, not a branch, folder or file: https://github.com/owner/repo',
    };
  }

  const owner = decodeURIComponent(segments[0] ?? '').toLowerCase();
  let name = decodeURIComponent(segments[1] ?? '').toLowerCase();
  if (name.endsWith('.git')) name = name.slice(0, -'.git'.length);

  if (!OWNER.test(owner)) return { ok: false, error: `"${owner}" is not a valid GitHub owner name` };
  if (!NAME.test(name) || name === '.' || name === '..') {
    return { ok: false, error: `"${name}" is not a valid GitHub repository name` };
  }

  return { ok: true, repo: { owner, name, url: `https://github.com/${owner}/${name}` } };
}
