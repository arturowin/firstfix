import { PermanentError, TransientError } from '../../ports/errors.ts';
import type { RepoAccess, RepoSource } from '../../ports/repo-source.ts';
import { fetchWithTimeout, USER_AGENT } from '../http.ts';
import { revoked, type InstallationTokens } from './app-tokens.ts';
import { API_VERSION, transientOrPermanent } from './common.ts';

type Repo = { owner: string; name: string };
type Installation = Extract<RepoAccess, { kind: 'installation' }>;

export interface GitHubOptions {
  /**
   * Public scans only, for API rate limits (without it GitHub allows 60 requests/hour/IP). Must be a token that
   * can't read private repositories: the worker passes it only after checkPublicOnlyToken said so. Lockfiles of
   * public scans are always read without it.
   */
  token?: string | undefined;
  /** Private scans: installation tokens of the FirstFix GitHub App. Without it private scans fail permanently. */
  appTokens?: InstallationTokens | undefined;
  apiBase?: string;
  rawBase?: string;
  timeoutMs?: number;
  /** Files larger than this are refused (memory bound). */
  maxFileBytes?: number;
}

const SHA = /^[0-9a-f]{40}$/;

export class GitHubRepoSource implements RepoSource {
  private readonly token: string | undefined;
  private readonly appTokens: InstallationTokens | undefined;
  /** Current full name of each private repository by id, from the installation's own listing. */
  private readonly fullNames = new Map<number, string>();
  private readonly apiBase: string;
  private readonly rawBase: string;
  private readonly timeoutMs: number;
  private readonly maxFileBytes: number;

  constructor(options: GitHubOptions = {}) {
    this.token = options.token;
    this.appTokens = options.appTokens;
    this.apiBase = options.apiBase ?? 'https://api.github.com';
    this.rawBase = options.rawBase ?? 'https://raw.githubusercontent.com';
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.maxFileBytes = options.maxFileBytes ?? 50 * 1024 * 1024;
  }

  async resolveDefaultCommit(repo: Repo, access: RepoAccess, signal: AbortSignal): Promise<{ sha: string; branch: string }> {
    if (access.kind === 'installation') return this.resolvePrivate(access, signal);
    const path = `/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}`;

    const meta = await this.api(path, signal);
    const body = (await meta.json()) as { default_branch?: unknown; private?: unknown };
    if (body.private === true) {
      // A public scan never reads a private repository, also when it became private after submit.
      throw notFoundOrPrivate();
    }
    if (typeof body.default_branch !== 'string') {
      throw new TransientError('github_bad_response', 'GitHub returned repository data without a default branch');
    }
    const branch = body.default_branch;

    const commit = await this.api(`${path}/commits/${encodeURIComponent(branch)}`, signal, {
      // 409 "Git Repository is empty"
      409: () => new PermanentError('empty_repository', 'The repository is empty', 'unsupported'),
    });
    const sha = ((await commit.json()) as { sha?: unknown }).sha;
    if (typeof sha !== 'string' || !SHA.test(sha)) {
      throw new TransientError('github_bad_response', 'GitHub returned a commit without a valid SHA');
    }
    return { sha, branch };
  }

  async readFile(repo: Repo, access: RepoAccess, sha: string, path: string, signal: AbortSignal): Promise<string | null> {
    if (!SHA.test(sha)) throw new Error(`refusing to read a file at a non-SHA ref: ${sha}`);
    if (path.split('/').some((seg) => seg === '' || seg === '.' || seg === '..')) {
      throw new Error(`refusing to read an unnormalised path: ${path}`);
    }
    const filePath = path.split('/').map(encodeURIComponent).join('/');
    if (access.kind === 'installation') return this.readPrivate(access, sha, path, filePath, signal);

    // Public scans read files without any credentials: a repository that became private answers 404.
    const url = `${this.rawBase}/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/${sha}/${filePath}`;
    const res = await fetchWithTimeout(url, {
      headers: { 'user-agent': USER_AGENT },
      timeoutMs: this.timeoutMs,
      signal,
      service: 'github',
    });
    if (res.status === 404) return null;
    if (!res.ok) throw classify(res, 'raw');
    return this.readBody(res, path);
  }

  private async readBody(res: Response, path: string): Promise<string> {

    const declared = Number(res.headers.get('content-length') ?? 0);
    if (declared > this.maxFileBytes) {
      await res.body?.cancel();
      throw tooLarge(path, this.maxFileBytes);
    }
    const text = await readCapped(res, this.maxFileBytes, () => tooLarge(path, this.maxFileBytes));
    return text;
  }

  // --- private scans: the app's installation token, scoped to the recorded repository id ----------------

  private async resolvePrivate(access: Installation, signal: AbortSignal): Promise<{ sha: string; branch: string }> {
    const match = await this.accessibleRepository(access, signal);
    if (typeof match.full_name !== 'string' || typeof match.default_branch !== 'string') {
      throw new TransientError('github_bad_response', 'GitHub returned repository data without a name or default branch');
    }
    this.fullNames.set(access.repositoryId, match.full_name);
    const branch = match.default_branch;
    const commit = await this.privateApi(access, `/repos/${repoPath(match.full_name)}/commits/${encodeURIComponent(branch)}`, signal, {
      409: () => new PermanentError('empty_repository', 'The repository is empty', 'unsupported'),
    });
    if (!commit) throw revoked();
    const sha = ((await commit.json()) as { sha?: unknown }).sha;
    if (typeof sha !== 'string' || !SHA.test(sha)) {
      throw new TransientError('github_bad_response', 'GitHub returned a commit without a valid SHA');
    }
    return { sha, branch };
  }

  private async readPrivate(access: Installation, sha: string, path: string, filePath: string, signal: AbortSignal): Promise<string | null> {
    const fullName = this.fullNames.get(access.repositoryId);
    // resolveDefaultCommit runs first in every attempt; without it the name isn't known.
    if (fullName === undefined) throw new TransientError('github_state', 'Repository not resolved before reading; will retry');
    const res = await this.privateApi(
      access,
      `/repos/${repoPath(fullName)}/contents/${filePath}?ref=${sha}`,
      signal,
      { 404: () => null },
      'application/vnd.github.raw+json',
    );
    if (res === null) {
      // GitHub also answers 404 once access is gone. Only a repository we can still read has a missing file;
      // otherwise this is lost access, not "no supported lockfile".
      await this.accessibleRepository(access, signal);
      return null;
    }
    return this.readBody(res, path);
  }

  /**
   * The recorded repository as the scoped token's own listing shows it (it can only contain that repository:
   * identity by id, not by name). Permanent `app_access_revoked` when it is no longer there.
   */
  private async accessibleRepository(
    access: Installation,
    signal: AbortSignal,
  ): Promise<{ id?: unknown; full_name?: unknown; default_branch?: unknown }> {
    const listing = await this.privateApi(access, '/installation/repositories?per_page=100', signal);
    if (!listing) throw revoked();
    const body = (await listing.json()) as { repositories?: unknown };
    const repos = Array.isArray(body.repositories) ? (body.repositories as unknown[]) : [];
    const match = repos
      .map((r) => r as { id?: unknown; full_name?: unknown; default_branch?: unknown })
      .find((r) => r.id === access.repositoryId);
    if (!match) throw revoked();
    return match;
  }

  /** null only where a `special` handler maps a status to null (a missing file). */
  private async privateApi(
    access: Installation,
    path: string,
    signal: AbortSignal,
    special: Record<number, () => Error | null> = {},
    accept = 'application/vnd.github+json',
  ): Promise<Response | null> {
    if (!this.appTokens) {
      throw new PermanentError('github_app_not_configured', 'Private repositories need the FirstFix GitHub App, which is not configured on this server');
    }
    const token = await this.appTokens.token(access.installationId, access.repositoryId, signal);
    const res = await fetchWithTimeout(`${this.apiBase}${path}`, {
      headers: { accept, 'x-github-api-version': API_VERSION, 'user-agent': USER_AGENT, authorization: `Bearer ${token}` },
      timeoutMs: this.timeoutMs,
      signal,
      service: 'github',
    });
    if (res.ok) return res;
    const handler = special[res.status];
    if (handler) {
      const err = handler();
      if (err === null) return null;
      throw err;
    }
    if (res.status === 401) {
      // The cached token was revoked or expired early: retry with a fresh one (an uninstalled app then
      // fails permanently when minting).
      this.appTokens.invalidate(access.installationId, access.repositoryId);
      throw new TransientError('github_token_refresh', 'GitHub refused the installation token; retrying with a new one');
    }
    if (res.status === 404) throw revoked();
    throw transientOrPermanent(res, 'private repository');
  }

  private async api(
    path: string,
    signal: AbortSignal,
    special: Record<number, () => Error> = {},
  ): Promise<Response> {
    const res = await fetchWithTimeout(`${this.apiBase}${path}`, {
      headers: {
        accept: 'application/vnd.github+json',
        'x-github-api-version': API_VERSION,
        'user-agent': USER_AGENT,
        ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),
      },
      timeoutMs: this.timeoutMs,
      signal,
      service: 'github',
    });
    if (res.ok) return res;
    const handler = special[res.status];
    if (handler) throw handler();
    throw classify(res, 'api');
  }
}

function notFoundOrPrivate(): PermanentError {
  return new PermanentError(
    'repo_not_found',
    'Repository not found or private. To scan a private repository, sign in with GitHub and choose it from your repositories.',
  );
}

function tooLarge(path: string, max: number): PermanentError {
  return new PermanentError('lockfile_too_large', `${path} is larger than ${max / 1024 / 1024} MB`, 'unsupported');
}

function classify(res: Response, kind: 'api' | 'raw'): Error {
  const rateLimited =
    res.status === 429 || (res.status === 403 && (res.headers.get('x-ratelimit-remaining') === '0' || res.headers.has('retry-after')));
  if (rateLimited) {
    return new TransientError('github_rate_limited', 'GitHub rate limit reached; the scan will be retried. Setting GITHUB_TOKEN raises the limit.');
  }
  if (res.status === 404 && kind === 'api') return notFoundOrPrivate();
  if (res.status === 401) {
    return new PermanentError('github_auth', 'GitHub rejected the configured GITHUB_TOKEN');
  }
  if (res.status >= 500) return new TransientError('github_unavailable', `GitHub answered ${res.status}`);
  return new PermanentError('github_error', `GitHub answered ${res.status}`);
}

/**
 * Reads the body as it streams, stopping as soon as it passes `max` bytes: a missing or wrong content-length
 * can't make the worker buffer an arbitrarily large file.
 */
async function readCapped(res: Response, max: number, tooBig: () => Error): Promise<string> {
  if (!res.body) return '';
  const reader = (res.body as ReadableStream<Uint8Array>).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw tooBig();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function repoPath(fullName: string): string {
  return fullName.split('/').map(encodeURIComponent).join('/');
}
