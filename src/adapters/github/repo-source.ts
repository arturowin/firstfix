import type { TreeEntry } from '../../domain/source-files.ts';
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

  async resolveDefaultCommit(repo: Repo, access: RepoAccess, signal: AbortSignal): Promise<{ sha: string; branch: string; treeSha: string }> {
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
    return { ...parseCommit(await commit.json()), branch };
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
    return this.readBody(res, this.maxFileBytes, () => tooLarge(path, this.maxFileBytes));
  }

  async listTree(repo: Repo, access: RepoAccess, treeSha: string, signal: AbortSignal): Promise<{ entries: TreeEntry[]; truncated: boolean }> {
    if (!SHA.test(treeSha)) throw new Error(`refusing to list a non-SHA tree: ${treeSha}`);
    const res =
      access.kind === 'installation'
        ? await this.privateApi(access, `/repos/${repoPath(this.resolvedName(access))}/git/trees/${treeSha}?recursive=1`, signal)
        : await this.api(`/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/git/trees/${treeSha}?recursive=1`, signal);
    if (!res) throw revoked();
    return parseTree(await res.json());
  }

  async readSourceFile(
    repo: Repo,
    access: RepoAccess,
    commitSha: string,
    path: string,
    maxBytes: number,
    signal: AbortSignal,
  ): Promise<string | null> {
    if (!SHA.test(commitSha)) throw new Error(`refusing to read a file at a non-SHA ref: ${commitSha}`);
    if (path.split('/').some((seg) => seg === '' || seg === '.' || seg === '..')) {
      throw new Error(`refusing to read an unnormalised path: ${path}`);
    }
    const filePath = path.split('/').map(encodeURIComponent).join('/');
    const oversize = () => new PermanentError('source_file_too_large', `${path} is larger than ${String(maxBytes)} bytes`, 'unsupported');
    if (access.kind === 'installation') {
      const res = await this.privateApi(
        access,
        `/repos/${repoPath(this.resolvedName(access))}/contents/${filePath}?ref=${commitSha}`,
        signal,
        { 404: () => null },
        'application/vnd.github.raw+json',
      );
      if (res === null) {
        await this.accessibleRepository(access, signal); // lost access is not a missing file
        return null;
      }
      return this.readBody(res, maxBytes, oversize);
    }
    // Public scans read source without any credentials, exactly like lockfiles.
    const url = `${this.rawBase}/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/${commitSha}/${filePath}`;
    const res = await fetchWithTimeout(url, { headers: { 'user-agent': USER_AGENT }, timeoutMs: this.timeoutMs, signal, service: 'github' });
    if (res.status === 404) return null;
    if (!res.ok) throw classify(res, 'raw');
    return this.readBody(res, maxBytes, oversize);
  }

  private async readBody(res: Response, max: number, tooBig: () => Error): Promise<string> {
    const declared = Number(res.headers.get('content-length') ?? 0);
    if (declared > max) {
      await res.body?.cancel();
      throw tooBig();
    }
    return readCapped(res, max, tooBig);
  }

  /** The private repository's current name, learned from its id by resolveDefaultCommit in this attempt. */
  private resolvedName(access: Installation): string {
    const fullName = this.fullNames.get(access.repositoryId);
    if (fullName === undefined) throw new TransientError('github_state', 'Repository not resolved before reading; will retry');
    return fullName;
  }

  // --- private scans: the app's installation token, scoped to the recorded repository id ----------------

  private async resolvePrivate(access: Installation, signal: AbortSignal): Promise<{ sha: string; branch: string; treeSha: string }> {
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
    return { ...parseCommit(await commit.json()), branch };
  }

  private async readPrivate(access: Installation, sha: string, path: string, filePath: string, signal: AbortSignal): Promise<string | null> {
    const res = await this.privateApi(
      access,
      `/repos/${repoPath(this.resolvedName(access))}/contents/${filePath}?ref=${sha}`,
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
    return this.readBody(res, this.maxFileBytes, () => tooLarge(path, this.maxFileBytes));
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

/** A commit's SHA and its root tree's SHA (the trees API is documented for tree SHAs). */
function parseCommit(body: unknown): { sha: string; treeSha: string } {
  const c = body as { sha?: unknown; commit?: { tree?: { sha?: unknown } } };
  const sha = c.sha;
  const treeSha = c.commit?.tree?.sha;
  if (typeof sha !== 'string' || !SHA.test(sha) || typeof treeSha !== 'string' || !SHA.test(treeSha)) {
    throw new TransientError('github_bad_response', 'GitHub returned a commit without a valid SHA or tree');
  }
  return { sha, treeSha };
}

/** Entries of a recursive tree listing; malformed entries are dropped, never trusted. */
function parseTree(body: unknown): { entries: TreeEntry[]; truncated: boolean } {
  const t = body as { tree?: unknown; truncated?: unknown };
  if (!Array.isArray(t.tree)) throw new TransientError('github_bad_response', 'GitHub returned a tree without entries');
  const entries: TreeEntry[] = [];
  for (const raw of t.tree as unknown[]) {
    const e = raw as { path?: unknown; type?: unknown; mode?: unknown; size?: unknown; sha?: unknown };
    if (typeof e.path !== 'string' || typeof e.type !== 'string' || typeof e.mode !== 'string' || typeof e.sha !== 'string') continue;
    entries.push({ path: e.path, type: e.type, mode: e.mode, size: typeof e.size === 'number' ? e.size : null, sha: e.sha });
  }
  return { entries, truncated: t.truncated === true };
}
