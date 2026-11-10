import { PermanentError, TransientError } from '../../ports/errors.ts';
import type { RepoSource } from '../../ports/repo-source.ts';
import { fetchWithTimeout, USER_AGENT } from '../http.ts';

export interface GitHubOptions {
  /** Optional; without it GitHub allows 60 API requests/hour/IP. */
  token?: string | undefined;
  apiBase?: string;
  rawBase?: string;
  timeoutMs?: number;
  /** Files larger than this are refused (memory bound). */
  maxFileBytes?: number;
}

const SHA = /^[0-9a-f]{40}$/;

export class GitHubRepoSource implements RepoSource {
  private readonly token: string | undefined;
  private readonly apiBase: string;
  private readonly rawBase: string;
  private readonly timeoutMs: number;
  private readonly maxFileBytes: number;

  constructor(options: GitHubOptions = {}) {
    this.token = options.token;
    this.apiBase = options.apiBase ?? 'https://api.github.com';
    this.rawBase = options.rawBase ?? 'https://raw.githubusercontent.com';
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.maxFileBytes = options.maxFileBytes ?? 50 * 1024 * 1024;
  }

  async resolveDefaultCommit(
    repo: { owner: string; name: string },
    signal: AbortSignal,
  ): Promise<{ sha: string; branch: string }> {
    const path = `/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}`;

    const meta = await this.api(path, signal);
    const body = (await meta.json()) as { default_branch?: unknown; private?: unknown };
    if (body.private === true) {
      // Only reachable with a token that can see private repos; this product scans public repos only.
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

  async readFile(
    repo: { owner: string; name: string },
    sha: string,
    path: string,
    signal: AbortSignal,
  ): Promise<string | null> {
    if (!SHA.test(sha)) throw new Error(`refusing to read a file at a non-SHA ref: ${sha}`);
    if (path.split('/').some((seg) => seg === '' || seg === '.' || seg === '..')) {
      throw new Error(`refusing to read an unnormalised path: ${path}`);
    }
    const filePath = path.split('/').map(encodeURIComponent).join('/');
    const url = `${this.rawBase}/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/${sha}/${filePath}`;
    const res = await fetchWithTimeout(url, {
      headers: { 'user-agent': USER_AGENT, ...(this.token ? { authorization: `Bearer ${this.token}` } : {}) },
      timeoutMs: this.timeoutMs,
      signal,
      service: 'github',
    });
    if (res.status === 404) return null;
    if (!res.ok) throw classify(res, 'raw');

    const declared = Number(res.headers.get('content-length') ?? 0);
    if (declared > this.maxFileBytes) {
      await res.body?.cancel();
      throw tooLarge(path, this.maxFileBytes);
    }
    const text = await readCapped(res, this.maxFileBytes, () => tooLarge(path, this.maxFileBytes));
    return text;
  }

  private async api(
    path: string,
    signal: AbortSignal,
    special: Record<number, () => Error> = {},
  ): Promise<Response> {
    const res = await fetchWithTimeout(`${this.apiBase}${path}`, {
      headers: {
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
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
    'Repository not found or private. Only public GitHub repositories can be scanned.',
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
