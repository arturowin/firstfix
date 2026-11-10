import { delay, http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { GitHubRepoSource } from '../../src/adapters/github/repo-source.ts';
import { PermanentError, TransientError } from '../../src/ports/errors.ts';

const API = 'https://api.github.com';
const RAW = 'https://raw.githubusercontent.com';
const SHA = 'a'.repeat(40);
const repo = { owner: 'owner', name: 'repo' };
const signal = () => new AbortController().signal;

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

function happyPath(seen: { auth: (string | null)[]; paths: string[] }) {
  server.use(
    http.get(`${API}/repos/owner/repo`, ({ request }) => {
      seen.auth.push(request.headers.get('authorization'));
      seen.paths.push(new URL(request.url).pathname);
      return HttpResponse.json({ default_branch: 'main', private: false });
    }),
    http.get(`${API}/repos/owner/repo/commits/:ref`, ({ request, params }) => {
      seen.paths.push(new URL(request.url).pathname);
      return params['ref'] === 'main' ? HttpResponse.json({ sha: SHA }) : new HttpResponse(null, { status: 404 });
    }),
    http.get(`${RAW}/owner/repo/:sha/package-lock.json`, ({ request, params }) => {
      seen.paths.push(new URL(request.url).pathname);
      return params['sha'] === SHA ? HttpResponse.text('{"lockfileVersion":3}') : new HttpResponse(null, { status: 404 });
    }),
  );
}

describe('GitHubRepoSource', () => {
  it('resolves the default branch to a SHA and reads the lockfile at exactly that SHA', async () => {
    const seen = { auth: [] as (string | null)[], paths: [] as string[] };
    happyPath(seen);
    const gh = new GitHubRepoSource();
    const commit = await gh.resolveDefaultCommit(repo, signal());
    expect(commit).toEqual({ sha: SHA, branch: 'main' });
    expect(await gh.readFile(repo, commit.sha, 'package-lock.json', signal())).toBe('{"lockfileVersion":3}');
    expect(seen.paths).toEqual([
      '/repos/owner/repo',
      '/repos/owner/repo/commits/main',
      `/owner/repo/${SHA}/package-lock.json`,
    ]);
    expect(seen.auth).toEqual([null]); // no token configured → no auth header
  });

  it('sends the token when configured', async () => {
    const seen = { auth: [] as (string | null)[], paths: [] as string[] };
    happyPath(seen);
    await new GitHubRepoSource({ token: 't0k' }).resolveDefaultCommit(repo, signal());
    expect(seen.auth).toEqual(['Bearer t0k']);
  });

  it('refuses to read at anything but a SHA (pinned-commit rule)', async () => {
    await expect(new GitHubRepoSource().readFile(repo, 'main', 'package-lock.json', signal())).rejects.toThrow(/non-SHA/);
  });

  it.each(['../secrets', 'a//b', '/abs', './x'])('refuses an unnormalised path: %s', async (p) => {
    await expect(new GitHubRepoSource().readFile(repo, SHA, p, signal())).rejects.toThrow(/unnormalised/);
  });

  it('reads any root-relative path at the SHA, encoding each segment', async () => {
    const seen: string[] = [];
    server.use(
      http.get(`${RAW}/owner/repo/:sha/*`, ({ request }) => {
        seen.push(new URL(request.url).pathname);
        return HttpResponse.text('ok');
      }),
    );
    expect(await new GitHubRepoSource().readFile(repo, SHA, 'sub dir/poetry.lock', signal())).toBe('ok');
    expect(seen).toEqual([`/owner/repo/${SHA}/sub%20dir/poetry.lock`]);
  });

  it('no such file at that SHA → null', async () => {
    server.use(http.get(`${RAW}/owner/repo/:sha/package-lock.json`, () => new HttpResponse(null, { status: 404 })));
    expect(await new GitHubRepoSource().readFile(repo, SHA, 'package-lock.json', signal())).toBeNull();
  });

  it.each([
    ['404', () => new HttpResponse(null, { status: 404 }), 'repo_not_found', 'failed'],
    ['private repo (visible with a token)', () => HttpResponse.json({ default_branch: 'main', private: true }), 'repo_not_found', 'failed'],
    ['401 bad token', () => new HttpResponse(null, { status: 401 }), 'github_auth', 'failed'],
    ['403 without rate-limit headers', () => new HttpResponse(null, { status: 403 }), 'github_error', 'failed'],
  ])('permanent: %s', async (_label, respond, code, outcome) => {
    server.use(http.get(`${API}/repos/owner/repo`, respond));
    const err: unknown = await new GitHubRepoSource().resolveDefaultCommit(repo, signal()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PermanentError);
    expect(err).toMatchObject({ code, outcome });
  });

  it('empty repository → permanent, scan becomes unsupported', async () => {
    server.use(
      http.get(`${API}/repos/owner/repo`, () => HttpResponse.json({ default_branch: 'main' })),
      http.get(`${API}/repos/owner/repo/commits/main`, () =>
        HttpResponse.json({ message: 'Git Repository is empty.' }, { status: 409 }),
      ),
    );
    await expect(new GitHubRepoSource().resolveDefaultCommit(repo, signal())).rejects.toMatchObject({
      code: 'empty_repository',
      outcome: 'unsupported',
    });
  });

  it.each([
    ['403 + x-ratelimit-remaining: 0', () => new HttpResponse(null, { status: 403, headers: { 'x-ratelimit-remaining': '0' } }), 'github_rate_limited'],
    ['403 + retry-after', () => new HttpResponse(null, { status: 403, headers: { 'retry-after': '60' } }), 'github_rate_limited'],
    ['429', () => new HttpResponse(null, { status: 429 }), 'github_rate_limited'],
    ['502', () => new HttpResponse(null, { status: 502 }), 'github_unavailable'],
    ['network error', () => HttpResponse.error(), 'github_unreachable'],
  ])('transient: %s', async (_label, respond, code) => {
    server.use(http.get(`${API}/repos/owner/repo`, respond));
    const err: unknown = await new GitHubRepoSource().resolveDefaultCommit(repo, signal()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TransientError);
    expect(err).toMatchObject({ code });
  });

  it('a slow answer times out as transient', async () => {
    server.use(
      http.get(`${API}/repos/owner/repo`, async () => {
        await delay(500);
        return HttpResponse.json({ default_branch: 'main' });
      }),
    );
    await expect(new GitHubRepoSource({ timeoutMs: 50 }).resolveDefaultCommit(repo, signal())).rejects.toMatchObject({
      code: 'github_timeout',
    });
  });

  it('when the job itself is aborted, the abort propagates as-is (not a retryable error)', async () => {
    server.use(
      http.get(`${API}/repos/owner/repo`, async () => {
        await delay(500);
        return HttpResponse.json({ default_branch: 'main' });
      }),
    );
    const job = new AbortController();
    const pending = new GitHubRepoSource().resolveDefaultCommit(repo, job.signal);
    job.abort(new Error('claim lost'));
    const err: unknown = await pending.catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(TransientError);
    expect(err).not.toBeInstanceOf(PermanentError);
  });

  it('refuses lockfiles over the size limit (unsupported)', async () => {
    server.use(http.get(`${RAW}/owner/repo/:sha/package-lock.json`, () => HttpResponse.text('x'.repeat(2048))));
    await expect(
      new GitHubRepoSource({ maxFileBytes: 1024 }).readFile(repo, SHA, 'package-lock.json', signal()),
    ).rejects.toMatchObject({
      code: 'lockfile_too_large',
      message: expect.stringMatching(/^package-lock.json is larger than/) as string,
      outcome: 'unsupported',
    });
  });
});
