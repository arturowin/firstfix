/**
 * Mocked GitHub (msw) for source acquisition: tree listing and file reads, pinned to the commit, with the
 * public/private credential rules. Shapes follow GitHub's docs and a live check against the public demo
 * repository (commit.tree.sha; recursive tree entries with mode/type/size and `truncated`).
 */
import { generateKeyPairSync } from 'node:crypto';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { GitHubAppTokens } from '../../src/adapters/github/app-tokens.ts';
import { GitHubRepoSource } from '../../src/adapters/github/repo-source.ts';
import { PermanentError } from '../../src/ports/errors.ts';
import type { RepoAccess } from '../../src/ports/repo-source.ts';

const API = 'https://api.github.com';
const RAW = 'https://raw.githubusercontent.com';
const SHA = 'c'.repeat(40);
const TREE = 'e'.repeat(40);
const PUBLIC: RepoAccess = { kind: 'public' };
const PRIVATE: RepoAccess = { kind: 'installation', installationId: 7, repositoryId: 42 };
const repo = { owner: 'acme', name: 'app' };
const signal = () => new AbortController().signal;
const PEM = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

const seen: { url: string; auth: string | null; accept: string | null }[] = [];
const server = setupServer();
server.events.on('request:start', ({ request }) => {
  seen.push({ url: request.url, auth: request.headers.get('authorization'), accept: request.headers.get('accept') });
});
beforeAll(() => {
  server.listen({ onUnhandledFrame: 'error' });
});
afterEach(() => {
  server.resetHandlers();
  seen.length = 0;
});
afterAll(() => {
  server.close();
});

const treeBody = {
  tree: [
    { path: 'src', mode: '040000', type: 'tree', sha: 'd1' },
    { path: 'src/a.ts', mode: '100644', type: 'blob', size: 120, sha: 'b1' },
    { path: 'src/link.js', mode: '120000', type: 'blob', size: 8, sha: 'b2' },
    { path: 'vendored', mode: '160000', type: 'commit', sha: 'c1' },
    { path: 'odd', type: 'blob' }, // malformed: dropped
  ],
  truncated: true,
};

function privateRepo() {
  server.use(
    http.post(`${API}/app/installations/7/access_tokens`, () =>
      HttpResponse.json({ token: 'ghs_scoped', expires_at: new Date(Date.now() + 3_600_000).toISOString() }, { status: 201 }),
    ),
    http.get(`${API}/installation/repositories`, () => HttpResponse.json({ repositories: [{ id: 42, full_name: 'Acme/App', default_branch: 'main' }] })),
    http.get(`${API}/repos/Acme/App/commits/main`, () => HttpResponse.json({ sha: SHA, commit: { tree: { sha: TREE } } })),
    http.get(`${API}/repos/Acme/App/git/trees/${TREE}`, ({ request }) =>
      new URL(request.url).searchParams.get('recursive') === '1' ? HttpResponse.json(treeBody) : new HttpResponse(null, { status: 400 }),
    ),
    http.get(`${API}/repos/Acme/App/contents/src/a.ts`, ({ request }) =>
      new URL(request.url).searchParams.get('ref') === SHA ? HttpResponse.text('const a = 1;') : new HttpResponse(null, { status: 404 }),
    ),
  );
}

describe('source acquisition, public repositories', () => {
  it('lists the tree by its SHA (recursive) and keeps type, mode, size and truncation', async () => {
    server.use(http.get(`${API}/repos/acme/app/git/trees/${TREE}`, () => HttpResponse.json(treeBody)));
    const listing = await new GitHubRepoSource().listTree(repo, PUBLIC, TREE, signal());
    expect(listing.truncated).toBe(true);
    expect(listing.entries).toEqual([
      { path: 'src', type: 'tree', mode: '040000', size: null, sha: 'd1' },
      { path: 'src/a.ts', type: 'blob', mode: '100644', size: 120, sha: 'b1' },
      { path: 'src/link.js', type: 'blob', mode: '120000', size: 8, sha: 'b2' },
      { path: 'vendored', type: 'commit', mode: '160000', size: null, sha: 'c1' },
    ]);
    expect(new URL(seen[0]?.url ?? '').search).toBe('?recursive=1');
  });

  it('reads source files at the commit SHA without any credentials, even with a public token configured', async () => {
    server.use(http.get(`${RAW}/acme/app/${SHA}/src/a.ts`, () => HttpResponse.text('let x = 1;')));
    const gh = new GitHubRepoSource({ token: 'github_pat_public_only' });
    expect(await gh.readSourceFile(repo, PUBLIC, SHA, 'src/a.ts', 1000, signal())).toBe('let x = 1;');
    expect(seen.map((r) => ({ url: r.url, auth: r.auth }))).toEqual([{ url: `${RAW}/acme/app/${SHA}/src/a.ts`, auth: null }]);
  });

  it('a file over the limit is source_file_too_large (counted as skipped, not a failure)', async () => {
    server.use(http.get(`${RAW}/acme/app/${SHA}/big.js`, () => HttpResponse.text('x'.repeat(2000))));
    const err = await new GitHubRepoSource().readSourceFile(repo, PUBLIC, SHA, 'big.js', 1000, signal()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PermanentError);
    expect((err as PermanentError).code).toBe('source_file_too_large');
  });

  it('refuses anything not pinned to a SHA, and unnormalised paths', async () => {
    const gh = new GitHubRepoSource();
    await expect(gh.listTree(repo, PUBLIC, 'main', signal())).rejects.toThrow(/non-SHA/);
    await expect(gh.readSourceFile(repo, PUBLIC, 'main', 'a.ts', 10, signal())).rejects.toThrow(/non-SHA/);
    await expect(gh.readSourceFile(repo, PUBLIC, SHA, '../x.ts', 10, signal())).rejects.toThrow(/unnormalised/);
  });
});

describe('source acquisition, private repositories', () => {
  const source = () => new GitHubRepoSource({ token: 'github_pat_public_only', appTokens: new GitHubAppTokens({ clientId: 'c', privateKey: PEM }) });

  it('uses only the scoped installation token, by the repository id’s current name, at the commit SHA', async () => {
    privateRepo();
    const gh = source();
    const { sha, treeSha } = await gh.resolveDefaultCommit(repo, PRIVATE, signal());
    expect(treeSha).toBe(TREE);
    expect((await gh.listTree(repo, PRIVATE, treeSha, signal())).entries).toHaveLength(4);
    expect(await gh.readSourceFile(repo, PRIVATE, sha, 'src/a.ts', 1000, signal())).toBe('const a = 1;');
    const reads = seen.filter((r) => !r.url.includes('/access_tokens'));
    expect(reads.every((r) => r.auth === 'Bearer ghs_scoped')).toBe(true);
    expect(reads.at(-1)).toMatchObject({ url: `${API}/repos/Acme/App/contents/src/a.ts?ref=${SHA}`, accept: 'application/vnd.github.raw+json' });
    expect(seen.some((r) => r.url.startsWith(RAW))).toBe(false);
  });

  it('a 404 while access holds is a missing file; after access was removed it is app_access_revoked', async () => {
    privateRepo();
    const gh = source();
    const { sha } = await gh.resolveDefaultCommit(repo, PRIVATE, signal());
    server.use(http.get(`${API}/repos/Acme/App/contents/src/gone.ts`, () => new HttpResponse(null, { status: 404 })));
    expect(await gh.readSourceFile(repo, PRIVATE, sha, 'src/gone.ts', 1000, signal())).toBeNull();
    server.use(http.get(`${API}/installation/repositories`, () => HttpResponse.json({ repositories: [] })));
    const err = await gh.readSourceFile(repo, PRIVATE, sha, 'src/gone.ts', 1000, signal()).catch((e: unknown) => e);
    expect((err as PermanentError).code).toBe('app_access_revoked');
  });

  it('a tree listing that 404s means access was lost', async () => {
    privateRepo();
    const gh = source();
    await gh.resolveDefaultCommit(repo, PRIVATE, signal());
    server.use(http.get(`${API}/repos/Acme/App/git/trees/${TREE}`, () => new HttpResponse(null, { status: 404 })));
    const err = await gh.listTree(repo, PRIVATE, TREE, signal()).catch((e: unknown) => e);
    expect((err as PermanentError).code).toBe('app_access_revoked');
  });
});
