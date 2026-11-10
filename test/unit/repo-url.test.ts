import { describe, expect, it } from 'vitest';
import { parseRepoUrl } from '../../src/domain/repo-url.ts';

describe('parseRepoUrl', () => {
  it.each([
    ['https://github.com/Owner/Repo', 'owner', 'repo'],
    ['https://github.com/owner/repo/', 'owner', 'repo'],
    ['https://github.com/owner/repo.git', 'owner', 'repo'],
    ['https://www.github.com/owner/repo', 'owner', 'repo'],
    ['http://github.com/owner/repo', 'owner', 'repo'],
    ['github.com/owner/repo', 'owner', 'repo'],
    ['  https://GitHub.com/OWNER/my.repo_name-2  ', 'owner', 'my.repo_name-2'],
  ])('normalizes %s', (input, owner, name) => {
    expect(parseRepoUrl(input)).toEqual({
      ok: true,
      repo: { owner, name, url: `https://github.com/${owner}/${name}` },
    });
  });

  it('gives the same canonical URL for equivalent inputs (idempotency relies on it)', () => {
    const urls = ['https://github.com/A/B', 'github.com/a/b.git', 'https://www.github.com/a/b/'].map((u) => {
      const r = parseRepoUrl(u);
      return r.ok ? r.repo.url : r.error;
    });
    expect(new Set(urls)).toEqual(new Set(['https://github.com/a/b']));
  });

  it.each([
    ['', /Enter a GitHub repository URL/],
    ['not a url at all', /not a valid URL|github.com/],
    ['https://gitlab.com/owner/repo', /Only public repositories on github.com/],
    ['https://github.com/owner', /both owner and repository/],
    ['https://github.com/owner/repo/tree/main', /not a branch, folder or file/],
    ['https://github.com/owner/repo?tab=readme', /query string/],
    ['https://github.com/owner/repo#readme', /fragment/],
    ['ftp://github.com/owner/repo', /https:\/\/github.com/],
    ['https://user:pw@github.com/owner/repo', /plain/],
    ['https://github.com/-bad/repo', /not a valid GitHub owner/],
    ['https://github.com/owner/..', /both owner and repository|not a valid GitHub repository/],
    ['git@github.com:owner/repo.git', /.+/],
  ])('rejects %j', (input, message) => {
    const r = parseRepoUrl(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(message);
  });
});
