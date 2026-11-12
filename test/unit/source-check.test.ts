import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { DEFAULT_SOURCE_CHECK, runSourceCheck, type SourceCheckOptions } from '../../src/application/source-check.ts';
import type { TreeEntry } from '../../src/domain/source-files.ts';
import { PermanentError, TransientError } from '../../src/ports/errors.ts';
import type { RepoSource } from '../../src/ports/repo-source.ts';

const FIXTURES = path.join(import.meta.dirname, '..', 'fixtures', 'source');
const fixture = (name: string) => readFileSync(path.join(FIXTURES, name), 'utf8');
const SHA = 'a'.repeat(40);
const input = { repo: { owner: 'o', name: 'r' }, access: { kind: 'public' } as const, commitSha: SHA, treeSha: 'e'.repeat(40) };
const signal = () => new AbortController().signal;
const blob = (p: string, size = 100): TreeEntry => ({ path: p, type: 'blob', mode: '100644', size, sha: `s-${p}` });

/** A repository whose files are read from `files` (missing → null); `fail` decides per path. */
function repoSource(
  entries: TreeEntry[],
  files: Record<string, string>,
  fail: (p: string) => Error | 'hang' | null = () => null,
  truncated = false,
): RepoSource & { reads: string[] } {
  const reads: string[] = [];
  return {
    reads,
    resolveDefaultCommit: () => Promise.reject(new Error('not used')),
    readFile: () => Promise.reject(new Error('not used')),
    listTree: () => Promise.resolve({ entries, truncated }),
    readSourceFile: (_r, _a, sha, p, _max, s) => {
      reads.push(`${sha}:${p}`);
      const f = fail(p);
      const reason = () => (s.reason instanceof Error ? s.reason : new Error('aborted'));
      if (s.aborted) return Promise.reject(reason()); // like fetch with an already-aborted signal
      if (f === 'hang') {
        return new Promise((_ok, reject) => {
          s.addEventListener('abort', () => {
            reject(reason());
          });
        });
      }
      if (f) return Promise.reject(f);
      return Promise.resolve(files[p] ?? null);
    },
  };
}

const options = (o: Partial<SourceCheckOptions> = {}): SourceCheckOptions => ({ ...DEFAULT_SOURCE_CHECK, ...o });

describe('runSourceCheck', () => {
  it('checks the fixture repository: three findings in the flagged file, none in the safe one', async () => {
    const src = repoSource([blob('src/flagged.ts'), blob('src/safe.ts'), blob('README.md')], {
      'src/flagged.ts': fixture('flagged.ts'),
      'src/safe.ts': fixture('safe.ts'),
    });
    const { check, findings } = await runSourceCheck(src, input, options(), signal());
    expect(check).toMatchObject({ status: 'complete', counts: { eligible: 2, checked: 2 } });
    expect(findings.map((f) => [f.ruleId, f.severity, f.path, f.start.line])).toEqual([
      ['FF-TLS-001', 'high', 'src/flagged.ts', 5],
      ['FF-TLS-002', 'medium', 'src/flagged.ts', 9],
      ['FF-TLS-002', 'medium', 'src/flagged.ts', 13],
    ]);
    // Every read is pinned to the commit.
    expect(src.reads.every((r) => r.startsWith(`${SHA}:`))).toBe(true);
  });

  it('no eligible files → no_files', async () => {
    expect((await runSourceCheck(repoSource([blob('README.md')], {}), input, options(), signal())).check.status).toBe('no_files');
  });

  it('files left out by the limits make coverage partial, with counts', async () => {
    const entries = [blob('a.ts'), blob('b.ts'), blob('c.ts', 10_000_000)];
    const { check } = await runSourceCheck(
      repoSource(entries, { 'a.ts': 'x', 'b.ts': 'y' }),
      input,
      options({ limits: { maxFiles: 1, maxFileBytes: 1000, maxTotalBytes: 10_000 } }),
      signal(),
    );
    expect(check).toMatchObject({ status: 'partial', counts: { eligible: 3, checked: 1, skippedLimit: 1, skippedSize: 1 } });
  });

  it('a file that fails to fetch is counted; the rest still count (partial)', async () => {
    const src = repoSource([blob('a.ts'), blob('b.ts')], { 'a.ts': '{ rejectUnauthorized: false }' }, (p) =>
      p === 'b.ts' ? new TransientError('github_unavailable', 'GitHub answered 502') : null,
    );
    const { check, findings } = await runSourceCheck(src, input, options(), signal());
    expect(check).toMatchObject({ status: 'partial', counts: { checked: 1, fetchFailed: 1 } });
    expect(findings).toHaveLength(1);
  });

  it('nothing fetchable at all is transient (the job is retried)', async () => {
    const src = repoSource([blob('a.ts'), blob('b.ts')], {}, () => new TransientError('github_unavailable', 'GitHub answered 502'));
    await expect(runSourceCheck(src, input, options(), signal())).rejects.toMatchObject({ code: 'source_fetch_failed' });
  });

  it('a file over the per-file limit while reading is counted as skipped by size', async () => {
    const src = repoSource([blob('a.ts'), blob('b.ts')], { 'a.ts': 'x' }, (p) =>
      p === 'b.ts' ? new PermanentError('source_file_too_large', 'too big', 'unsupported') : null,
    );
    expect((await runSourceCheck(src, input, options(), signal())).check.counts).toMatchObject({ checked: 1, skippedSize: 1 });
  });

  it('lost access is a shared failure: it propagates unchanged', async () => {
    const revoked = new PermanentError('app_access_revoked', 'FirstFix no longer has access to this repository.');
    const src = repoSource([blob('a.ts'), blob('b.ts')], { 'a.ts': 'x' }, (p) => (p === 'b.ts' ? revoked : null));
    await expect(runSourceCheck(src, input, options(), signal())).rejects.toBe(revoked);
  });

  it('the time budget ends the check: files not reached are counted, the rest kept', async () => {
    const src = repoSource([blob('a.ts'), blob('b.ts'), blob('c.ts')], { 'a.ts': '{ rejectUnauthorized: false }' }, (p) => (p === 'a.ts' ? null : 'hang'));
    const { check, findings } = await runSourceCheck(src, input, options({ concurrency: 1, budgetMs: 100 }), signal());
    expect(check).toMatchObject({ status: 'partial', counts: { checked: 1, skippedTime: 2 } });
    expect(findings).toHaveLength(1);
  });

  it('a cancelled job propagates its cancellation', async () => {
    const job = new AbortController();
    const src = repoSource([blob('a.ts')], {}, () => 'hang');
    const running = runSourceCheck(src, input, options(), job.signal);
    job.abort(new Error('job cancelled'));
    await expect(running).rejects.toThrow(/job cancelled/);
  });

  it('a high-severity match after many medium ones is kept, and every match is still counted', async () => {
    const file = `${Array.from({ length: 50 }, () => '{ rejectUnauthorized: false }').join('\n')}\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';`;
    const { check, findings } = await runSourceCheck(repoSource([blob('a.ts')], { 'a.ts': file }), input, options({ maxFindings: 10 }), signal());
    expect(findings).toHaveLength(10);
    expect(findings[0]).toMatchObject({ ruleId: 'FF-TLS-001', severity: 'high', start: { line: 51 } });
    expect(check.counts.rules).toEqual({
      'FF-TLS-002': { matches: 50, files: 1, inTestFiles: 0 },
      'FF-TLS-001': { matches: 1, files: 1, inTestFiles: 0 },
    });
    expect(check).toMatchObject({ status: 'complete', counts: { findingsTruncated: true } });
  });

  it('which examples are kept doesn’t depend on fetch order: severity, then non-test code, then path', async () => {
    const files = { 'a/test/x.ts': '{ rejectUnauthorized: false }', 'b/y.ts': '{ rejectUnauthorized: false }', 'z.ts': "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'" };
    const entries = Object.keys(files).map((p) => blob(p));
    for (const order of [['a/test/x.ts', 'b/y.ts', 'z.ts'], ['z.ts', 'b/y.ts', 'a/test/x.ts']]) {
      // Each file answers after a delay that makes them complete in `order`.
      const src = repoSource(entries, files);
      const read = src.readSourceFile.bind(src);
      src.readSourceFile = async (...args) => {
        await new Promise((r) => setTimeout(r, 10 * order.indexOf(args[3])));
        return read(...args);
      };
      const { findings } = await runSourceCheck(src, input, options({ maxFindings: 2 }), signal());
      expect(findings.map((f) => f.path)).toEqual(['z.ts', 'b/y.ts']);
    }
  });

  it('a file that can’t be read as code is counted as not checked (partial); the rest are checked', async () => {
    const deep = `${'`${'.repeat(3000)}\`${'}`'.repeat(3000)}`;
    const src = repoSource([blob('deep.ts'), blob('ok.ts')], { 'deep.ts': deep, 'ok.ts': '{ rejectUnauthorized: false }' });
    const { check, findings } = await runSourceCheck(src, input, options(), signal());
    expect(check).toMatchObject({ status: 'partial', counts: { checked: 1, skippedParse: 1 } });
    expect(findings).toHaveLength(1);
  });

  it('every file unreadable as code is a partial result with nothing checked, not a retry', async () => {
    const deep = `${'`${'.repeat(3000)}\`${'}`'.repeat(3000)}`;
    const { check } = await runSourceCheck(repoSource([blob('deep.ts')], { 'deep.ts': deep }), input, options(), signal());
    expect(check).toMatchObject({ status: 'partial', counts: { checked: 0, skippedParse: 1 } });
  });

  it('caps stored matches and says so', async () => {
    const many = Array.from({ length: 10 }, () => '{ rejectUnauthorized: false }').join('\n');
    const { check, findings } = await runSourceCheck(repoSource([blob('a.ts')], { 'a.ts': many }), input, options({ maxFindings: 4 }), signal());
    expect(findings).toHaveLength(4);
    // Every file was checked: coverage stays complete; the summary says more were found than are shown.
    expect(check).toMatchObject({ status: 'complete', counts: { findingsTruncated: true } });
  });
});
