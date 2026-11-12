import { describe, expect, it } from 'vitest';
import { isEligiblePath, isTestPath, selectSourceFiles, type TreeEntry } from '../../src/domain/source-files.ts';
import { isPartial, sourceSummaryLine, NO_SOURCE_COUNTS } from '../../src/domain/source-rules.ts';

const blob = (path: string, size = 100, mode = '100644'): TreeEntry => ({ path, type: 'blob', mode, size, sha: `sha-${path}` });

describe('isEligiblePath', () => {
  it.each(['index.js', 'src/a.jsx', 'src/b.ts', 'lib/c.tsx', 'SRC/D.TS'])('checks %s', (p) => {
    expect(isEligiblePath(p)).toBe(true);
  });

  it.each([
    'types.d.ts', 'app.min.js', 'vendor.bundle.js', 'a.mjs', 'readme.md', 'a.json',
    'node_modules/x/index.js', 'packages/a/node_modules/b.js', 'dist/app.js', 'build/x.ts', 'out/y.js', 'coverage/z.js',
    '.next/server.js', 'vendor/lib.js', 'src/generated/api.ts', 'src/__generated__/x.ts', 'storybook-static/a.js',
  ])('skips %s', (p) => {
    expect(isEligiblePath(p)).toBe(false);
  });
});

describe('isTestPath', () => {
  it.each(['test/a.js', 'src/__tests__/b.ts', 'a.test.ts', 'b.spec.tsx', 'packages/x/tests/c.js'])('labels %s', (p) => {
    expect(isTestPath(p)).toBe(true);
  });
  it.each(['src/testing.ts', 'src/contest.js', 'src/latest/a.ts'])('does not label %s', (p) => {
    expect(isTestPath(p)).toBe(false);
  });
});

describe('selectSourceFiles', () => {
  const limits = { maxFiles: 2, maxFileBytes: 1000, maxTotalBytes: 1500 };

  it('takes eligible files in path order and counts what the limits leave out', () => {
    const { selected, counts } = selectSourceFiles(
      [blob('z.js'), blob('a.ts', 600), blob('m.js', 2000), blob('b.js', 600), blob('c.js'), blob('README.md')],
      limits,
      false,
    );
    expect(selected.map((e) => e.path)).toEqual(['a.ts', 'b.js']);
    expect(counts).toMatchObject({ eligible: 5, skippedSize: 1, skippedLimit: 2, skippedLinks: 0 });
  });

  it('stops at the total-size budget', () => {
    const { selected, counts } = selectSourceFiles([blob('a.js', 900), blob('b.js', 900)], { ...limits, maxFiles: 10 }, false);
    expect(selected.map((e) => e.path)).toEqual(['a.js']);
    expect(counts.skippedLimit).toBe(1);
  });

  it('never follows symbolic links or submodules, only counts them', () => {
    const { selected, counts } = selectSourceFiles(
      [blob('link.js', 10, '120000'), { path: 'lib', type: 'commit', mode: '160000', size: null, sha: 'x' }, blob('a.js')],
      limits,
      false,
    );
    expect(selected.map((e) => e.path)).toEqual(['a.js']);
    expect(counts.skippedLinks).toBe(2);
  });

  it('carries a truncated listing into the counts', () => {
    expect(selectSourceFiles([], limits, true).counts.listingTruncated).toBe(true);
  });
});

describe('source summary', () => {
  const counts = { ...NO_SOURCE_COUNTS, eligible: 12, checked: 10 };

  it('older scans: not run', () => {
    expect(sourceSummaryLine(null, [])).toBe('Source checks were not run for this scan.');
  });

  it('no matches is "no issues found by the supported checks", never "secure"', () => {
    const line = sourceSummaryLine({ status: 'complete', counts, error: null }, []);
    expect(line).toBe('Source checks: no issues found by the 2 supported checks in 10 of 12 JavaScript/TypeScript files.');
    expect(line).not.toMatch(/secure|safe/i);
  });

  it('counts findings by severity and flags partial coverage', () => {
    expect(sourceSummaryLine({ status: 'partial', counts, error: null }, [{ severity: 'high' }, { severity: 'medium' }, { severity: 'medium' }])).toBe(
      'Partial source check: 3 findings (1 high, 2 medium) in 10 of 12 JavaScript/TypeScript files.',
    );
  });

  it('no files and failures say so', () => {
    expect(sourceSummaryLine({ status: 'no_files', counts, error: null }, [])).toBe('Source checks: no JavaScript/TypeScript files to check.');
    expect(sourceSummaryLine({ status: 'failed', counts, error: { message: 'GitHub answered 502' } }, [])).toBe('Source checks failed: GitHub answered 502');
  });

  it('is partial when anything eligible may have been missed', () => {
    expect(isPartial(NO_SOURCE_COUNTS)).toBe(false);
    expect(isPartial({ ...NO_SOURCE_COUNTS, skippedLinks: 3 })).toBe(false);
    for (const k of ['skippedLimit', 'skippedSize', 'skippedTime', 'fetchFailed'] as const) expect(isPartial({ ...NO_SOURCE_COUNTS, [k]: 1 })).toBe(true);
    expect(isPartial({ ...NO_SOURCE_COUNTS, listingTruncated: true })).toBe(true);
    expect(isPartial({ ...NO_SOURCE_COUNTS, findingsTruncated: true })).toBe(false); // all files checked
  });

  it('counts every match found, not only the stored examples', () => {
    const recorded = { ...counts, findingsTruncated: true, rules: { 'FF-TLS-001': { matches: 1, files: 1, inTestFiles: 0 }, 'FF-TLS-002': { matches: 50, files: 1, inTestFiles: 0 } } };
    expect(sourceSummaryLine({ status: 'complete', counts: recorded, error: null }, [{ severity: 'high' }])).toBe(
      'Source checks: 51 findings (1 high, 50 medium) in 10 of 12 JavaScript/TypeScript files. More matches were found than are shown.',
    );
  });

  it('says when more matches were found than are shown', () => {
    expect(sourceSummaryLine({ status: 'complete', counts: { ...counts, findingsTruncated: true }, error: null }, [{ severity: 'medium' }])).toBe(
      'Source checks: 1 finding (1 medium) in 10 of 12 JavaScript/TypeScript files. More matches were found than are shown.',
    );
  });
});
