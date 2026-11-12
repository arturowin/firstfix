import { describe, expect, it } from 'vitest';
import { sourceBadge, sourceBadgeLabel, sourceHeadline, sourceTotals, type SourceResultJson } from '../../src/web/source-text.ts';

const rule = (severity: 'high' | 'medium', matches: number, inTestFiles: number) => ({ severity, matches, inTestFiles });
const complete = (rules: NonNullable<SourceResultJson['rules']>): SourceResultJson => ({ status: 'complete', findings: [], rules });

describe('sourceTotals', () => {
  it('counts every match from the per-rule counts, including those in test files', () => {
    expect(sourceTotals(complete([rule('high', 1, 1), rule('medium', 40, 2)]))).toEqual({ total: 41, high: 1, inTests: 3 });
  });

  it('falls back to the stored findings for scans without per-rule counts', () => {
    const src: SourceResultJson = {
      status: 'complete',
      findings: [
        { severity: 'high', testFile: false },
        { severity: 'medium', testFile: true },
      ],
    };
    expect(sourceTotals(src)).toEqual({ total: 2, high: 1, inTests: 1 });
  });
});

describe('sourceBadgeLabel', () => {
  it.each([
    [{ total: 3, high: 1, inTests: 0 }, '3 findings'],
    [{ total: 1, high: 1, inTests: 0 }, '1 finding'],
    [{ total: 3, high: 1, inTests: 3 }, '3 findings · all in tests'],
    [{ total: 3, high: 1, inTests: 2 }, '3 findings · 2 in tests'],
  ])('%j → %s', (totals, label) => {
    expect(sourceBadgeLabel(totals)).toBe(label);
  });
});

describe('sourceHeadline', () => {
  it('adds the source result to a clean dependency headline, saying when all matches are in tests', () => {
    expect(sourceHeadline(complete([rule('high', 1, 1), rule('medium', 2, 2)]))).toBe(' Source checks: 3 findings, all in test files.');
  });

  it.each([
    [[rule('high', 1, 0), rule('medium', 2, 0)], ' Source checks: 3 findings.'],
    [[rule('high', 1, 0), rule('medium', 2, 2)], ' Source checks: 3 findings, 2 in test files.'],
    [[rule('high', 1, 0), rule('medium', 2, 1)], ' Source checks: 3 findings, 1 in a test file.'],
    [[rule('high', 1, 1), rule('medium', 0, 0)], ' Source checks: 1 finding, in a test file.'],
  ])('%j', (rules, text) => {
    expect(sourceHeadline(complete(rules))).toBe(text);
  });

  it('says it for a partial check too', () => {
    expect(sourceHeadline({ status: 'partial', findings: [], rules: [rule('medium', 1, 0)] })).toBe(' Source checks: 1 finding.');
  });

  it.each([
    ['no source result', null],
    ['no matches', complete([rule('high', 0, 0), rule('medium', 0, 0)])],
    ['no files', { status: 'no_files', findings: [] } satisfies SourceResultJson],
    ['a failed check', { status: 'failed', findings: [] } satisfies SourceResultJson],
    ['a scan from before source checks', { status: null, findings: [] } satisfies SourceResultJson],
  ])('adds nothing for %s', (_name, src) => {
    expect(sourceHeadline(src)).toBe('');
  });
});

describe('sourceBadge', () => {
  const none = [rule('high', 0, 0), rule('medium', 0, 0)];
  const result = (status: SourceResultJson['status'], checked: number, rules = none): SourceResultJson => ({ status, counts: { checked }, findings: [], rules });

  it.each([
    ['a complete check with no matches', result('complete', 12), { label: 'No issues found', tone: 'ok' }],
    ['a partial check with no matches', result('partial', 7), { label: 'No findings in checked files', tone: 'warn' }],
    ['a partial check that checked no files', result('partial', 0), { label: 'No files checked', tone: 'warn' }],
    ['a complete check that checked no files', result('complete', 0), { label: 'No files checked', tone: 'warn' }],
    ['high matches, all in tests', result('complete', 12, [rule('high', 1, 1), rule('medium', 2, 2)]), { label: '3 findings · all in tests', tone: 'danger' }],
    ['medium matches only', result('partial', 7, [rule('high', 0, 0), rule('medium', 2, 0)]), { label: '2 findings', tone: 'warn' }],
    ['no JS/TS files', { status: 'no_files', findings: [] } satisfies SourceResultJson, { label: 'No JS/TS files', tone: 'muted' }],
    ['a failed check', { status: 'failed', findings: [] } satisfies SourceResultJson, { label: 'Check failed', tone: 'danger' }],
    ['a scan from before source checks', null, { label: 'Not run', tone: 'muted' }],
  ])('%s', (_name, src, badge) => {
    expect(sourceBadge(src)).toEqual(badge);
  });

  it('is green only for a complete check that found nothing', () => {
    const green = [result('complete', 12), result('partial', 7), result('partial', 0), result('complete', 0)].filter((s) => sourceBadge(s).tone === 'ok');
    expect(green).toEqual([result('complete', 12)]);
  });
});
