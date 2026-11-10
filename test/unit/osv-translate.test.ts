import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { isMalicious, isOsvVuln, severityFromLabel, toAdvisory, toRanges, type OsvVuln } from '../../src/adapters/osv/translate.ts';
import { readdirSync } from 'node:fs';

const fixture = (id: string): OsvVuln =>
  JSON.parse(readFileSync(path.join(import.meta.dirname, '..', 'fixtures', 'osv', `${id}.json`), 'utf8')) as OsvVuln;

describe('severityFromLabel', () => {
  it.each([
    ['CRITICAL', 'critical'],
    ['HIGH', 'high'],
    ['MODERATE', 'medium'],
    ['moderate', 'medium'],
    ['LOW', 'low'],
    ['', 'unknown'],
    ['SEVERE', 'unknown'],
    [undefined, 'unknown'],
    [7.5, 'unknown'],
  ])('%j → %s', (label, expected) => {
    expect(severityFromLabel(label)).toBe(expected);
  });
});

describe('isMalicious', () => {
  it('OpenSSF MAL- records and GitHub advisories tagged CWE-506 (recorded fixtures)', () => {
    expect(isMalicious(fixture('MAL-2025-20690'))).toBe(true);
    expect(isMalicious(fixture('GHSA-9x64-5r7x-2q53'))).toBe(true);
    expect(isMalicious(fixture('GHSA-mh6f-8j2x-4483'))).toBe(true);
    expect(isMalicious(fixture('GHSA-29mw-wpgm-hmr9'))).toBe(false); // CWE-1333/400: ReDoS, not malware
    expect(isMalicious({ id: 'X', database_specific: { cwe_ids: 'CWE-506' } })).toBe(false); // not a list
  });
});

describe('toRanges: OSV events → AffectedRange', () => {
  const r = (events: object[], type = 'SEMVER') => toRanges({ ranges: [{ type, events }] });

  it('introduced + fixed', () => {
    expect(r([{ introduced: '4.0.0' }, { fixed: '4.17.21' }])).toEqual([
      { kind: 'range', introduced: '4.0.0', fixed: '4.17.21', lastAffected: null },
    ]);
  });

  it('introduced: 0 + last_affected → no fix published', () => {
    expect(r([{ introduced: '0' }, { last_affected: '2.88.2' }])).toEqual([
      { kind: 'range', introduced: '0', fixed: null, lastAffected: '2.88.2' },
    ]);
  });

  it('an open range affects every later version', () => {
    expect(r([{ introduced: '0' }])).toEqual([{ kind: 'range', introduced: '0', fixed: null, lastAffected: null }]);
  });

  it('several ranges in one event list; a limit keeps its upper bound but is not a fix', () => {
    expect(r([{ introduced: '1.0.0' }, { fixed: '1.2.0' }, { introduced: '2.0.0' }, { limit: '3.0.0' }])).toEqual([
      { kind: 'range', introduced: '1.0.0', fixed: '1.2.0', lastAffected: null },
      { kind: 'range', introduced: '2.0.0', fixed: null, lastAffected: null, limit: '3.0.0' },
    ]);
  });

  it('an explicit versions list is kept next to ranges (affected if in either)', () => {
    expect(toRanges({ ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }], versions: ['1.0.0', '1.0.1'] })).toEqual([
      { kind: 'range', introduced: '0', fixed: '1.0.1', lastAffected: null },
      { kind: 'versions', versions: ['1.0.0', '1.0.1'] },
    ]);
  });

  it('GIT ranges are skipped; versions-only entries become an explicit list', () => {
    expect(r([{ introduced: 'abc123' }, { fixed: 'def456' }], 'GIT')).toEqual([]);
    expect(toRanges({ versions: ['0.1.1'] })).toEqual([{ kind: 'versions', versions: ['0.1.1'] }]);
    expect(toRanges({})).toEqual([]);
  });
});

describe('toAdvisory (recorded fixtures)', () => {
  it('keeps only this package’s entries: axios has two ranges in two entries', () => {
    expect(toAdvisory(fixture('GHSA-wf5p-g6vw-rhxx'), { ecosystem: 'npm', name: 'axios' }).affectedRanges).toEqual([
      { kind: 'range', introduced: '1.0.0', fixed: '1.6.0', lastAffected: null },
      { kind: 'range', introduced: '0.8.1', fixed: '0.28.0', lastAffected: null },
    ]);
  });

  it('versions-only malware advisory', () => {
    expect(toAdvisory(fixture('GHSA-9x64-5r7x-2q53'), { ecosystem: 'npm', name: 'flatmap-stream' })).toMatchObject({
      severity: 'critical',
      isMalicious: true,
      affectedRanges: [{ kind: 'versions', versions: ['0.1.1'] }],
    });
  });
});

describe('isOsvVuln', () => {
  it('accepts every recorded real OSV record', () => {
    const dir = path.join(import.meta.dirname, '..', 'fixtures', 'osv');
    const records = readdirSync(dir).filter((f) => /^(GHSA|MAL)-.*\.json$/.test(f));
    expect(records.length).toBeGreaterThan(4);
    for (const f of records) expect(isOsvVuln(fixture(f.replace(/\.json$/, '')), f.replace(/\.json$/, ''))).toBe(true);
  });
});
