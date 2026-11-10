import { describe, expect, it } from 'vitest';
import type { AffectedRange } from '../../src/domain/advisory.ts';
import { selectCandidate } from '../../src/domain/candidate.ts';
import { npmVersionScheme } from '../../src/domain/ecosystems/npm/version.ts';
import { toRanges } from '../../src/adapters/osv/translate.ts';
import { buildFixPlan } from '../../src/domain/fix-plan.ts';

const range = (introduced: string, fixed: string | null, lastAffected: string | null = null): AffectedRange => ({
  kind: 'range',
  introduced,
  fixed,
  lastAffected,
});
const pick = (installed: string, ranges: AffectedRange[]) => selectCandidate(installed, ranges, npmVersionScheme);

describe('selectCandidate (AffectedRange only)', () => {
  it('the fix of the range containing the installed version', () => {
    expect(pick('4.17.20', [range('4.0.0', '4.17.21')])).toEqual({ status: 'candidate', version: '4.17.21' });
  });

  it('several ranges: picks the one that contains the installed version (axios 0.x and 1.x)', () => {
    const axios = [range('1.0.0', '1.6.0'), range('0.8.1', '0.28.0')];
    expect(pick('0.21.1', axios)).toEqual({ status: 'candidate', version: '0.28.0' });
    expect(pick('1.5.0', axios)).toEqual({ status: 'candidate', version: '1.6.0' });
  });

  it('a candidate inside another range of the same advisory follows that range’s fix', () => {
    expect(pick('1.1.0', [range('1.0.0', '1.5.0'), range('1.5.0', '1.8.0')])).toEqual({ status: 'candidate', version: '1.8.0' });
  });

  it('no fix: last_affected, open range, explicit versions, or a containing range without a fix', () => {
    expect(pick('2.88.2', [range('0', null, '2.88.2')])).toEqual({ status: 'no_fix', version: null });
    expect(pick('0.1.1', [range('0', null)])).toEqual({ status: 'no_fix', version: null });
    expect(pick('0.1.1', [{ kind: 'versions', versions: ['0.1.1'] }])).toEqual({ status: 'no_fix', version: null });
    expect(pick('1.1.0', [range('1.0.0', '1.5.0'), range('1.5.0', null)])).toEqual({ status: 'no_fix', version: null });
  });

  it('unknown: ranges don’t place the installed version, no ranges, invalid version, no scheme', () => {
    expect(pick('3.0.0', [range('4.0.0', '4.17.21')])).toEqual({ status: 'unknown', version: null });
    expect(pick('3.0.0', [])).toEqual({ status: 'unknown', version: null });
    expect(pick('latest', [range('0', '1.0.0')])).toEqual({ status: 'unknown', version: null });
    expect(selectCandidate('4.17.20', [range('4.0.0', '4.17.21')], null)).toEqual({ status: 'unknown', version: null });
  });

  it('a candidate the same advisory explicitly lists as affected is no candidate (review reproduction)', () => {
    expect(pick('1.0.0', [range('0', '1.0.1'), { kind: 'versions', versions: ['1.0.0', '1.0.1'] }])).toEqual({
      status: 'no_fix',
      version: null,
    });
  });

  it('a versions list consistent with the ranges doesn’t block the candidate', () => {
    expect(pick('1.0.0', [range('0', '1.0.1'), { kind: 'versions', versions: ['0.9.0', '1.0.0'] }])).toEqual({
      status: 'candidate',
      version: '1.0.1',
    });
  });

  it('a limit bounds the range: versions at or above it are not affected', () => {
    const limited = { kind: 'range' as const, introduced: '2.0.0', fixed: null, lastAffected: null, limit: '3.0.0' };
    expect(npmVersionScheme.inRange('2.5.0', limited)).toBe(true);
    expect(npmVersionScheme.inRange('3.0.0', limited)).toBe(false);
    expect(pick('2.5.0', [limited])).toEqual({ status: 'no_fix', version: null }); // a limit is not a fix
  });

  describe('OSV limits through translation (review finding)', () => {
    const osv = (ranges: { events: object[] }[], versions?: string[]) =>
      toRanges({ ranges: ranges.map((x) => ({ type: 'SEMVER', ...x })), ...(versions ? { versions } : {}) });

    it.each([
      ['one range', [{ events: [{ introduced: '0' }, { fixed: '2.0.0' }, { introduced: '2.0.0' }, { limit: '*' }] }]],
      ['two ranges', [{ events: [{ introduced: '0' }, { fixed: '2.0.0' }] }, { events: [{ introduced: '2.0.0' }, { limit: '*' }] }]],
    ])('fixed at 2.0.0 but affected again from 2.0.0 with limit "*" (%s): 2.0.0 is not offered', (_l, ranges) => {
      const affected = osv(ranges);
      expect(npmVersionScheme.inRange('2.0.0', affected[1] ?? expect.fail())).toBe(true);
      expect(pick('1.5.0', affected)).toEqual({ status: 'no_fix', version: null });
      // and the planner offers no upgrade for it
      const [action] = buildFixPlan(
        [
          {
            ecosystem: 'npm', package: 'lib', installedAs: [], directAs: ['lib'], installedVersion: '1.5.0', scope: 'runtime',
            isDirect: true, directParents: [], advisoryId: 'GHSA-aaaa-bbbb-cccc', severity: 'high', isMalicious: false,
            title: null, candidateVersion: null, fixStatus: 'no_fix', affectedRanges: affected,
          },
        ],
        () => npmVersionScheme,
      );
      expect(action?.versions[0]?.candidate).toBeNull();
    });

    it('a finite limit applies to the whole range, alongside a fixed event', () => {
      const affected = osv([{ events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }, { limit: '1.5.0' }] }]);
      expect(affected).toEqual([{ kind: 'range', introduced: '1.0.0', fixed: '2.0.0', lastAffected: null, limits: ['1.5.0'] }]);
      expect(npmVersionScheme.inRange('1.2.0', affected[0] ?? expect.fail())).toBe(true);
      expect(npmVersionScheme.inRange('1.5.0', affected[0] ?? expect.fail())).toBe(false);
      expect(npmVersionScheme.inRange('1.9.0', affected[0] ?? expect.fail())).toBe(false);
      expect(pick('1.2.0', affected)).toEqual({ status: 'candidate', version: '2.0.0' });
    });

    it('explicit versions still count next to limited ranges', () => {
      const affected = osv([{ events: [{ introduced: '1.0.0' }, { fixed: '1.1.0' }, { limit: '5.0.0' }] }], ['1.0.5', '1.1.0']);
      expect(pick('1.0.5', affected)).toEqual({ status: 'no_fix', version: null }); // 1.1.0 is listed as affected
    });

    it('an unparseable limit never narrows a range (an affected version is never hidden)', () => {
      expect(npmVersionScheme.inRange('9.0.0', { kind: 'range', introduced: '0', fixed: null, lastAffected: null, limits: ['not-a-version'] })).toBe(true);
    });
  });

  it('a major jump is reported by the scheme, not hidden by selection', () => {
    const r = pick('2.5.0', [range('0', '3.0.0')]);
    expect(r).toEqual({ status: 'candidate', version: '3.0.0' });
    expect(npmVersionScheme.isMajorJump('2.5.0', r.version ?? '')).toBe(true);
  });
});
