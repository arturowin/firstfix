import { describe, expect, it } from 'vitest';
import type { AffectedRange } from '../../src/domain/advisory.ts';
import { npmVersionScheme as s } from '../../src/domain/ecosystems/npm/version.ts';

const range = (introduced: string, fixed: string | null, lastAffected: string | null = null): AffectedRange => ({
  kind: 'range',
  introduced,
  fixed,
  lastAffected,
});

describe('npm version scheme', () => {
  it('inRange: introduced inclusive, fixed exclusive, last affected inclusive, open-ended, introduced 0', () => {
    expect(s.inRange('4.0.0', range('4.0.0', '4.17.21'))).toBe(true);
    expect(s.inRange('4.17.20', range('4.0.0', '4.17.21'))).toBe(true);
    expect(s.inRange('4.17.21', range('4.0.0', '4.17.21'))).toBe(false);
    expect(s.inRange('3.10.1', range('4.0.0', '4.17.21'))).toBe(false);
    expect(s.inRange('2.88.2', range('0', null, '2.88.2'))).toBe(true);
    expect(s.inRange('2.88.3', range('0', null, '2.88.2'))).toBe(false);
    expect(s.inRange('99.0.0', range('0', null))).toBe(true);
  });

  it('inRange: explicit version lists; invalid versions never match', () => {
    expect(s.inRange('0.1.1', { kind: 'versions', versions: ['0.1.1'] })).toBe(true);
    expect(s.inRange('0.1.2', { kind: 'versions', versions: ['0.1.1'] })).toBe(false);
    expect(s.inRange('not-a-version', range('0', null))).toBe(false);
  });

  it('prereleases order before their release', () => {
    expect(s.inRange('2.0.0-beta.1', range('1.0.0', '2.0.0'))).toBe(true);
    expect(s.compare('2.0.0-beta.1', '2.0.0')).toBeLessThan(0);
  });

  it.each([
    ['1.2.3', '1.9.0', false],
    ['1.2.3', '2.0.0', true],
    ['0.3.1', '0.3.9', false],
    ['0.3.1', '0.4.0', true], // 0.x: the minor is the leftmost non-zero part
    ['0.0.3', '0.0.4', true],
    ['4.17.20', '4.17.21', false],
    ['6.5.5', '6.5.3', false], // a downgrade is never a jump
  ])('isMajorJump(%s → %s) = %s', (from, to, jump) => {
    expect(s.isMajorJump(from, to)).toBe(jump);
  });
});
