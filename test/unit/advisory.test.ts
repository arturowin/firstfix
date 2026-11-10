import { describe, expect, it } from 'vitest';
import { isMaliciousId, severityFromLabel } from '../../src/domain/advisory.ts';

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

describe('isMaliciousId', () => {
  it('recognises OpenSSF MAL- ids only', () => {
    expect(isMaliciousId('MAL-2025-20690')).toBe(true);
    expect(isMaliciousId('GHSA-9x64-5r7x-2q53')).toBe(false);
  });
});
