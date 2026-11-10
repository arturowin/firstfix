import { describe, expect, it } from 'vitest';
import { fixedWindowLimiter } from '../../src/api/rate-limit.ts';

describe('per-client submit limit', () => {
  const t0 = Date.UTC(2026, 10, 10, 12, 0, 0);

  it('allows N per minute per client, then says how long to wait; the next minute starts fresh', () => {
    const limit = fixedWindowLimiter(3);
    expect([1, 2, 3].map(() => limit.take('1.2.3.4', t0 + 1000))).toEqual([0, 0, 0]);
    expect(limit.take('1.2.3.4', t0 + 1000)).toBe(59);
    expect(limit.take('5.6.7.8', t0 + 1000)).toBe(0); // other clients unaffected
    expect(limit.take('1.2.3.4', t0 + 60_000)).toBe(0);
  });

  it('memory is bounded: a full table drops stale windows, and refuses new clients only if still full', () => {
    const limit = fixedWindowLimiter(10, 2);
    limit.take('a', t0);
    limit.take('b', t0);
    expect(limit.take('c', t0)).toBeGreaterThan(0); // full with live windows
    expect(limit.take('c', t0 + 60_000)).toBe(0); // a and b are stale now
  });
});
