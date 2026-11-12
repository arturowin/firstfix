import { describe, expect, it } from 'vitest';
import { TtlCache } from '../../src/application/ttl-cache.ts';

describe('TtlCache', () => {
  it('returns a value until its fixed lifetime ends, never after; reads do not extend it', () => {
    let now = 0;
    const cache = new TtlCache<string>({ ttlMs: 1000, maxEntries: 10, now: () => now });
    cache.set('k', 'v');
    now = 500;
    expect(cache.get('k')).toBe('v');
    now = 999;
    expect(cache.get('k')).toBe('v');
    now = 1000;
    expect(cache.get('k')).toBeUndefined();
  });

  it('is bounded: the oldest entry goes first', () => {
    const cache = new TtlCache<number>({ ttlMs: 1000, maxEntries: 2, now: () => 0 });
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('c', 3);
    expect(cache.size).toBe(2);
    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('c')).toBe(3);
  });

  it('drops every entry of a session by prefix', () => {
    const cache = new TtlCache<number>({ ttlMs: 1000, maxEntries: 10, now: () => 0 });
    cache.set('s1|i', 1);
    cache.set('s1|r|7', 2);
    cache.set('s2|i', 3);
    cache.deletePrefix('s1|');
    expect(cache.get('s1|i')).toBeUndefined();
    expect(cache.get('s1|r|7')).toBeUndefined();
    expect(cache.get('s2|i')).toBe(3);
  });
});
