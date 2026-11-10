/**
 * Per-client request limit for POST /scans: a fixed one-minute window per key (the client IP). In memory, per
 * API process: with several API instances each enforces its own limit (stated in README). Bounded memory: stale
 * windows are dropped as new ones start, and the table never holds more than `maxKeys` clients.
 */
export interface RateLimiter {
  /** Counts a request; returns the seconds to wait if it's over the limit, or 0. */
  take(key: string, now?: number): number;
}

export function fixedWindowLimiter(perMinute: number, maxKeys = 50_000): RateLimiter {
  const windows = new Map<string, { start: number; count: number }>();
  return {
    take(key, now = Date.now()) {
      const minute = Math.floor(now / 60_000) * 60_000;
      let w = windows.get(key);
      if (!w || w.start !== minute) {
        if (windows.size >= maxKeys) {
          for (const [k, v] of windows) if (v.start !== minute) windows.delete(k);
          if (windows.size >= maxKeys) return Math.ceil((minute + 60_000 - now) / 1000); // table full: refuse
        }
        w = { start: minute, count: 0 };
        windows.set(key, w);
      }
      w.count++;
      return w.count > perMinute ? Math.ceil((minute + 60_000 - now) / 1000) : 0;
    },
  };
}
