/**
 * A bounded in-memory cache with a fixed lifetime per entry (from when the value was stored, never extended by
 * reads). Expired entries are never returned. When full, the oldest entry is dropped.
 */
export class TtlCache<V> {
  private readonly entries = new Map<string, { value: V; storedAt: number }>();
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private readonly now: () => number;

  constructor(options: { ttlMs: number; maxEntries: number; now?: () => number }) {
    this.ttlMs = options.ttlMs;
    this.maxEntries = options.maxEntries;
    this.now = options.now ?? Date.now;
  }

  get(key: string): V | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (this.now() - entry.storedAt >= this.ttlMs) {
      this.entries.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: string, value: V): void {
    this.entries.delete(key); // re-insert at the end: Map order is age order
    this.entries.set(key, { value, storedAt: this.now() });
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done === true) break;
      this.entries.delete(oldest.value);
    }
  }

  deletePrefix(prefix: string): void {
    for (const key of [...this.entries.keys()]) if (key.startsWith(prefix)) this.entries.delete(key);
  }

  get size(): number {
    return this.entries.size;
  }
}
