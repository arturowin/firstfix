import { describe, expect, it } from 'vitest';
import { SecretBox } from '../../src/adapters/secret-box.ts';

const SECRET = 'x'.repeat(32);

describe('SecretBox', () => {
  it('round-trips, with a fresh IV each time', () => {
    const box = new SecretBox(SECRET);
    const a = box.seal('ghu_token');
    const b = box.seal('ghu_token');
    expect(a.equals(b)).toBe(false);
    expect(box.open(a)).toBe('ghu_token');
    expect(a.includes(Buffer.from('ghu_token'))).toBe(false);
  });

  it('rejects tampered data', () => {
    const box = new SecretBox(SECRET);
    const sealed = box.seal('ghu_token');
    const last = sealed.length - 1;
    sealed[last] = (sealed[last] ?? 0) ^ 1;
    expect(() => box.open(sealed)).toThrow();
  });

  it('rejects data sealed with another secret', () => {
    const sealed = new SecretBox(SECRET).seal('ghu_token');
    expect(() => new SecretBox('y'.repeat(32)).open(sealed)).toThrow();
  });

  it('requires a long secret', () => {
    expect(() => new SecretBox('short')).toThrow(/at least 32/);
  });
});
