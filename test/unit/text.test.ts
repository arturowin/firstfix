import { describe, expect, it } from 'vitest';
import { isStorableText, storableText } from '../../src/domain/text.ts';

describe('storable text from untrusted files', () => {
  it.each([
    ['plain', 'lodash', 'lodash', true],
    ['NUL', 'a\u0000b', 'a\\u0000b', false],
    ['newline and bell', 'x\ny\u0007', 'x\\u000ay\\u0007', false],
    ['DEL', 'x\u007f', 'x\\u007f', false],
    ['lone high surrogate', 'v1\ud800', 'v1�', false],
    ['lone low surrogate', '\udc00x', '�x', false],
    ['a valid surrogate pair (emoji) stays', 'pkg-😀', 'pkg-😀', true],
  ])('%s', (_l, input, shown, storable) => {
    expect(isStorableText(input)).toBe(storable);
    expect(storableText(input)).toBe(shown);
  });

  it('is capped in length', () => {
    expect(storableText('a'.repeat(1000), 10)).toHaveLength(10);
  });
});
