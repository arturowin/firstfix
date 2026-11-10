/**
 * Strings from repository-controlled files can hold things PostgreSQL won't store (NUL, unpaired UTF-16
 * surrogates) or a reader can't see (control characters). Such values are kept, never dropped, in a visible and
 * storable form: unpaired surrogates become U+FFFD, control characters become the literal text `\uXXXX`.
 */
// eslint-disable-next-line no-control-regex -- finding control characters is the purpose of this pattern
const CONTROL = /[\u0000-\u001f\u007f]/g;

export function isStorableText(s: string): boolean {
  // eslint-disable-next-line no-control-regex -- finding control characters is the purpose of this pattern
  return s.isWellFormed() && !/[\u0000-\u001f\u007f]/.test(s);
}

export function storableText(s: string, maxLength = 256): string {
  return s
    .toWellFormed()
    .replace(CONTROL, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
    .slice(0, maxLength);
}
