/**
 * Targeted source checks for JavaScript/TypeScript (docs/ARCHITECTURE.md "Source checks"). Pure: text in,
 * matches out. A small error-tolerant tokenizer, not a parser: comments are skipped, and the contents of strings,
 * templates and regular expressions are never read as code, so quoted examples and documentation don't match.
 * Rules then match short token sequences, so whitespace, line breaks and quote style don't matter.
 *
 * Positions are 1-based lines and columns in UTF-16 code units (how editors and GitHub count). Lines end at "\n";
 * "\r\n" counts as one line ending.
 */
import type { SourceRuleId } from './source-rules.ts';

export type TokenKind = 'ident' | 'punct' | 'string' | 'template' | 'number' | 'regex';

export interface Token {
  kind: TokenKind;
  /** The token's source text (strings and templates with their quotes). */
  text: string;
  /** Decoded value of a string, or of a template without substitutions; null otherwise. */
  value: string | null;
  start: number;
  end: number;
}

export interface Position {
  line: number;
  column: number;
}

export interface SourceMatch {
  ruleId: SourceRuleId;
  ruleVersion: number;
  start: Position;
  /** Position of the last character of the match. */
  end: Position;
  /** The matched code rebuilt from its tokens (no comments; no other string literals), at most 200 characters. */
  excerpt: string;
}

// --- tokenizer ------------------------------------------------------------------------------------------

const PUNCTUATORS = [
  '>>>=', '...', '===', '!==', '**=', '<<=', '>>=', '>>>', '??=', '&&=', '||=',
  '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '++', '--', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '**', '<<', '>>',
  '{', '}', '(', ')', '[', ']', ';', ',', '<', '>', '+', '-', '*', '/', '%', '&', '|', '^', '!', '~', '?', ':', '=', '.', '@', '#',
];

/** After these keywords an expression starts, so "/" begins a regular expression. */
const EXPRESSION_KEYWORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await', 'extends',
]);

const IDENT = /[\p{ID_Start}$_][\p{ID_Continue}$‌‍]*/uy;
const NUMBER = /(?:0[xXoObB][0-9a-fA-F_]+|\d[\d_]*(?:\.[\d_]*)?(?:[eE][+-]?\d+)?|\.\d[\d_]*(?:[eE][+-]?\d+)?)n?/y;
const REGEX_FLAGS = /[\p{ID_Continue}]*/uy;
const SPACE = /\s/u;

function isLineBreak(ch: string | undefined): boolean {
  return ch === '\n' || ch === '\r';
}

/** Decodes one escape sequence starting after the backslash at `j`; returns the text and the next index. */
function decodeEscape(src: string, j: number): { text: string; next: number } {
  const ch = src[j] ?? '';
  const simple: Record<string, string> = { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', v: '\v', '0': '\0' };
  if (ch === 'x') {
    const hex = src.slice(j + 1, j + 3);
    if (/^[0-9a-fA-F]{2}$/.test(hex)) return { text: String.fromCharCode(parseInt(hex, 16)), next: j + 3 };
  }
  if (ch === 'u') {
    if (src[j + 1] === '{') {
      const close = src.indexOf('}', j + 2);
      const hex = close === -1 ? '' : src.slice(j + 2, close);
      if (/^[0-9a-fA-F]{1,6}$/.test(hex) && parseInt(hex, 16) <= 0x10ffff) return { text: String.fromCodePoint(parseInt(hex, 16)), next: close + 1 };
    } else {
      const hex = src.slice(j + 1, j + 5);
      if (/^[0-9a-fA-F]{4}$/.test(hex)) return { text: String.fromCharCode(parseInt(hex, 16)), next: j + 5 };
    }
  }
  if (ch === '0' && /[0-9]/.test(src[j + 1] ?? '')) return { text: '\0', next: j + 1 }; // legacy octal: rare, never "0"
  return { text: simple[ch] ?? ch, next: j + 1 };
}

/** A quoted string from `i` (the quote). Unterminated: ends before the line break or at the end of the text. */
function readString(src: string, i: number): { end: number; value: string } {
  const quote = src[i];
  let j = i + 1;
  let value = '';
  while (j < src.length) {
    const ch = src[j];
    if (ch === quote) return { end: j + 1, value };
    if (isLineBreak(ch)) return { end: j, value };
    if (ch === '\\') {
      if (src[j + 1] === '\r' && src[j + 2] === '\n') {
        j += 3;
        continue;
      }
      if (isLineBreak(src[j + 1])) {
        j += 2;
        continue;
      }
      const esc = decodeEscape(src, j + 1);
      value += esc.text;
      j = esc.next;
      continue;
    }
    value += ch ?? '';
    j++;
  }
  return { end: j, value };
}

/**
 * Nested templates and `${…}` substitutions deeper than this are not read: the file is reported as not checked
 * (partial coverage) instead of exhausting the stack. Real code stays far below it.
 */
export const MAX_TEMPLATE_NESTING = 64;

/** Thrown inside the tokenizer when nesting passes MAX_TEMPLATE_NESTING; caught by scanSource. */
class NestingLimit extends Error {}

/** A template literal from `i` (the backtick). Substitutions are skipped as opaque; their value is then null. */
function readTemplate(src: string, i: number, depth = 0): { end: number; value: string | null } {
  if (depth > MAX_TEMPLATE_NESTING) throw new NestingLimit('template nesting too deep');
  let j = i + 1;
  let value = '';
  let substituted = false;
  while (j < src.length) {
    const ch = src[j];
    if (ch === '`') return { end: j + 1, value: substituted ? null : value };
    if (ch === '\\') {
      const esc = decodeEscape(src, j + 1);
      value += esc.text;
      j = esc.next;
      continue;
    }
    if (ch === '$' && src[j + 1] === '{') {
      substituted = true;
      j = skipBalanced(src, j + 2, depth + 1);
      continue;
    }
    value += ch ?? '';
    j++;
  }
  return { end: j, value: substituted ? null : value };
}

/** From just inside a "${", to just after its matching "}", stepping over nested strings, templates and comments. */
function skipBalanced(src: string, from: number, nesting: number): number {
  if (nesting > MAX_TEMPLATE_NESTING) throw new NestingLimit('template nesting too deep');
  let depth = 1;
  let j = from;
  while (j < src.length) {
    const ch = src[j];
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return j + 1;
    } else if (ch === '"' || ch === "'") {
      j = readString(src, j).end;
      continue;
    } else if (ch === '`') {
      j = readTemplate(src, j, nesting + 1).end;
      continue;
    } else if (ch === '/' && src[j + 1] === '/') {
      while (j < src.length && !isLineBreak(src[j])) j++;
      continue;
    } else if (ch === '/' && src[j + 1] === '*') {
      const close = src.indexOf('*/', j + 2);
      j = close === -1 ? src.length : close + 2;
      continue;
    }
    j++;
  }
  return j;
}

/** A regular expression literal from `i` (the slash); null when it isn't one (no closing slash on the line). */
function readRegex(src: string, i: number): number | null {
  let j = i + 1;
  let inClass = false;
  while (j < src.length) {
    const ch = src[j];
    if (isLineBreak(ch)) return null;
    if (ch === '\\') {
      j += 2;
      continue;
    }
    if (ch === '[') inClass = true;
    else if (ch === ']') inClass = false;
    else if (ch === '/' && !inClass) {
      REGEX_FLAGS.lastIndex = j + 1;
      REGEX_FLAGS.exec(src);
      return REGEX_FLAGS.lastIndex;
    }
    j++;
  }
  return null;
}

function regexAllowedAfter(prev: Token | undefined): boolean {
  if (!prev) return true;
  if (prev.kind === 'ident') return EXPRESSION_KEYWORDS.has(prev.text);
  if (prev.kind === 'punct') return prev.text !== ')' && prev.text !== ']' && prev.text !== '}';
  return false;
}

/** Tokens of JavaScript/TypeScript source, comments dropped. Never throws; malformed input gives fewer tokens. */
export function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  if (src.startsWith('#!')) while (i < src.length && !isLineBreak(src[i])) i++;
  const push = (kind: TokenKind, start: number, end: number, value: string | null = null) => {
    tokens.push({ kind, text: src.slice(start, end), value, start, end });
  };
  while (i < src.length) {
    const ch = src[i] ?? '';
    const next = src[i + 1];
    if (SPACE.test(ch) || ch === '﻿') {
      i++;
      continue;
    }
    if (ch === '/' && next === '/') {
      while (i < src.length && !isLineBreak(src[i])) i++;
      continue;
    }
    if (ch === '/' && next === '*') {
      const close = src.indexOf('*/', i + 2);
      i = close === -1 ? src.length : close + 2;
      continue;
    }
    if (ch === '"' || ch === "'") {
      const s = readString(src, i);
      push('string', i, s.end, s.value);
      i = s.end;
      continue;
    }
    if (ch === '`') {
      const t = readTemplate(src, i);
      push('template', i, t.end, t.value);
      i = t.end;
      continue;
    }
    if (/[0-9]/.test(ch) || (ch === '.' && /[0-9]/.test(next ?? ''))) {
      NUMBER.lastIndex = i;
      if (NUMBER.exec(src)) {
        push('number', i, NUMBER.lastIndex);
        i = NUMBER.lastIndex;
        continue;
      }
    }
    IDENT.lastIndex = i;
    if (IDENT.exec(src)) {
      push('ident', i, IDENT.lastIndex);
      i = IDENT.lastIndex;
      continue;
    }
    if (ch === '/' && regexAllowedAfter(tokens.at(-1))) {
      const end = readRegex(src, i);
      if (end !== null) {
        push('regex', i, end);
        i = end;
        continue;
      }
    }
    const punct = PUNCTUATORS.find((p) => src.startsWith(p, i));
    if (punct) {
      push('punct', i, i + punct.length);
      i += punct.length;
      continue;
    }
    i++; // anything else (stray characters): skipped
  }
  return tokens;
}

// --- rules ----------------------------------------------------------------------------------------------

/** A token after the value that continues the expression: then the value is not what gets assigned. */
const CONTINUES = new Set([
  '.', '?.', '[', '(', '+', '-', '*', '/', '%', '**', '?', '??', '||', '&&',
  '==', '===', '!=', '!==', '<', '>', '<=', '>=', '|', '&', '^', '<<', '>>', '>>>',
]);

function endsExpression(t: Token | undefined): boolean {
  if (!t) return true;
  if (t.kind === 'punct') return !CONTINUES.has(t.text);
  if (t.kind === 'template') return false; // tagged template: the value is called
  return !(t.kind === 'ident' && (t.text === 'instanceof' || t.text === 'in' || t.text === 'as' || t.text === 'satisfies'));
}

const isPunct = (t: Token | undefined, text: string) => t?.kind === 'punct' && t.text === text;
const isIdent = (t: Token | undefined, text: string) => t?.kind === 'ident' && t.text === text;
/** A string, or a template without substitutions, with exactly this value. */
const isLiteral = (t: Token | undefined, value: string) => (t?.kind === 'string' || t?.kind === 'template') && t.value === value;

/** `.NAME` or `['NAME']` at k: the index after it, or -1. */
function memberAccess(tokens: Token[], k: number, name: string): number {
  if (isPunct(tokens[k], '.') && isIdent(tokens[k + 1], name)) return k + 2;
  if (isPunct(tokens[k], '[') && isLiteral(tokens[k + 1], name) && isPunct(tokens[k + 2], ']')) return k + 3;
  return -1;
}

interface RawMatch {
  ruleId: SourceRuleId;
  first: number;
  last: number;
}

/** FF-TLS-001: process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0' (or ["…"], any quotes, or the number 0). */
function matchProcessWideTls(tokens: Token[], k: number): RawMatch | null {
  if (!isIdent(tokens[k], 'process')) return null;
  const before = tokens[k - 1];
  if (isPunct(before, '.') || isPunct(before, '?.')) return null; // something.process
  if (!isPunct(tokens[k + 1], '.') || !isIdent(tokens[k + 2], 'env')) return null;
  const afterName = memberAccess(tokens, k + 3, 'NODE_TLS_REJECT_UNAUTHORIZED');
  if (afterName === -1 || !isPunct(tokens[afterName], '=')) return null;
  const value = tokens[afterName + 1];
  const zero = isLiteral(value, '0') || (value?.kind === 'number' && value.text === '0');
  if (!zero || !endsExpression(tokens[afterName + 2])) return null;
  return { ruleId: 'FF-TLS-001', first: k, last: afterName + 1 };
}

/** FF-TLS-002: `{ rejectUnauthorized: false }` (identifier or quoted key) or `<expr>.rejectUnauthorized = false`. */
function matchClientTls(tokens: Token[], k: number): RawMatch | null {
  const t = tokens[k];
  // Object property: the key directly after "{" or "," (not a ternary "a ? rejectUnauthorized : false").
  if (isIdent(t, 'rejectUnauthorized') || isLiteral(t, 'rejectUnauthorized')) {
    const before = tokens[k - 1];
    if ((isPunct(before, '{') || isPunct(before, ',')) && isPunct(tokens[k + 1], ':') && isIdent(tokens[k + 2], 'false') && endsExpression(tokens[k + 3])) {
      return { ruleId: 'FF-TLS-002', first: k, last: k + 2 };
    }
  }
  // Member assignment: … .rejectUnauthorized = false  /  … ['rejectUnauthorized'] = false
  if (isPunct(t, '.') || isPunct(t, '[')) {
    const after = memberAccess(tokens, k, 'rejectUnauthorized');
    if (after === -1 || k === 0 || !isPunct(tokens[after], '=') || !isIdent(tokens[after + 1], 'false') || !endsExpression(tokens[after + 2])) return null;
    // Start the excerpt at the object: a short `a.b.c` chain of identifiers before the property.
    let first = k;
    if (tokens[k - 1]?.kind === 'ident') {
      first = k - 1;
      while (first >= 2 && k - first < 8 && (isPunct(tokens[first - 1], '.') || isPunct(tokens[first - 1], '?.')) && tokens[first - 2]?.kind === 'ident') {
        first -= 2;
      }
    }
    return { ruleId: 'FF-TLS-002', first, last: after + 1 };
  }
  return null;
}

/** Rebuilds a token range as compact code: no comments, no stray whitespace. */
function render(tokens: Token[]): string {
  let out = '';
  let prev: Token | undefined;
  for (const t of tokens) {
    const tight =
      isPunct(t, '.') || isPunct(t, '?.') || isPunct(t, '[') || isPunct(t, ']') || isPunct(t, ':') ||
      isPunct(prev, '.') || isPunct(prev, '?.') || isPunct(prev, '[');
    out += (out !== '' && !tight ? ' ' : '') + t.text;
    prev = t;
  }
  return out.length > 200 ? `${out.slice(0, 199)}…` : out;
}

function lineStarts(src: string): number[] {
  const starts = [0];
  for (let i = 0; i < src.length; i++) if (src[i] === '\n') starts.push(i + 1);
  return starts;
}

function positionOf(starts: number[], offset: number): Position {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((starts[mid] ?? 0) <= offset) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: offset - (starts[lo] ?? 0) + 1 };
}

const VERSIONS: Record<SourceRuleId, number> = { 'FF-TLS-001': 1, 'FF-TLS-002': 1 };

/**
 * Every match of the supported rules in one file, in source order (at most `max`; no limit by default: the caller
 * decides what to keep). `unparsed`: the file could not be read as code (nesting limit), so it was not checked.
 */
export function scanSource(src: string, max = Infinity): { matches: SourceMatch[]; truncated: boolean; unparsed: boolean } {
  let tokens: Token[];
  try {
    tokens = tokenize(src);
  } catch (err) {
    if (err instanceof NestingLimit) return { matches: [], truncated: false, unparsed: true };
    throw err;
  }
  const starts = lineStarts(src);
  const matches: SourceMatch[] = [];
  for (let k = 0; k < tokens.length; k++) {
    const found = matchProcessWideTls(tokens, k) ?? matchClientTls(tokens, k);
    if (!found) continue;
    if (matches.length >= max) return { matches, truncated: true, unparsed: false };
    const first = tokens[found.first];
    const last = tokens[found.last];
    if (!first || !last) continue;
    matches.push({
      ruleId: found.ruleId,
      ruleVersion: VERSIONS[found.ruleId],
      start: positionOf(starts, first.start),
      end: positionOf(starts, last.end - 1),
      excerpt: render(tokens.slice(found.first, found.last + 1)),
    });
    k = found.last; // a match is never reused by the next one
  }
  return { matches, truncated: false, unparsed: false };
}
