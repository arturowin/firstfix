import { describe, expect, it } from 'vitest';
import { scanSource, tokenize } from '../../src/domain/source-scan.ts';

const rules = (src: string) => scanSource(src).matches.map((m) => m.ruleId);
const first = (src: string) => scanSource(src).matches[0];

describe('FF-TLS-001: process-wide NODE_TLS_REJECT_UNAUTHORIZED = "0"', () => {
  it.each([
    "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';",
    'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"',
    'process.env.NODE_TLS_REJECT_UNAUTHORIZED = `0`',
    'process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0',
    "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'",
    'process.env["NODE_TLS_REJECT_UNAUTHORIZED"]="0"',
    "process\n  .env\n  .NODE_TLS_REJECT_UNAUTHORIZED\n  =\n  '0'",
    "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '\\x30'",
    "if (dev) process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'",
    "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0', other()",
  ])('matches %j', (src) => {
    expect(rules(src)).toEqual(['FF-TLS-001']);
  });

  it.each([
    ["comparison, not assignment", "if (process.env.NODE_TLS_REJECT_UNAUTHORIZED == '0') warn()"],
    ['strict comparison', "process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0'"],
    ['enabling it', "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1'"],
    ['a computed value', "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0' + suffix"],
    ['a fallback expression', "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0' || x"],
    ['a different variable', "process.env.NODE_TLS_REJECT_UNAUTHORIZED_X = '0'"],
    ['someone else’s process object', "worker.process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'"],
    ['a line comment', "// process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'"],
    ['a block comment', "/* never do: process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0' */"],
    ['a quoted example', "const doc = \"process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'\";"],
    ['a template example', "const doc = `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`;"],
    ['a regular expression', "const re = /process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'/;"],
    ['an alias (unsupported, documented)', "const env = process.env; env.NODE_TLS_REJECT_UNAUTHORIZED = '0'"],
  ])('does not match %s', (_name, src) => {
    expect(rules(src)).toEqual([]);
  });
});

describe('FF-TLS-002: rejectUnauthorized: false', () => {
  it.each([
    'https.request({ host, rejectUnauthorized: false })',
    "new https.Agent({ 'rejectUnauthorized': false })",
    'const opts = {\n  ca,\n  rejectUnauthorized:\n    false,\n}',
    'tls.connect(port, { rejectUnauthorized : false }, cb)',
    'agent.options.rejectUnauthorized = false;',
    "options['rejectUnauthorized'] = false",
    'this.rejectUnauthorized = false',
  ])('matches %j', (src) => {
    expect(rules(src)).toEqual(['FF-TLS-002']);
  });

  it.each([
    ['the safe value', '{ rejectUnauthorized: true }'],
    ['a runtime value', '{ rejectUnauthorized: !insecure }'],
    ['a ternary', 'const x = strict ? rejectUnauthorized : false'],
    ['a comparison', 'if (opts.rejectUnauthorized === false) log()'],
    ['a type annotation', 'interface O { rejectUnauthorized: boolean }'],
    ['a fallback', '{ rejectUnauthorized: false || x }'],
    ['a comment', '// rejectUnauthorized: false is insecure'],
    ['a string', "throw new Error('do not set rejectUnauthorized: false')"],
  ])('does not match %s', (_name, src) => {
    expect(rules(src)).toEqual([]);
  });
});

describe('locations and excerpts', () => {
  it('reports the exact start and end, 1-based', () => {
    const src = "import x from 'y';\n\n    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n";
    expect(first(src)).toMatchObject({ start: { line: 3, column: 5 }, end: { line: 3, column: 50 } });
  });

  it('spans lines for a multi-line statement', () => {
    const m = first('const o = {\n  rejectUnauthorized:\n    false }');
    expect(m).toMatchObject({ start: { line: 2, column: 3 }, end: { line: 3, column: 9 }, excerpt: 'rejectUnauthorized: false' });
  });

  it('counts CRLF as one line ending', () => {
    expect(first('a();\r\nb();\r\n{ rejectUnauthorized: false }')?.start).toEqual({ line: 3, column: 3 });
  });

  it('counts columns in UTF-16 code units after multi-byte characters', () => {
    expect(first("const s = '😀é'; process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0")?.start).toEqual({ line: 1, column: 18 });
  });

  it('rebuilds the excerpt from tokens: no comments, normalised spacing', () => {
    const m = first("process /* why */ .env\n  ['NODE_TLS_REJECT_UNAUTHORIZED']   =   '0'");
    expect(m?.excerpt).toBe("process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'");
  });

  it('keeps nothing else from the line (a secret next to it is not stored)', () => {
    const m = first("connect({ password: 'hunter2', rejectUnauthorized: false, token: 'abc' })");
    expect(m?.excerpt).toBe('rejectUnauthorized: false');
  });

  it('starts a member assignment at its object', () => {
    expect(first('client.agent.options.rejectUnauthorized = false')?.excerpt).toBe('client.agent.options.rejectUnauthorized = false');
  });

  it('finds several matches in source order, and caps them', () => {
    const src = Array.from({ length: 5 }, () => '{ rejectUnauthorized: false }').join('\n');
    expect(scanSource(src).matches.map((m) => m.start.line)).toEqual([1, 2, 3, 4, 5]);
    expect(scanSource(src, 3)).toMatchObject({ truncated: true, matches: [{}, {}, {}] });
  });
});

describe('tokenizer', () => {
  it('reads strings, templates, numbers and regexes as opaque tokens', () => {
    const kinds = tokenize('a = "s" + `t${x}` + 1.5e3 + /re[/]/g').map((t) => t.kind);
    expect(kinds).toEqual(['ident', 'punct', 'string', 'punct', 'template', 'punct', 'number', 'punct', 'regex']);
  });

  it('tells division from a regular expression', () => {
    expect(tokenize('a / b / c').filter((t) => t.kind === 'regex')).toEqual([]);
    expect(tokenize('return /x/').at(-1)?.kind).toBe('regex');
  });

  it('skips nested substitutions without losing its place', () => {
    const src = "`a ${ { b: `c ${'}'}` } } d`; { rejectUnauthorized: false }";
    expect(rules(src)).toEqual(['FF-TLS-002']);
  });

  it('never throws on malformed input and keeps scanning after it', () => {
    for (const src of ['"unterminated\n{ rejectUnauthorized: false }', '/* open comment', '`open template ${', "'\\", ' ﻿#!']) {
      expect(() => scanSource(src)).not.toThrow();
    }
    expect(rules('"unterminated\n{ rejectUnauthorized: false }')).toEqual(['FF-TLS-002']);
  });

  it('deeply nested templates are reported as unparsed, never a stack overflow', () => {
    const depth = 3000; // ~15 KB, far below the per-file size limit
    const nested = '`${'.repeat(depth) + '`' + '}`'.repeat(depth);
    let result: ReturnType<typeof scanSource> | undefined;
    expect(() => (result = scanSource(nested))).not.toThrow();
    expect(result).toEqual({ matches: [], truncated: false, unparsed: true });
  });

  it('ordinary nesting still parses, and code after it is checked', () => {
    const src = '`a ${`b ${`c ${x}`}`}`;\n{ rejectUnauthorized: false }';
    expect(scanSource(src)).toMatchObject({ unparsed: false, matches: [{ ruleId: 'FF-TLS-002', start: { line: 2 } }] });
  });

  it('skips a hashbang line', () => {
    expect(rules("#!/usr/bin/env node\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'")).toEqual(['FF-TLS-001']);
  });
});
