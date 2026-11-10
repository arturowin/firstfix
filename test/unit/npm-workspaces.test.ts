import { describe, expect, it } from 'vitest';
import { parsePackageLock } from '../../src/domain/ecosystems/npm/package-lock.ts';
import { workspaceMatcher } from '../../src/domain/ecosystems/npm/workspaces.ts';

const timed = <T>(fn: () => T): { value: T; ms: number } => {
  const t = performance.now();
  const value = fn();
  return { value, ms: performance.now() - t };
};

describe('workspace globs', () => {
  it.each([
    // exact paths and `*` within one segment
    [['packages/ws'], 'packages/ws', true],
    [['packages/ws'], 'packages/wsx', false],
    [['packages/*'], 'packages/ws', true],
    [['packages/*'], 'packages/a/b', false],
    [['packages/ui-*'], 'packages/ui-kit', true],
    [['packages/ui-*'], 'packages/core', false],
    [['packages/*-plugin'], 'packages/eslint-plugin', true],
    // `**` across segments, including zero segments
    [['packages/**'], 'packages/a/b', true],
    [['packages/**'], 'packages', true],
    [['apps/**/web'], 'apps/web', true],
    [['apps/**/web'], 'apps/x/y/web', true],
    [['apps/**/web'], 'apps/x/y/api', false],
    // normalisation and both declaration shapes
    [['./apps/web/'], 'apps/web', true],
    [{ packages: ['libs/*'] }, 'libs/x', true],
    [{ packages: 'libs/*' }, 'libs/x', false],
    // outside the repository: never a workspace, whatever the pattern
    [['packages/*'], '../local', false],
    [['*'], '../local', false],
    [['**'], '../local', false],
    [['**'], 'packages/../../x', false],
    [['**'], '', false],
    [[], 'packages/ws', false],
    [undefined, 'packages/ws', false],
  ])('%j matches %j → %s', (workspaces, location, expected) => {
    expect(workspaceMatcher({ workspaces })(location)).toBe(expected);
  });
});

describe('workspace globs: bounded work on untrusted patterns (review finding)', () => {
  it('the crafted backtracking pattern is answered at once', () => {
    // Review reproduction: as a regex this ran past a 1.2 s deadline.
    const { value, ms } = timed(() => workspaceMatcher({ workspaces: ['*a'.repeat(18) + 'b'] })('a'.repeat(36)));
    expect(value).toBe(false);
    expect(ms).toBeLessThan(100);
  });

  it('total work across many crafted patterns and many locations stays bounded', () => {
    const matcher = workspaceMatcher({ workspaces: Array.from({ length: 1000 }, () => '*a'.repeat(400) + 'b') });
    const { ms } = timed(() => {
      for (let i = 0; i < 2000; i++) matcher(`packages/${'a'.repeat(900)}${String(i)}`);
    });
    expect(ms).toBeLessThan(1500);
  });

  it('a location asked about repeatedly is matched once (cached), so repeats cost no budget', () => {
    // An expensive pattern before the real one: matching the same location again must not re-spend budget,
    // or the 3000th repeat would run the budget out and flip the answer.
    const matcher = workspaceMatcher({ workspaces: ['*a'.repeat(30) + 'b', 'packages/*'] });
    const location = `packages/${'a'.repeat(60)}`;
    const repeats = timed(() => Array.from({ length: 3000 }, () => matcher(location)));
    expect(repeats.value.every((v) => v)).toBe(true);
    expect(repeats.ms).toBeLessThan(100);
  });
});

describe('workspace globs: memory bounded before allocation (review finding)', () => {
  // ~1 KB pattern (~512 segments) against ~200 KB paths (~100,000 segments): the full table was ~51 MB per
  // uncached path, allocated even after the budget was spent.
  const pattern = 'a/'.repeat(512).slice(0, 1023);
  const bigPath = (c: string) => `${c}/`.repeat(100_000).slice(0, 199_999);

  it('a huge pattern x path is refused before allocating; later uncached paths allocate nothing either', () => {
    const matcher = workspaceMatcher({ workspaces: [pattern] });
    const before = process.memoryUsage().arrayBuffers;
    expect(matcher(bigPath('x'))).toBe(false);
    expect(matcher(bigPath('y'))).toBe(false);
    expect(process.memoryUsage().arrayBuffers - before).toBeLessThan(4 * 1024 * 1024);
  });

  it('normal wildcard matching is unchanged by the rolling rows', () => {
    const m = workspaceMatcher({ workspaces: ['apps/**/web', 'packages/ui-*', 'libs/*/src'] });
    expect([m('apps/web'), m('apps/a/b/web'), m('packages/ui-kit'), m('libs/x/src'), m('libs/x/y/src'), m('apps/web/x')]).toEqual([
      true,
      true,
      true,
      true,
      false,
      false,
    ]);
  });

  it('when matching can’t finish within the budget, the link stays visible as unchecked', () => {
    const target = bigPath('w');
    const r = parsePackageLock({
      lockfileVersion: 3,
      packages: {
        '': { workspaces: [pattern, '**'] },
        [target]: { name: 'huge-ws', version: '1.0.0' },
        'node_modules/huge-ws': { resolved: target, link: true },
      },
    });
    expect(r.kind === 'ok' && r.uncheckable).toEqual([{ name: 'huge-ws', version: '1.0.0', reason: 'unsupported_source' }]);
  });
});

describe('workspace links vs local file: dependencies', () => {
  const lockWith = (workspaces: unknown) =>
    parsePackageLock({
      lockfileVersion: 3,
      packages: {
        '': { workspaces, dependencies: { '@x/ws': '*', 'local-lib': 'file:../local' } },
        'packages/ws': { name: '@x/ws', version: '0.1.0' },
        '../local': { name: 'local-lib', version: '2.0.0' },
        'node_modules/@x/ws': { resolved: 'packages/ws', link: true },
        'node_modules/local-lib': { resolved: '../local', link: true },
      },
    });

  it('a link into a declared workspace is project code; a file: dependency is reported unchecked', () => {
    for (const shape of [['packages/*'], { packages: ['packages/*'] }]) {
      expect(lockWith(shape)).toEqual({
        kind: 'ok',
        packages: [],
        uncheckable: [{ name: 'local-lib', version: '2.0.0', reason: 'unsupported_source' }],
      });
    }
  });

  it('a pattern that would cover ../ can’t turn a file: dependency into a workspace', () => {
    const r = lockWith(['**', '../*', '*']);
    expect(r.kind === 'ok' && r.uncheckable).toEqual([{ name: 'local-lib', version: '2.0.0', reason: 'unsupported_source' }]);
  });

  it('when the work budget runs out, links are reported as unchecked dependencies, never hidden', () => {
    // 1000 expensive patterns ahead of the real one: the budget is spent before `packages/*` is tried.
    const target = `packages/${'a'.repeat(1000)}`;
    const r = parsePackageLock({
      lockfileVersion: 3,
      packages: {
        '': { workspaces: [...Array.from({ length: 1000 }, () => '*a'.repeat(500) + 'b'), 'packages/*'] },
        [target]: { name: 'big-ws', version: '1.0.0' },
        'node_modules/big-ws': { resolved: target, link: true },
      },
    });
    expect(r.kind === 'ok' && r.uncheckable).toEqual([{ name: 'big-ws', version: '1.0.0', reason: 'unsupported_source' }]);
  });
});
