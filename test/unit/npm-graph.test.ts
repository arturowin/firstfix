import { describe, expect, it } from 'vitest';
import { buildInstallGraph, MAX_PATH_SEGMENTS, PATH_ELLIPSIS } from '../../src/domain/ecosystems/npm/graph.ts';
import { parsePackageLock } from '../../src/domain/ecosystems/npm/package-lock.ts';
import type { LockedPackage } from '../../src/domain/lockfile.ts';

const v = (version: string, deps: Record<string, string> = {}, extra: object = {}) => ({ version, dependencies: deps, ...extra });

function parse(packages: Record<string, unknown>): LockedPackage[] {
  const r = parsePackageLock({ lockfileVersion: 3, packages });
  if (r.kind !== 'ok') throw new Error(r.reason);
  return r.packages;
}
const get = (pkgs: LockedPackage[], name: string, version: string) => pkgs.find((p) => p.name === name && p.version === version);

describe('npm install graph', () => {
  it('resolves nested first, then upwards (Node resolution); each version gets its own parents and paths', () => {
    const pkgs = parse({
      '': { dependencies: { express: '4', request: '2' } },
      'node_modules/express': v('4.17.1', { 'body-parser': '1', qs: '6.7.0' }),
      'node_modules/body-parser': v('1.19.0', { qs: '6.7.0' }),
      'node_modules/qs': v('6.7.0'),
      'node_modules/request': v('2.88.2', { qs: '~6.5.2' }),
      'node_modules/request/node_modules/qs': v('6.5.5'),
    });
    expect(get(pkgs, 'qs', '6.7.0')).toMatchObject({ isDirect: false, directParents: ['express'], installPaths: [['express', 'qs']] });
    expect(get(pkgs, 'qs', '6.5.5')).toMatchObject({ isDirect: false, directParents: ['request'], installPaths: [['request', 'qs']] });
    expect(get(pkgs, 'express', '4.17.1')).toMatchObject({ isDirect: true, directParents: [], installPaths: [['express']] });
  });

  it('a package pulled in by several direct dependencies names all of them; a direct one can also be transitive', () => {
    const pkgs = parse({
      '': { dependencies: { a: '1', b: '1', shared: '1' } },
      'node_modules/a': v('1.0.0', { mid: '1' }),
      'node_modules/b': v('1.0.0', { shared: '1' }),
      'node_modules/mid': v('1.0.0', { shared: '1' }),
      'node_modules/shared': v('1.0.0'),
    });
    expect(get(pkgs, 'shared', '1.0.0')).toEqual({
      name: 'shared',
      installedAs: [],
      directAs: ['shared'],
      contextTruncated: false,
      version: '1.0.0',
      scope: 'runtime',
      isDirect: true,
      directParents: ['a', 'b'],
      installPaths: [['shared'], ['b', 'shared'], ['a', 'mid', 'shared']],
    });
  });

  it('cycles terminate', () => {
    const pkgs = parse({
      '': { dependencies: { a: '1' } },
      'node_modules/a': v('1.0.0', { b: '1' }),
      'node_modules/b': v('1.0.0', { a: '1' }),
    });
    expect(get(pkgs, 'b', '1.0.0')).toMatchObject({ directParents: ['a'], installPaths: [['a', 'b']] });
    expect(get(pkgs, 'a', '1.0.0')).toMatchObject({ isDirect: true, directParents: [] }); // b is not direct
  });

  it('workspace declarations are direct; links into workspace folders are project code, not walked', () => {
    const pkgs = parse({
      '': { workspaces: ['packages/ws'], dependencies: { '@x/ws': '*' } },
      'node_modules/@x/ws': { resolved: 'packages/ws', link: true },
      'packages/ws': { name: '@x/ws', version: '0.1.0', dependencies: { c: '3' }, devDependencies: { d: '1' } },
      'packages/ws/node_modules/c': v('3.0.0', { e: '1' }),
      'node_modules/d': v('1.0.0', {}, { dev: true }),
      'node_modules/e': v('1.0.0'),
    });
    expect(get(pkgs, 'c', '3.0.0')).toMatchObject({ isDirect: true, directParents: [] });
    expect(get(pkgs, 'd', '1.0.0')).toMatchObject({ isDirect: true, scope: 'dev' });
    expect(get(pkgs, 'e', '1.0.0')).toMatchObject({ isDirect: false, directParents: ['c'], installPaths: [['c', 'e']] });
  });

  it('follows optional and peer dependencies of installed packages, not their devDependencies', () => {
    const pkgs = parse({
      '': { dependencies: { a: '1' } },
      'node_modules/a': { version: '1.0.0', optionalDependencies: { o: '1' }, peerDependencies: { p: '1' }, devDependencies: { x: '1' } },
      'node_modules/o': v('1.0.0', {}, { optional: true }),
      'node_modules/p': v('1.0.0'),
      'node_modules/x': v('1.0.0'), // extraneous here: nothing installs it
    });
    expect(get(pkgs, 'o', '1.0.0')?.directParents).toEqual(['a']);
    expect(get(pkgs, 'p', '1.0.0')?.directParents).toEqual(['a']);
    expect(get(pkgs, 'x', '1.0.0')).toMatchObject({ isDirect: false, directParents: [], installPaths: [] });
  });

  it('a peer the project provides itself is not "pulled in" by the package naming it (@eslint/js → eslint)', () => {
    const pkgs = parse({
      '': { devDependencies: { '@eslint/js': '10', eslint: '10' } },
      'node_modules/@eslint/js': { version: '10.0.1', dev: true, peerDependencies: { eslint: '^10.0.0' } },
      'node_modules/eslint': v('10.14.0', { minimatch: '^10.2.6' }, { dev: true }),
      'node_modules/minimatch': v('10.2.6', {}, { dev: true }),
    });
    expect(get(pkgs, 'minimatch', '10.2.6')).toMatchObject({ directParents: ['eslint'], installPaths: [['eslint', 'minimatch']] });
  });

  it('a peer npm installed only because of the package that names it still counts as pulled in by it', () => {
    const pkgs = parse({
      '': { dependencies: { plugin: '1' } },
      'node_modules/plugin': { version: '1.0.0', peerDependencies: { host: '1' } },
      'node_modules/host': v('1.0.0', { leaf: '1' }),
      'node_modules/leaf': v('1.0.0'),
    });
    expect(get(pkgs, 'leaf', '1.0.0')).toMatchObject({ directParents: ['plugin'], installPaths: [['plugin', 'host', 'leaf']] });
  });

  it('install paths are capped at five, shortest first; parents are complete', () => {
    const roots = ['r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7'];
    const pkgs = parse({
      '': { dependencies: Object.fromEntries(roots.map((r) => [r, '1'])) },
      ...Object.fromEntries(roots.map((r) => [`node_modules/${r}`, v('1.0.0', { leaf: '1' })])),
      'node_modules/leaf': v('1.0.0'),
    });
    const leaf = get(pkgs, 'leaf', '1.0.0');
    expect(leaf?.directParents).toEqual(roots);
    expect(leaf?.installPaths).toEqual(roots.slice(0, 5).map((r) => [r, 'leaf']));
  });

  it('an unresolvable dependency or a broken link is skipped', () => {
    const g = buildInstallGraph({
      '': { dependencies: { a: '1', gone: '1', l: '1' } },
      'node_modules/a': v('1.0.0', { missing: '1' }),
      'node_modules/l': { resolved: '../outside', link: true },
    });
    expect([...g.direct]).toEqual(['node_modules/a']);
  });
});

describe('npm install graph: bounded work and memory (review finding)', () => {
  // 300 direct dependencies all reaching one shared 300-package chain: a ~42 KB lockfile that used to build
  // ~90,000 path arrays (about 185 MiB of heap).
  const D = 300;
  const C = 300;
  const packages: Record<string, unknown> = {
    '': { dependencies: Object.fromEntries(Array.from({ length: D }, (_, i) => [`d${String(i)}`, '1'])) },
  };
  for (let i = 0; i < D; i++) packages[`node_modules/d${String(i)}`] = v('1.0.0', { c0: '1' });
  for (let i = 0; i < C; i++) packages[`node_modules/c${String(i)}`] = v('1.0.0', i + 1 < C ? { [`c${String(i + 1)}`]: '1' } : {});

  it('keeps at most 5 paths per location while walking, and every direct parent', () => {
    const g = buildInstallGraph(packages);
    expect(g.complete).toBe(true);
    const stored = [...g.reach.values()].reduce((n, r) => n + r.paths.length, 0);
    expect(stored).toBeLessThanOrEqual(5 * g.reach.size);
    const tail = g.reach.get(`node_modules/c${String(C - 1)}`);
    expect(tail?.parents.size).toBe(D);
    expect(tail?.paths).toHaveLength(5);
    // 301 segments deep: kept as root, ellipsis and the last 10, and flagged.
    expect(tail?.paths[0]).toHaveLength(MAX_PATH_SEGMENTS);
    expect(tail?.paths[0]?.[1]).toBe(PATH_ELLIPSIS);
    expect(tail?.truncated).toBe(true);
  });

  it('past the step budget, parents and paths are left empty rather than partly filled; direct stays complete', () => {
    const g = buildInstallGraph(packages, () => false, 1000);
    expect(g.complete).toBe(false);
    expect([...g.reach.values()].every((r) => r.parents.size === 0 && r.paths.length === 0)).toBe(true);
    expect(g.direct.size).toBe(D);
  });
});

describe('deep chains: path work and memory bounded through the normal parse (review finding)', () => {
  // One direct dependency, then a chain of 3,999 edges (~270 KB lockfile): full paths retained ~8,000,000
  // entries (~265 MiB). Paths are now capped while building, and the cut is explicit.
  const N = 4000;
  const packages: Record<string, unknown> = { '': { dependencies: { c0: '1' } } };
  for (let i = 0; i < N; i++) packages[`node_modules/c${String(i)}`] = v('1.0.0', i + 1 < N ? { [`c${String(i + 1)}`]: '1' } : {});

  it('every stored path is at most MAX_PATH_SEGMENTS long; deep packages are flagged, shallow ones are not', () => {
    const r = parsePackageLock({ lockfileVersion: 3, packages });
    if (r.kind !== 'ok') throw new Error(r.kind);
    const entries = r.packages.reduce((n, p) => n + p.installPaths.reduce((m, x) => m + x.length, 0), 0);
    expect(entries).toBeLessThanOrEqual(N * MAX_PATH_SEGMENTS);
    expect(r.packages.every((p) => p.installPaths.every((x) => x.length <= MAX_PATH_SEGMENTS))).toBe(true);

    const deepest = r.packages.find((p) => p.name === `c${String(N - 1)}`);
    expect(deepest).toMatchObject({ isDirect: false, directParents: ['c0'], contextTruncated: true });
    expect(deepest?.installPaths[0]).toEqual(['c0', PATH_ELLIPSIS, ...Array.from({ length: 10 }, (_, i) => `c${String(N - 10 + i)}`)]);

    const shallow = r.packages.find((p) => p.name === 'c5');
    expect(shallow).toMatchObject({ contextTruncated: false, installPaths: [['c0', 'c1', 'c2', 'c3', 'c4', 'c5']] });
  });
});
