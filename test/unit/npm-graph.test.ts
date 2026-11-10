import { describe, expect, it } from 'vitest';
import { buildInstallGraph } from '../../src/domain/ecosystems/npm/graph.ts';
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
