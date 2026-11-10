import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { parsePackageLock as parseLockfile, packageLockFormat } from '../../src/domain/ecosystems/npm/package-lock.ts';
import type { LockedPackage } from '../../src/domain/lockfile.ts';

const demo: unknown = JSON.parse(
  readFileSync(path.join(import.meta.dirname, '..', 'fixtures', 'lockfiles', 'demo.package-lock.json'), 'utf8'),
);

function lock(packages: Record<string, unknown>, lockfileVersion: unknown = 3): unknown {
  return { name: 'x', lockfileVersion, packages };
}

const reg = (name: string, version: string) => `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`;

describe('parseLockfile', () => {
  it('lockfileVersion 1 → unsupported', () => {
    expect(parseLockfile(lock({}, 1))).toEqual({
      kind: 'unsupported',
      reason: 'lockfileVersion 1 is not supported (only 2 and 3, written by npm 7 or later)',
    });
  });

  it('missing lockfileVersion → unsupported', () => {
    expect(parseLockfile({ packages: {} })).toEqual({ kind: 'unsupported', reason: 'package-lock.json has no lockfileVersion' });
  });

  it('accepts version 2 and 3; zero dependencies is ok', () => {
    for (const v of [2, 3]) {
      expect(parseLockfile(lock({ '': { name: 'x' } }, v))).toEqual({ kind: 'ok', packages: [], uncheckable: [] });
    }
  });

  it('rejects non-objects and a missing packages section', () => {
    expect(parseLockfile('nope').kind).toBe('unsupported');
    expect(parseLockfile({ lockfileVersion: 3 })).toEqual({
      kind: 'unsupported',
      reason: 'package-lock.json has no "packages" section',
    });
  });

  it('only node_modules/ keys are dependencies; name comes from the last segment', () => {
    const r = parseLockfile(
      lock({
        '': { dependencies: { a: '1' } },
        'packages/ws': { name: '@x/ws', version: '0.1.0' }, // workspace folder: not a dependency
        'node_modules/a': { version: '1.0.0', resolved: reg('a', '1.0.0') },
        'node_modules/a/node_modules/@s/b': { version: '2.0.0', resolved: reg('b', '2.0.0') },
        'packages/ws/node_modules/c': { version: '3.0.0', resolved: reg('c', '3.0.0') },
      }),
    );
    expect(r.kind === 'ok' && r.packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      '@s/b@2.0.0',
      'a@1.0.0',
      'c@3.0.0',
    ]);
  });

  it('skips links into the project’s own workspaces', () => {
    const r = parseLockfile(
      lock({
        '': { workspaces: ['packages/*'] },
        'packages/ws': { name: '@x/ws', version: '0.1.0' },
        'node_modules/@x/ws': { resolved: 'packages/ws', link: true },
      }),
    );
    expect(r).toEqual({ kind: 'ok', packages: [], uncheckable: [] });
  });

  it('a file: link (real npm 10 lockfile) is a dependency we can’t check, not a workspace', () => {
    const fileLink = parseLockfile(
      JSON.parse(readFileSync(path.join(import.meta.dirname, '..', 'fixtures', 'lockfiles', 'file-link.package-lock.json'), 'utf8')),
    );
    // Review reproduction: this used to come back with zero packages and zero unchecked entries.
    expect(fileLink).toEqual({
      kind: 'ok',
      packages: [],
      uncheckable: [{ name: 'local-lib', version: '2.0.0', reason: 'unsupported_source' }],
    });
  });

  it('a link to a folder inside the repo that isn’t a declared workspace is also unchecked', () => {
    const r = parseLockfile(
      lock({
        '': { workspaces: ['packages/*'] },
        'vendor/x': { name: 'x', version: '1.0.0' },
        'node_modules/x': { resolved: 'vendor/x', link: true },
      }),
    );
    expect(r.kind === 'ok' && r.uncheckable).toEqual([{ name: 'x', version: '1.0.0', reason: 'unsupported_source' }]);
  });

  it('non-registry sources are uncheckable; a missing resolved is tolerated', () => {
    const r = parseLockfile(
      lock({
        'node_modules/g': { version: '1.0.0', resolved: 'git+ssh://git@github.com/o/g.git#abc' },
        'node_modules/f': { version: '1.0.0', resolved: 'file:../f' },
        'node_modules/t': { version: '1.0.0', resolved: 'https://example.com/t-1.0.0.tgz' },
        'node_modules/m': { version: '0.1.1' },
      }),
    );
    expect(r).toEqual({
      kind: 'ok',
      packages: [{ name: 'm', installedAs: [], directAs: [], contextTruncated: false, version: '0.1.1', scope: 'runtime', isDirect: false, directParents: [], installPaths: [] }],
      uncheckable: [
        { name: 'f', version: '1.0.0', reason: 'unsupported_source' },
        { name: 'g', version: '1.0.0', reason: 'unsupported_source' },
        { name: 't', version: '1.0.0', reason: 'unsupported_source' },
      ],
    });
  });

  it('scope: dev / devOptional → dev, optional → optional, otherwise runtime', () => {
    const r = parseLockfile(
      lock({
        'node_modules/d': { version: '1.0.0', dev: true },
        'node_modules/do': { version: '1.0.0', devOptional: true },
        'node_modules/o': { version: '1.0.0', optional: true },
        'node_modules/r': { version: '1.0.0' },
      }),
    );
    expect(r.kind === 'ok' && Object.fromEntries(r.packages.map((p) => [p.name, p.scope]))).toEqual({
      d: 'dev',
      do: 'dev',
      o: 'optional',
      r: 'runtime',
    });
  });

  it('dedupes name@version, keeping the most exposed scope and direct if any location is direct', () => {
    const r = parseLockfile(
      lock({
        '': { devDependencies: { q: '1' } },
        'node_modules/q': { version: '1.0.0', dev: true },
        'node_modules/x/node_modules/q': { version: '1.0.0' },
        'node_modules/y/node_modules/q': { version: '2.0.0' },
      }),
    );
    expect(r.kind === 'ok' && r.packages.map(({ name, version, scope, isDirect }) => ({ name, version, scope, isDirect }))).toEqual([
      { name: 'q', version: '1.0.0', scope: 'runtime', isDirect: true },
      { name: 'q', version: '2.0.0', scope: 'runtime', isDirect: false },
    ]);
  });

  it('a top-level package not listed by the root is transitive', () => {
    const r = parseLockfile(lock({ '': {}, 'node_modules/hoisted': { version: '1.0.0' } }));
    expect(r.kind === 'ok' && r.packages[0]?.isDirect).toBe(false);
  });

  describe('npm aliases (real lockfile from npm 10: "my-lodash": "npm:lodash@4.17.20")', () => {
    const r = parseLockfile(
      JSON.parse(readFileSync(path.join(import.meta.dirname, '..', 'fixtures', 'lockfiles', 'alias.package-lock.json'), 'utf8')),
    );

    it('queries the real package name, keeping the alias it is installed under', () => {
      expect(r.kind === 'ok' && r.packages.map((p) => [p.name, p.version, p.installedAs, p.directAs])).toEqual([
        ['lodash', '4.17.20', ['my-lodash'], ['my-lodash']],
        ['lodash', '4.17.21', [], ['lodash']],
      ]);
    });

    it('the same version installed under both names lists both', () => {
      const both = parseLockfile(
        lock({
          '': { dependencies: { lodash: '4.17.20', 'my-lodash': 'npm:lodash@4.17.20' } },
          'node_modules/lodash': { version: '4.17.20', resolved: reg('lodash', '4.17.20') },
          'node_modules/my-lodash': { name: 'lodash', version: '4.17.20', resolved: reg('lodash', '4.17.20') },
        }),
      );
      expect(both.kind === 'ok' && both.packages).toMatchObject([
        { name: 'lodash', installedAs: ['lodash', 'my-lodash'], directAs: ['lodash', 'my-lodash'] },
      ]);
    });

    it('a transitive alias is not a direct declaration', () => {
      const r2 = parseLockfile(
        lock({
          '': { dependencies: { first: 'npm:lodash@4.17.20', a: '1' } },
          'node_modules/first': { name: 'lodash', version: '4.17.20', resolved: reg('lodash', '4.17.20') },
          'node_modules/a': { version: '1.0.0', resolved: reg('a', '1.0.0'), dependencies: { second: 'npm:lodash@4.17.20' } },
          'node_modules/a/node_modules/second': { name: 'lodash', version: '4.17.20', resolved: reg('lodash', '4.17.20') },
        }),
      );
      expect(r2.kind === 'ok' && r2.packages.find((p) => p.name === 'lodash')).toMatchObject({
        installedAs: ['first', 'second'],
        directAs: ['first'],
        directParents: ['a'],
      });
    });
  });

  describe('as a registered lockfile format', () => {
    it('is the npm package-lock.json format', () => {
      expect(packageLockFormat).toMatchObject({ ecosystem: 'npm', fileNames: ['package-lock.json'] });
    });

    it('parses text; invalid JSON is "invalid", not "unsupported"', () => {
      expect(packageLockFormat.parse('{not json')).toEqual({ kind: 'invalid', reason: 'package-lock.json is not valid JSON' });
      expect(packageLockFormat.parse(JSON.stringify(lock({}, 1))).kind).toBe('unsupported');
      expect(packageLockFormat.parse(JSON.stringify(lock({ 'node_modules/a': { version: '1.0.0' } })))).toMatchObject({
        kind: 'ok',
        packages: [{ name: 'a', version: '1.0.0' }],
      });
    });
  });

  describe('demo fixture repo lockfile', () => {
    const r = parseLockfile(demo);
    if (r.kind !== 'ok') throw new Error('demo lockfile should parse');
    const find = (name: string, version: string): LockedPackage | undefined =>
      r.packages.find((p) => p.name === name && p.version === version);

    it('finds every planned case', () => {
      expect(find('lodash', '4.17.20')).toMatchObject({ isDirect: true, scope: 'runtime' });
      expect(find('qs', '6.7.0')).toMatchObject({ isDirect: false, scope: 'runtime' });
      expect(find('qs', '6.5.5')).toMatchObject({ isDirect: false });
      expect(find('postcss', '7.0.35')).toMatchObject({ isDirect: true });
      expect(find('request', '2.88.2')).toMatchObject({ isDirect: true });
      expect(find('minimist', '1.2.0')).toMatchObject({ isDirect: true, scope: 'dev' });
      expect(find('flatmap-stream', '0.1.1')).toMatchObject({ isDirect: true, scope: 'runtime' });
      // Who pulls the transitive ones in, and how.
      expect(find('qs', '6.7.0')).toMatchObject({ directParents: ['express'], installPaths: [['express', 'qs']] });
      expect(find('qs', '6.5.5')).toMatchObject({ directParents: ['request'], installPaths: [['request', 'qs']] });
    });

    it('skips the workspace link and folder, and marks the git dependency uncheckable', () => {
      expect(r.packages.some((p) => p.name.includes('internal-utils'))).toBe(false);
      expect(r.uncheckable).toEqual([{ name: 'slash', version: '5.1.0', reason: 'unsupported_source' }]);
    });

    it('every transitive package is reached from some direct dependency', () => {
      expect(r.packages.filter((p) => !p.isDirect && p.directParents.length === 0)).toEqual([]);
    });

    it('counts: 106 checkable package versions', () => {
      // 110 package entries: root "", the workspace folder, its link, the git dependency, 105 registry
      // entries + flatmap-stream (no resolved). An early manual OSV query counted 107 because it wrongly
      // included the workspace folder.
      expect(r.packages).toHaveLength(106);
    });
  });
});
