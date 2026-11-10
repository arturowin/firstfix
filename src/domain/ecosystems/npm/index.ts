import type { Ecosystem } from '../types.ts';
import { npmVersionScheme } from './version.ts';

export const npm: Ecosystem = {
  id: 'npm',
  label: 'npm',
  versionScheme: npmVersionScheme,
  hints: {
    upgradeCommand: (pkg, version, alias) =>
      alias === undefined || alias === pkg ? `npm install ${pkg}@${version}` : `npm install ${alias}@npm:${pkg}@${version}`,
    inspectCommand: (pkg) => `npm ls ${pkg}`,
    transitiveFix: 'an `overrides` entry in package.json',
    ciChecks: ['Dependabot alerts', '`npm audit` in CI'],
  },
};
