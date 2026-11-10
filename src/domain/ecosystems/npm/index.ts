import type { Ecosystem } from '../types.ts';
import semver from 'semver';
import { isValidNpmName } from './name.ts';
import { npmVersionScheme } from './version.ts';

export const npm: Ecosystem = {
  id: 'npm',
  label: 'npm',
  versionScheme: npmVersionScheme,
  hints: {
    // Names and versions are validated again here (defence in depth): the parser already rejects invalid
    // names, and versions come from advisory data, but nothing unvalidated goes into a command.
    upgradeCommand: (pkg, version, alias) => {
      if (!isValidNpmName(pkg) || semver.valid(version) !== version) return null;
      if (alias === undefined || alias === pkg) return `npm install ${pkg}@${version}`;
      return isValidNpmName(alias) ? `npm install ${alias}@npm:${pkg}@${version}` : null;
    },
    inspectCommand: (pkg) => (isValidNpmName(pkg) ? `npm ls ${pkg}` : null),
    upgradeTemplate: 'npm install <package>@<version>',
    inspectTemplate: 'npm ls <package>',
    transitiveFix: 'an `overrides` entry in package.json',
    ciChecks: ['Dependabot alerts', '`npm audit` in CI'],
  },
};
