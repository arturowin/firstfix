import type { Ecosystem } from '../types.ts';
import { npmVersionScheme } from './version.ts';

export const npm: Ecosystem = {
  id: 'npm',
  label: 'npm',
  versionScheme: npmVersionScheme,
  hints: {
    upgradeCommand: (pkg, version) => `npm install ${pkg}@${version}`,
    ciChecks: ['Dependabot alerts', '`npm audit` in CI'],
  },
};
