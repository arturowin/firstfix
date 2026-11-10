import type { Ecosystem } from '../types.ts';

export const npm: Ecosystem = {
  id: 'npm',
  label: 'npm',
  hints: {
    upgradeCommand: (pkg, version) => `npm install ${pkg}@${version}`,
    ciChecks: ['Dependabot alerts', '`npm audit` in CI'],
  },
};
