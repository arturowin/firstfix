// Architectural import boundaries (CLAUDE.md rule 4). Kept separate so test/unit/boundaries.test.ts
// can lint sample code against exactly these rules.
import { builtinModules } from 'node:module';

const IO_LIBRARIES = ['pg', 'pg-boss'];

// Every Node built-in, both bare ('fs', 'fs/promises') and prefixed ('node:fs').
const nodeBuiltins = builtinModules.filter((m) => !m.startsWith('_'));

export const boundaries = [
  {
    // Domain code is pure: no I/O, no adapters, no application services.
    files: ['src/domain/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [...nodeBuiltins, ...IO_LIBRARIES].map((name) => ({
            name,
            message: 'domain code is pure: no I/O modules',
          })),
          patterns: [
            { group: ['node:*'], message: 'domain code is pure: no I/O modules' },
            { group: ['**/adapters/**', '**/application/**'], message: 'domain must not import adapters or application' },
          ],
        },
      ],
    },
  },
  {
    // application/ talks to the outside world only through ports.
    files: ['src/application/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: IO_LIBRARIES.map((name) => ({ name, message: 'application must use ports, not I/O libraries' })),
          patterns: [{ group: ['**/adapters/**'], message: 'application must depend on ports, not adapters' }],
        },
      ],
    },
  },
];
