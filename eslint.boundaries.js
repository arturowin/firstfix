// Architectural import boundaries (CLAUDE.md rule 4). Kept separate so test/unit/boundaries.test.ts
// can lint sample code against exactly these rules.
import { builtinModules } from 'node:module';

const IO_LIBRARIES = ['pg', 'pg-boss'];

// LLM provider SDKs: only their own adapter may import them, so switching providers touches one file
// (src/adapters/llm/<provider>.ts) plus the registry.
const LLM_SDKS = ['@anthropic-ai/sdk', '@anthropic-ai/sdk/*'];
const LLM_SDK_MESSAGE = 'LLM SDKs are imported only by their provider adapter in src/adapters/llm/';

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
            { group: LLM_SDKS, message: LLM_SDK_MESSAGE },
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
          patterns: [
            { group: ['**/adapters/**'], message: 'application must depend on ports, not adapters' },
            { group: LLM_SDKS, message: LLM_SDK_MESSAGE },
          ],
        },
      ],
    },
  },
  {
    // Everywhere else (other adapters, entry points): no provider SDK outside its adapter.
    files: ['src/adapters/**/*.ts', 'src/api/**/*.ts', 'src/worker/**/*.ts', 'src/ports/**/*.ts', 'src/web/**/*.ts'],
    ignores: ['src/adapters/llm/anthropic.ts'],
    rules: {
      'no-restricted-imports': ['error', { patterns: [{ group: LLM_SDKS, message: LLM_SDK_MESSAGE }] }],
    },
  },
];
