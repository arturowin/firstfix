import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import { boundaries } from './eslint.boundaries.js';

export default tseslint.config(
  { ignores: ['node_modules/', 'dist/', 'coverage/', 'eslint.config.js', 'eslint.boundaries.js', 'scripts/*.mjs'] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
    },
  },
  ...boundaries,
);
