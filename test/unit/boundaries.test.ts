import { ESLint } from 'eslint';
import tseslint from 'typescript-eslint';
import { describe, expect, it } from 'vitest';
// @ts-expect-error -- plain JS config module, no type declarations
import { boundaries } from '../../eslint.boundaries.js';

const eslint = new ESLint({
  cwd: process.cwd(),
  overrideConfigFile: true,
  // Syntax-only parse: these checks need no type information.
  overrideConfig: [{ files: ['**/*.ts'], languageOptions: { parser: tseslint.parser } }, ...(boundaries as [])],
});

async function violations(filePath: string, code: string): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath });
  return (result?.messages ?? []).map((m) => m.ruleId ?? m.message);
}

describe('import boundaries', () => {
  it.each([
    "import fs from 'fs';",
    "import { readFile } from 'fs/promises';",
    "import fs from 'node:fs';",
    "import http from 'node:http';",
    "import pg from 'pg';",
    "import { PgBoss } from 'pg-boss';",
    "import { x } from '../adapters/osv/client.ts';",
    "import { x } from '../application/scan-service.ts';",
  ])('domain rejects: %s', async (code) => {
    expect(await violations('src/domain/sample.ts', code)).toEqual(['no-restricted-imports']);
  });

  it('domain allows pure imports', async () => {
    expect(await violations('src/domain/sample.ts', "import { rank } from './ranking.ts';")).toEqual([]);
  });

  it.each([
    "import pg from 'pg';",
    "import { PgBoss } from 'pg-boss';",
    "import { x } from '../adapters/postgres/scan-repository.ts';",
  ])('application rejects: %s', async (code) => {
    expect(await violations('src/application/sample.ts', code)).toEqual(['no-restricted-imports']);
  });

  it('application allows ports and domain', async () => {
    const code = "import type { ScanRepository } from '../ports/scan-repository.ts';\nimport { rank } from '../domain/ranking.ts';";
    expect(await violations('src/application/sample.ts', code)).toEqual([]);
  });

  it('adapters may use I/O', async () => {
    expect(await violations('src/adapters/sample.ts', "import pg from 'pg';")).toEqual([]);
  });
});
