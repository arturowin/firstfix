import { randomUUID } from 'node:crypto';
import pg from 'pg';

export interface TestDatabase {
  url: string;
  drop: () => Promise<void>;
}

export const DEFAULT_URL = 'postgres://scan:scan@localhost:5432/scan';

/** Creates a throwaway database next to DATABASE_URL so tests never touch real data. */
export async function createTestDatabase(): Promise<TestDatabase> {
  const base = new URL(process.env['DATABASE_URL'] ?? DEFAULT_URL);
  const name = `test_${randomUUID().replaceAll('-', '')}`;

  const admin = new pg.Client({ connectionString: base.toString() });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${name}`);
  } finally {
    await admin.end();
  }

  const url = new URL(base);
  url.pathname = `/${name}`;

  return {
    url: url.toString(),
    drop: async () => {
      const c = new pg.Client({ connectionString: base.toString() });
      await c.connect();
      try {
        await c.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      } finally {
        await c.end();
      }
    },
  };
}
