import { randomUUID } from 'node:crypto';
import pg from 'pg';

export interface TestDatabase {
  url: string;
  drop: () => Promise<void>;
}

export function testDatabaseUrl(): string {
  const url = process.env['DATABASE_URL'];
  if (!url) throw new Error('Set DATABASE_URL to a local PostgreSQL instance before running integration tests.');
  return url;
}

/** Creates a throwaway database next to DATABASE_URL so tests never touch real data. */
export async function createTestDatabase(): Promise<TestDatabase> {
  const base = new URL(testDatabaseUrl());
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
