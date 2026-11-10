import pg from 'pg';
import { DEFAULT_URL } from './db.ts';

/** Integration and contract tests need Postgres; fail once, clearly, instead of in every file. */
export default async function setup(): Promise<void> {
  const url = process.env['DATABASE_URL'] ?? DEFAULT_URL;
  const client = new pg.Client({ connectionString: url, connectionTimeoutMillis: 3000 });
  try {
    await client.connect();
    await client.query('SELECT 1');
  } catch (err) {
    // ECONNREFUSED arrives as an AggregateError with an empty message; its code is the useful part.
    const reason = (err as { code?: string }).code ?? (err instanceof Error ? err.message : String(err));
    throw new Error(
      `Tests need Postgres at ${url.replace(/:[^:@/]+@/, ':***@')} (${reason}).\n` +
        'Start it with `docker compose up -d postgres`, or set DATABASE_URL.',
      { cause: err },
    );
  } finally {
    await client.end().catch(() => undefined);
  }
}
