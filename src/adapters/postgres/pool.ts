import pg from 'pg';

export function createPool(connectionString: string): pg.Pool {
  const pool = new pg.Pool({ connectionString, max: 10 });
  // An idle client erroring (e.g. Postgres restart) must not crash the process; the next query reconnects.
  pool.on('error', (err) => {
    console.error('postgres pool error', err.message);
  });
  return pool;
}

/**
 * Runs fn in a transaction on one client. Rolls back on error; a client whose ROLLBACK fails is destroyed
 * instead of being returned to the pool. The original error always propagates.
 */
export async function inTransaction<T>(pool: pg.Pool, fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  let broken: Error | undefined;
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      broken = rollbackErr instanceof Error ? rollbackErr : new Error(String(rollbackErr));
    }
    throw err;
  } finally {
    client.release(broken);
  }
}

/** Thrown inside inTransaction to roll back on purpose and hand a value back to the caller. */
export class Rollback<T> extends Error {
  readonly value: T;
  constructor(value: T) {
    super('rollback');
    this.value = value;
  }
}

export async function inTransactionOrRollback<T>(
  pool: pg.Pool,
  fn: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  try {
    return await inTransaction(pool, fn);
  } catch (err) {
    if (err instanceof Rollback) return err.value as T;
    throw err;
  }
}
