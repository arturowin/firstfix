import type pg from 'pg';
import type { Db, PgBoss, Queue } from 'pg-boss';

export const SCAN_QUEUE = 'scan';
export const SCAN_DEAD_LETTER_QUEUE = 'scan-dead-letter';

export interface ScanJobData {
  scanId: string;
}

/** Verified in M0 (test/contract/pgboss.test.ts); rationale in docs/ARCHITECTURE.md "Queue settings". */
export const SCAN_QUEUE_OPTIONS: Omit<Queue, 'name'> = {
  heartbeatSeconds: 30,
  expireInSeconds: 300,
  retryLimit: 3,
  retryDelay: 5,
  retryBackoff: true,
  retryDelayMax: 60,
  deadLetter: SCAN_DEAD_LETTER_QUEUE,
};

/** Idempotent: safe to call from both processes on every start. */
export async function ensureQueues(boss: PgBoss): Promise<void> {
  if (!(await boss.getQueue(SCAN_DEAD_LETTER_QUEUE))) await boss.createQueue(SCAN_DEAD_LETTER_QUEUE);
  if (await boss.getQueue(SCAN_QUEUE)) {
    await boss.updateQueue(SCAN_QUEUE, SCAN_QUEUE_OPTIONS);
  } else {
    await boss.createQueue(SCAN_QUEUE, SCAN_QUEUE_OPTIONS);
  }
}

/** Lets pg-boss run its statements on our client, inside our open transaction. */
export function clientDb(client: pg.PoolClient): Db {
  return {
    executeSql: async (text, values) => {
      const res = await client.query(text, values);
      return { rows: res.rows };
    },
  };
}
