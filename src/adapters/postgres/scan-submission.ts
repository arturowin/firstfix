import type pg from 'pg';
import type { PgBoss } from 'pg-boss';
import type { IdempotencyInput, ScanSubmission, SubmitResult } from '../../ports/scan-submission.ts';
import type { RepoRef } from '../../domain/repo-url.ts';
import { clientDb, SCAN_QUEUE, type ScanJobData } from '../pgboss/queue.ts';
import { inTransactionOrRollback, Rollback } from './pool.ts';

interface KeyRow {
  request_hash: string;
  scan_id: string;
}

function resultForExistingKey(row: KeyRow, idem: IdempotencyInput): SubmitResult {
  return row.request_hash === idem.requestHash ? { kind: 'existing', scanId: row.scan_id } : { kind: 'conflict' };
}

export class PostgresScanSubmission implements ScanSubmission {
  private readonly pool: pg.Pool;
  private readonly boss: PgBoss;

  constructor(pool: pg.Pool, boss: PgBoss) {
    this.pool = pool;
    this.boss = boss;
  }

  async submit(input: { scanId: string; repo: RepoRef; idempotency: IdempotencyInput | null }): Promise<SubmitResult> {
    const { scanId, repo, idempotency: idem } = input;

    const outcome = await inTransactionOrRollback<SubmitResult | null>(this.pool, async (client) => {
      if (idem) {
        const prior = await client.query<KeyRow>(
          'SELECT request_hash, scan_id FROM idempotency_keys WHERE key = $1',
          [idem.key],
        );
        const row = prior.rows[0];
        if (row) throw new Rollback(resultForExistingKey(row, idem));
      }

      await client.query(
        `INSERT INTO scans (id, repo_owner, repo_name, repo_url_normalized) VALUES ($1, $2, $3, $4)`,
        [scanId, repo.owner, repo.name, repo.url],
      );

      const data: ScanJobData = { scanId };
      const jobId = await this.boss.send(SCAN_QUEUE, data, { id: scanId, db: clientDb(client) });
      // send() returns null only when it dedupes; a scan must never exist without its job.
      if (jobId !== scanId) throw new Error(`job was not created for scan ${scanId} (send returned ${String(jobId)})`);

      if (idem) {
        // A concurrent request with the same key blocks here until the first commits, then inserts nothing.
        const inserted = await client.query(
          `INSERT INTO idempotency_keys (key, request_hash, scan_id) VALUES ($1, $2, $3)
           ON CONFLICT (key) DO NOTHING`,
          [idem.key, idem.requestHash, scanId],
        );
        if (inserted.rowCount === 0) throw new Rollback(null);
      }
      return { kind: 'created', scanId };
    });

    if (outcome !== null) return outcome;

    // Lost the race for this key: our scan and job were rolled back; answer with the winner's.
    if (!idem) throw new Error('unreachable: rollback without an idempotency key');
    const winner = await this.pool.query<KeyRow>('SELECT request_hash, scan_id FROM idempotency_keys WHERE key = $1', [
      idem.key,
    ]);
    const row = winner.rows[0];
    if (!row) throw new Error(`idempotency key ${idem.key} vanished after a conflict`);
    return resultForExistingKey(row, idem);
  }
}
