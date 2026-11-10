import type { PgBoss } from 'pg-boss';
import type { JobQueue, ScanJobState } from '../../ports/job-queue.ts';
import { SCAN_QUEUE } from './queue.ts';

/** pg-boss 12 states → what the sweeper needs. findJobs by id verified in M0. */
export class PgBossJobQueue implements JobQueue {
  private readonly boss: PgBoss;

  constructor(boss: PgBoss) {
    this.boss = boss;
  }

  async scanJobState(scanId: string): Promise<ScanJobState> {
    const [job] = await this.boss.findJobs(SCAN_QUEUE, { id: scanId });
    if (!job) return 'missing';
    switch (job.state) {
      case 'completed':
      case 'failed':
      case 'cancelled':
        return 'finished';
      case 'active':
        return 'active';
      default:
        // created, retry, and any state a future pg-boss adds: assume it may still run.
        return 'pending';
    }
  }
}
