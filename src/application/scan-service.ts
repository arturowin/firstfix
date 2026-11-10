import { createHash, randomUUID } from 'node:crypto';
import { parseRepoUrl } from '../domain/repo-url.ts';
import type { ReportData, ScanRepository, ScanView } from '../ports/scan-repository.ts';
import type { ScanSubmission, SubmitResult } from '../ports/scan-submission.ts';

export type SubmitOutcome = SubmitResult | { kind: 'invalid'; error: string };

/** API-side use cases. Validation of the repo URL lives in the domain; atomic create+enqueue in the port. */
export class ScanService {
  private readonly submission: ScanSubmission;
  private readonly scans: ScanRepository;
  private readonly newId: () => string;

  constructor(submission: ScanSubmission, scans: ScanRepository, newId: () => string = randomUUID) {
    this.submission = submission;
    this.scans = scans;
    this.newId = newId;
  }

  async submit(repoUrl: string, idempotencyKey: string | null): Promise<SubmitOutcome> {
    const parsed = parseRepoUrl(repoUrl);
    if (!parsed.ok) return { kind: 'invalid', error: parsed.error };
    const { repo } = parsed;
    // The request is identified by what it means, not how it was typed: equivalent URLs hash the same.
    const requestHash = createHash('sha256').update(JSON.stringify({ repoUrl: repo.url })).digest('hex');
    return this.submission.submit({
      scanId: this.newId(),
      repo,
      idempotency: idempotencyKey === null ? null : { key: idempotencyKey, requestHash },
    });
  }

  get(scanId: string): Promise<ScanView | null> {
    return this.scans.get(scanId);
  }

  getReport(scanId: string): Promise<ReportData | null> {
    return this.scans.getReport(scanId);
  }
}
