/**
 * How adapters report failures, so the pipeline can decide without knowing HTTP:
 * - TransientError: worth retrying (timeouts, 5xx, rate limits). The pipeline throws so pg-boss retries.
 * - PermanentError: retrying cannot help. The pipeline records the outcome and returns normally.
 */
export class TransientError extends Error {
  readonly code: string;
  constructor(code: string, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'TransientError';
    this.code = code;
  }
}

export type PermanentOutcome = 'failed' | 'unsupported';

export class PermanentError extends Error {
  readonly code: string;
  /** What the scan becomes: `unsupported` (nothing we can check) or `failed`. */
  readonly outcome: PermanentOutcome;
  constructor(code: string, message: string, outcome: PermanentOutcome = 'failed', options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'PermanentError';
    this.code = code;
    this.outcome = outcome;
  }
}
