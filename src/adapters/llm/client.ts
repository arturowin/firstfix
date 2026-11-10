/**
 * The provider seam for LLM calls. Everything provider-specific (SDK, request shape, error types, structured
 * output mechanism) lives in one adapter per provider (e.g. anthropic.ts); prompts, schemas and validation live
 * in provider-neutral code (explainer.ts). Every client passes test/contract/llm-client.contract.ts.
 */
import type { z } from 'zod';

export interface LlmRequest<T> {
  system: string;
  user: string;
  /** The JSON the model must return; the client asks the provider for it and validates it. */
  schema: z.ZodType<T>;
  maxOutputTokens: number;
  signal: AbortSignal;
}

export interface LlmClient {
  /** e.g. "anthropic"; shown by `npm run eval`. */
  readonly provider: string;
  readonly model: string;
  /** Resolves with schema-valid output or rejects with an LlmError. Never retries on its own. */
  generate<T>(request: LlmRequest<T>): Promise<LlmResult<T>>;
}

export interface LlmResult<T> {
  output: T;
  /** The model that answered (may differ from the requested one if the provider fell back). */
  model: string;
  usage: { inputTokens: number; outputTokens: number } | null;
}

export type LlmErrorKind =
  | 'timeout'
  | 'aborted'
  | 'rate_limited'
  | 'unavailable'
  | 'auth'
  | 'bad_request'
  | 'refused'
  | 'invalid_output';

/** Provider errors mapped to neutral kinds, so nothing above the adapter sees an SDK's error types. */
export class LlmError extends Error {
  readonly kind: LlmErrorKind;

  constructor(kind: LlmErrorKind, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'LlmError';
    this.kind = kind;
  }
}
