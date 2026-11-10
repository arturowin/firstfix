/**
 * Anthropic provider for LlmClient: the only file that imports the Anthropic SDK.
 * Structured output via `messages.parse` + a zod output format, so the reply is schema-valid JSON.
 * Server-side refusal fallback is on (the provider re-runs a declined request on another model); a refusal
 * that still comes back is reported as `refused`, and the caller falls back to the template.
 */
import Anthropic from '@anthropic-ai/sdk';
import { betaZodOutputFormat } from '@anthropic-ai/sdk/helpers/beta/zod';
import { LlmError, type LlmClient, type LlmRequest, type LlmResult } from './client.ts';

export interface AnthropicOptions {
  apiKey: string;
  model: string;
  /** Per-request HTTP timeout; the caller's own deadline usually ends things first. */
  timeoutMs: number;
  /** For tests: point the SDK at a mock server. */
  baseURL?: string;
}

export const ANTHROPIC_DEFAULT_MODEL = 'claude-opus-5-5';

export class AnthropicClient implements LlmClient {
  readonly provider = 'anthropic';
  readonly model: string;
  private readonly client: Anthropic;
  private readonly timeoutMs: number;

  constructor(options: AnthropicOptions) {
    this.model = options.model;
    this.timeoutMs = options.timeoutMs;
    // No SDK retries: a slow or failing explanation falls back to the template instead of making the scan wait.
    this.client = new Anthropic({
      apiKey: options.apiKey,
      maxRetries: 0,
      timeout: options.timeoutMs,
      ...(options.baseURL ? { baseURL: options.baseURL } : {}),
    });
  }

  async generate<T>(req: LlmRequest<T>): Promise<LlmResult<T>> {
    let res;
    try {
      res = await this.client.beta.messages.parse(
        {
          model: this.model,
          max_tokens: req.maxOutputTokens,
          system: req.system,
          messages: [{ role: 'user', content: req.user }],
          // A short, bounded writing task: low effort keeps latency and cost down.
          output_config: { effort: 'low', format: betaZodOutputFormat(req.schema) },
          betas: ['server-side-fallback-2026-07-01'],
          fallbacks: 'default',
        },
        { signal: req.signal, timeout: this.timeoutMs },
      );
    } catch (err) {
      throw toLlmError(err);
    }
    if (res.stop_reason === 'refusal') throw new LlmError('refused', 'the model declined the request');
    if (res.stop_reason === 'max_tokens') throw new LlmError('invalid_output', 'the reply was cut off at max_tokens');
    if (res.parsed_output === null) throw new LlmError('invalid_output', 'the reply did not match the schema');
    return {
      output: res.parsed_output,
      model: res.model,
      usage: { inputTokens: res.usage.input_tokens, outputTokens: res.usage.output_tokens },
    };
  }
}

function toLlmError(err: unknown): LlmError {
  const cause = { cause: err };
  if (err instanceof Anthropic.APIUserAbortError) return new LlmError('aborted', 'request aborted', cause);
  if (err instanceof Anthropic.APIConnectionTimeoutError) return new LlmError('timeout', 'request timed out', cause);
  if (err instanceof Anthropic.APIConnectionError) return new LlmError('unavailable', 'could not reach the provider', cause);
  if (err instanceof Anthropic.RateLimitError) return new LlmError('rate_limited', 'rate limited', cause);
  if (err instanceof Anthropic.AuthenticationError || err instanceof Anthropic.PermissionDeniedError) {
    return new LlmError('auth', 'the API key was rejected', cause);
  }
  if (err instanceof Anthropic.BadRequestError || err instanceof Anthropic.NotFoundError || err instanceof Anthropic.UnprocessableEntityError) {
    return new LlmError('bad_request', `request rejected: ${err.message}`, cause);
  }
  if (err instanceof Anthropic.APIError) {
    return new LlmError('unavailable', `provider answered ${String(err.status ?? 'without a status')}`, cause);
  }
  // The SDK's parser throws when the reply isn't valid JSON for the schema.
  if (err instanceof Anthropic.AnthropicError) return new LlmError('invalid_output', err.message, cause);
  return new LlmError('invalid_output', err instanceof Error ? err.message : String(err), cause);
}
