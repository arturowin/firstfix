/**
 * The LLM provider contract (src/adapters/llm/client.ts). Every LlmClient adapter runs this suite against its
 * provider's HTTP shape, through a harness that knows how to make the provider answer. Expectations are
 * provider-neutral: schema-valid output, and every failure mapped to a neutral LlmError kind.
 */
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { LlmError, type LlmClient, type LlmErrorKind } from '../../src/adapters/llm/client.ts';

export interface LlmContractHarness {
  create(options?: { timeoutMs?: number }): LlmClient;
  /** The provider replies with this value as its structured (JSON) output. */
  serveOutput(value: unknown): void;
  /** The provider replies with text that is not JSON. */
  serveText(text: string): void;
  serveRefusal(): void;
  /** The reply was cut off by the output-token limit. */
  serveTruncated(): void;
  serveStatus(status: 400 | 401 | 429 | 500 | 529): void;
  serveNetworkError(): void;
  serveSlow(ms: number): void;
  /** System and user text of the last request the provider received. */
  lastPrompt(): { system: string; user: string } | null;
}

const Schema = z.object({ summary: z.string(), actions: z.array(z.object({ actionId: z.string(), whyItMatters: z.string() })) });
const valid = { summary: 'Start with lodash.', actions: [{ actionId: 'npm:lodash', whyItMatters: 'Runtime dependency.' }] };

export function llmClientContract(provider: string, harness: LlmContractHarness): void {
  const request = (signal = new AbortController().signal) => ({
    system: 'SYSTEM PROMPT',
    user: 'USER DATA',
    schema: Schema,
    maxOutputTokens: 1000,
    signal,
  });

  async function kindOf(p: Promise<unknown>): Promise<LlmErrorKind | 'resolved' | 'other'> {
    try {
      await p;
      return 'resolved';
    } catch (err) {
      return err instanceof LlmError ? err.kind : 'other';
    }
  }

  describe(`LlmClient contract: ${provider}`, () => {
    it('returns schema-valid output with the answering model and usage; sends the prompt unchanged', async () => {
      harness.serveOutput(valid);
      const res = await harness.create().generate(request());
      expect(res.output).toEqual(valid);
      expect(res.model).toEqual(expect.any(String));
      expect(res.usage).toEqual({ inputTokens: expect.any(Number) as number, outputTokens: expect.any(Number) as number });
      expect(harness.lastPrompt()).toEqual({ system: 'SYSTEM PROMPT', user: 'USER DATA' });
    });

    it.each([
      ['JSON of the wrong shape', () => {
        harness.serveOutput({ summary: 42 });
      }, 'invalid_output'],
      ['text that is not JSON', () => {
        harness.serveText('Sure! Here is the explanation: ...');
      }, 'invalid_output'],
      ['a cut-off reply', () => {
        harness.serveTruncated();
      }, 'invalid_output'],
      ['a refusal', () => {
        harness.serveRefusal();
      }, 'refused'],
      ['400', () => {
        harness.serveStatus(400);
      }, 'bad_request'],
      ['401', () => {
        harness.serveStatus(401);
      }, 'auth'],
      ['429', () => {
        harness.serveStatus(429);
      }, 'rate_limited'],
      ['500', () => {
        harness.serveStatus(500);
      }, 'unavailable'],
      ['529 overloaded', () => {
        harness.serveStatus(529);
      }, 'unavailable'],
      ['a network error', () => {
        harness.serveNetworkError();
      }, 'unavailable'],
    ] as const)('%s → LlmError %s (never a provider error type)', async (_l, serve, kind) => {
      serve();
      expect(await kindOf(harness.create().generate(request()))).toBe(kind);
    });

    it('a slow provider → timeout', async () => {
      harness.serveSlow(2000);
      expect(await kindOf(harness.create({ timeoutMs: 100 }).generate(request()))).toBe('timeout');
    });

    it('the caller’s abort → aborted', async () => {
      harness.serveSlow(2000);
      const ctl = new AbortController();
      const pending = harness.create().generate(request(ctl.signal));
      setTimeout(() => {
        ctl.abort();
      }, 50);
      expect(await kindOf(pending)).toBe('aborted');
    });
  });
}
