/**
 * LLM providers by name. Adding one = an LlmClient adapter + one entry here; nothing else changes.
 * Configuration: LLM_PROVIDER (default "anthropic"), LLM_API_KEY, LLM_MODEL (default per provider),
 * LLM_TIMEOUT_MS. No key → no LLM: the template explains everything, by design.
 */
import { ANTHROPIC_DEFAULT_MODEL, AnthropicClient } from './anthropic.ts';
import type { LlmClient } from './client.ts';

interface ProviderEntry {
  defaultModel: string;
  create(options: { apiKey: string; model: string; timeoutMs: number }): LlmClient;
}

export const LLM_PROVIDERS: Record<string, ProviderEntry> = {
  anthropic: { defaultModel: ANTHROPIC_DEFAULT_MODEL, create: (o) => new AnthropicClient(o) },
};

export const DEFAULT_LLM_TIMEOUT_MS = 20_000;

export function llmClientFromEnv(env: Record<string, string | undefined>): LlmClient | null {
  const apiKey = env['LLM_API_KEY']?.trim();
  if (!apiKey) return null;
  const provider = env['LLM_PROVIDER']?.trim() || 'anthropic';
  const entry = LLM_PROVIDERS[provider];
  if (!entry) {
    // A typo in configuration should stop the worker, not silently disable explanations.
    throw new Error(`LLM_PROVIDER "${provider}" is not supported (supported: ${Object.keys(LLM_PROVIDERS).join(', ')})`);
  }
  return entry.create({
    apiKey,
    model: env['LLM_MODEL']?.trim() || entry.defaultModel,
    timeoutMs: llmTimeoutMs(env),
  });
}

export function llmTimeoutMs(env: Record<string, string | undefined>): number {
  const n = Number(env['LLM_TIMEOUT_MS']);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_LLM_TIMEOUT_MS;
}
