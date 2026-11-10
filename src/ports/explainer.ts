import type { ExplainInput, Explanation } from '../domain/explanation.ts';

/**
 * Writes the two pieces of prose in a report: a summary paragraph and a "why it matters" line per action.
 * Facts (IDs, versions, severity, steps) are never taken from it. Implementations: a deterministic template,
 * and an LLM explainer whose provider sits behind its own client interface (src/adapters/llm/).
 * Any output is checked against the facts before use (domain/explanation.ts); a failure falls back to the template.
 */
export interface Explainer {
  explain(input: ExplainInput, signal: AbortSignal): Promise<Explanation>;
}
