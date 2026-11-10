/**
 * Explanation with fallback (docs/ARCHITECTURE.md "Evidence vs AI text"). The template explains every action;
 * the AI explainer, when configured, explains the summary and the top actions. AI output is used only if it
 * arrives in time and passes the facts check; otherwise the template's text stands. Never fails a scan.
 */
import { checkExplanation, explainInput, type StoredExplanation } from '../domain/explanation.ts';
import type { Action } from '../domain/fix-plan.ts';
import type { Explainer } from '../ports/explainer.ts';

export interface ExplainDeps {
  /** Null when no LLM is configured (no key): the template is used, by design. */
  ai: Explainer | null;
  template: Explainer;
  /** Upper bound on the AI call, on top of whatever the adapter enforces. */
  timeoutMs: number;
}

export async function explainPlan(
  deps: ExplainDeps,
  facts: { repo: string; summaryLine: string; checkedDeps: number; totalDeps: number; actions: readonly Action[] },
  signal: AbortSignal,
): Promise<StoredExplanation> {
  const all = explainInput(facts, Infinity);
  const template = await deps.template.explain(all, signal);
  const templateCheck = checkExplanation(all, template);
  if (!templateCheck.ok) throw new Error(`template explanation failed its own check: ${templateCheck.problems.join('; ')}`);

  const stored: StoredExplanation = {
    source: 'template',
    summary: template.summary,
    actions: Object.fromEntries(template.actions.map((a) => [a.actionId, { text: a.whyItMatters, source: 'template' as const }])),
  };
  // Nothing to explain beyond the clean-result wording: no AI call.
  if (!deps.ai || all.actions.length === 0) return stored;

  const input = explainInput(facts);
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(deps.timeoutMs)]);
  let reason: string;
  try {
    const out = await withDeadline(deps.ai.explain(input, deadline), deadline);
    const check = checkExplanation(input, out);
    if (check.ok) {
      stored.source = 'ai';
      stored.summary = out.summary;
      for (const a of out.actions) stored.actions[a.actionId] = { text: a.whyItMatters, source: 'ai' };
      return stored;
    }
    reason = `failed the facts check: ${check.problems.slice(0, 5).join('; ')}`;
  } catch (err) {
    // The job itself was stopped (claim lost, shutdown): stop, don't fall back.
    if (signal.aborted) throw signal.reason;
    reason = deadline.aborted ? `no answer within ${String(deps.timeoutMs)} ms` : `error: ${describe(err)}`;
  }
  stored.fallbackReason = reason;
  return stored;
}

/** Resolves or rejects with `work`, but rejects as soon as `signal` aborts, even if `work` ignores the signal. */
function withDeadline<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      reject(signal.reason instanceof Error ? signal.reason : new Error('aborted'));
    };
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener('abort', onAbort, { once: true });
    work.then(
      (v) => {
        signal.removeEventListener('abort', onAbort);
        resolve(v);
      },
      (e: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(e instanceof Error ? e : new Error(String(e)));
      },
    );
  });
}

function describe(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`.slice(0, 300);
  return String(err).slice(0, 300);
}
