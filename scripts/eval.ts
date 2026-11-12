// `npm run eval`: runs the explainers over fixed scan fixtures (test/fixtures/eval/*.json) and checks the output.
// Hard checks (fail the run): the facts check every explanation must pass (exact action set, no versions or
// advisory IDs outside the scan data, length limits, no "secure"/"safe"/"fixed" claims) and no provider error.
// Soft signals (reported only): the summary names the first action's package; malicious actions don't talk
// about upgrading. Uses the LLM configured by LLM_PROVIDER / LLM_API_KEY / LLM_MODEL; without a key it runs the
// template only and says so. Every AI run costs a few cents.
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { LlmExplainer } from '../src/adapters/llm/explainer.ts';
import { llmClientFromEnv, llmTimeoutMs } from '../src/adapters/llm/registry.ts';
import { TemplateExplainer } from '../src/adapters/template-explainer.ts';
import { defaultRegistry } from '../src/domain/ecosystems/registry.ts';
import { checkExplanation, explainInput, type ExplainInput, type Explanation, type SourceFacts } from '../src/domain/explanation.ts';
import { buildFixPlan, type PlanFinding } from '../src/domain/fix-plan.ts';
import { summaryLine } from '../src/domain/report-text.ts';
import type { Explainer } from '../src/ports/explainer.ts';

interface Fixture {
  name: string;
  description: string;
  repo: string;
  checkedDeps: number;
  totalDeps: number;
  findings: PlanFinding[];
  /** False: the dependency check didn't run (e.g. lockfileVersion 1). Default true. */
  dependenciesChecked?: boolean;
  /** Source-check facts (rules and counts only), when the fixture covers them. */
  source?: SourceFacts;
}

interface Row {
  fixture: string;
  explainer: string;
  ok: boolean;
  ms: number;
  problems: string[];
  notes: string[];
  tokens?: string;
}

const dir = path.join(import.meta.dirname, '..', 'test', 'fixtures', 'eval');
const fixtures: Fixture[] = readdirSync(dir)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => JSON.parse(readFileSync(path.join(dir, f), 'utf8')) as Fixture);

const llm = llmClientFromEnv(process.env);
const ai = llm ? new LlmExplainer(llm) : null;
const explainers: [string, Explainer][] = [['template', new TemplateExplainer()]];
if (ai) explainers.push([ai.provider, ai]);
else console.log('No LLM_API_KEY: evaluating the template only.\n');

const rows: Row[] = [];
for (const fx of fixtures) {
  const plan = buildFixPlan(fx.findings, (e) => defaultRegistry.ecosystems.get(e)?.versionScheme ?? null);
  const line = summaryLine({ counts: fx, lockfilePath: 'package-lock.json', actions: plan });
  const facts = {
    repo: fx.repo,
    summaryLine: line,
    checkedDeps: fx.checkedDeps,
    totalDeps: fx.totalDeps,
    actions: plan,
    dependenciesChecked: fx.dependenciesChecked ?? true,
    source: fx.source ?? null,
  };

  for (const [name, explainer] of explainers) {
    const isAi = explainer === ai;
    // The pipeline explains every action with the template and the top ones with the AI; same here.
    const input = isAi ? explainInput(facts) : explainInput(facts, Infinity);
    if (isAi && input.actions.length === 0 && (input.source?.rules.length ?? 0) === 0) {
      rows.push({ fixture: fx.name, explainer: name, ok: true, ms: 0, problems: [], notes: ['not called: nothing to explain'] });
      continue;
    }
    const started = Date.now();
    const row: Row = { fixture: fx.name, explainer: name, ok: false, ms: 0, problems: [], notes: [] };
    try {
      const out = await explainer.explain(input, AbortSignal.timeout(llmTimeoutMs(process.env)));
      row.ms = Date.now() - started;
      const check = checkExplanation(input, out);
      row.ok = check.ok;
      if (!check.ok) row.problems = check.problems;
      row.notes = softSignals(input, out);
      if (explainer instanceof LlmExplainer && explainer.lastResult) {
        const { model, usage: u } = explainer.lastResult;
        row.tokens = `${model}${u ? ` in ${String(u.inputTokens)} / out ${String(u.outputTokens)}` : ''}`;
      }
    } catch (err) {
      row.ms = Date.now() - started;
      row.problems = [`error: ${err instanceof Error ? `${err.name}: ${err.message}` : String(err)}`];
    }
    rows.push(row);
  }
}

function softSignals(input: ExplainInput, out: Explanation): string[] {
  const notes: string[] = [];
  const first = input.actions[0];
  if (first && !out.summary.toLowerCase().includes(first.package.toLowerCase())) {
    notes.push(`summary doesn't name the first action (${first.package})`);
  }
  for (const a of input.actions.filter((x) => x.isMalicious)) {
    const why = out.actions.find((x) => x.actionId === a.actionId)?.whyItMatters ?? '';
    if (/\bupgrad/i.test(why)) notes.push(`${a.package}: malicious, but the text talks about upgrading`);
  }
  return notes;
}

for (const r of rows) {
  const status = r.ok ? 'PASS' : 'FAIL';
  console.log(`${status}  ${r.fixture.padEnd(16)} ${r.explainer.padEnd(28)} ${String(r.ms).padStart(6)} ms${r.tokens ? `  ${r.tokens}` : ''}`);
  for (const p of r.problems) console.log(`        ✗ ${p}`);
  for (const n of r.notes) console.log(`        · ${n}`);
}
const failed = rows.filter((r) => !r.ok).length;
console.log(`\n${String(rows.length - failed)}/${String(rows.length)} passed${failed > 0 ? ` (${String(failed)} failed)` : ''}.`);
process.exitCode = failed > 0 ? 1 : 0;
