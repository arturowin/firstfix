import { describe, expect, it } from 'vitest';
import { TemplateExplainer } from '../../src/adapters/template-explainer.ts';
import { explainPlan } from '../../src/application/explain.ts';
import { checkExplanation, explainInput, sourceFacts, type Explanation, type SourceFacts } from '../../src/domain/explanation.ts';
import { NO_SOURCE_COUNTS } from '../../src/domain/source-rules.ts';
import type { Explainer } from '../../src/ports/explainer.ts';

const signal = () => new AbortController().signal;
const counts = { ...NO_SOURCE_COUNTS, eligible: 12, checked: 12 };
const findings = [
  { ruleId: 'FF-TLS-002', path: 'test/agent.ts' },
  { ruleId: 'FF-TLS-002', path: 'src/client.ts' },
  { ruleId: 'FF-TLS-001', path: 'src/boot.ts' },
  { ruleId: 'FF-TLS-002', path: 'src/client.ts' },
];

describe('sourceFacts', () => {
  it('counts per rule, most severe first: matches, files, matches in test files; never paths or code', () => {
    const facts = sourceFacts({ status: 'complete', counts }, findings);
    expect(facts).toEqual({
      checkedFiles: 12,
      eligibleFiles: 12,
      partial: false,
      rules: [
        { ruleId: 'FF-TLS-001', title: 'TLS certificate verification disabled for the whole process', severity: 'high', matches: 1, files: 1, inTestFiles: 0 },
        { ruleId: 'FF-TLS-002', title: 'TLS certificate verification turned off for a client', severity: 'medium', matches: 3, files: 2, inTestFiles: 1 },
      ],
    });
    expect(JSON.stringify(facts)).not.toMatch(/src\/|test\//);
  });

  it('uses the recorded counts when only some examples were stored', () => {
    const recorded = { ...counts, rules: { 'FF-TLS-001': { matches: 1, files: 1, inTestFiles: 0 }, 'FF-TLS-002': { matches: 50, files: 3, inTestFiles: 40 } } };
    const facts = sourceFacts({ status: 'complete', counts: recorded }, [{ ruleId: 'FF-TLS-002', path: 'a.ts' }]);
    expect(facts?.rules.map((r) => [r.ruleId, r.matches, r.files, r.inTestFiles])).toEqual([
      ['FF-TLS-001', 1, 1, 0],
      ['FF-TLS-002', 50, 3, 40],
    ]);
  });

  it('nothing to explain when the check had no files or failed', () => {
    expect(sourceFacts({ status: 'no_files', counts }, [])).toBeNull();
    expect(sourceFacts({ status: 'failed', counts }, [])).toBeNull();
  });
});

const source = (rules: SourceFacts['rules']): SourceFacts => ({ checkedFiles: 12, eligibleFiles: 12, partial: false, rules });
const tls1 = { ruleId: 'FF-TLS-001', title: 't1', severity: 'high' as const, matches: 1, files: 1, inTestFiles: 0 };
const tls2 = { ruleId: 'FF-TLS-002', title: 't2', severity: 'medium' as const, matches: 3, files: 2, inTestFiles: 3 };
const noDeps = (src: SourceFacts | null) =>
  explainInput({ repo: 'o/r', summaryLine: 'x', checkedDeps: 0, totalDeps: 0, actions: [], dependenciesChecked: false, source: src });

describe('template explanations for source findings', () => {
  it.each([
    ['no lockfile, process-wide and client findings', noDeps(source([tls1, tls2]))],
    ['no lockfile, no matches', noDeps(source([]))],
    ['no lockfile, no source result', noDeps(null)],
    ['dependencies clean, process-wide finding', explainInput({ repo: 'o/r', summaryLine: 'x', checkedDeps: 3, totalDeps: 3, actions: [], source: source([tls1]) })],
  ])('passes the facts check: %s', async (_name, input) => {
    const out = await new TemplateExplainer().explain(input);
    expect(checkExplanation(input, out)).toEqual({ ok: true });
  });

  it('without a dependency check, never talks about dependency vulnerabilities; leads with the process-wide setting', async () => {
    const out = await new TemplateExplainer().explain(noDeps(source([tls1, tls2])));
    expect(out.summary).toMatch(/^Start with the process-wide TLS setting/);
    expect(out.summary).not.toMatch(/advisor|vulnerab|package/i);
  });

  it('says where matches are: all in test files', async () => {
    const out = await new TemplateExplainer().explain(noDeps(source([tls2])));
    expect(out.sourceRules).toEqual([{ ruleId: 'FF-TLS-002', whyItMatters: expect.stringMatching(/All 3 matches are in test files\.$/) as unknown }]);
  });

  it('a clean source check only says these checks found nothing', async () => {
    const out = await new TemplateExplainer().explain(noDeps(source([])));
    expect(out.summary).toMatch(/look only for disabled TLS certificate verification and found no match in the 12 JavaScript\/TypeScript files/);
  });
});

describe('the facts check on source rules', () => {
  const input = noDeps(source([tls1, tls2]));
  const R1 = { ruleId: 'FF-TLS-001', whyItMatters: 'Every connection accepts any certificate.' };
  const R2 = { ruleId: 'FF-TLS-002', whyItMatters: 'This client accepts any certificate.' };
  const good: Explanation = { summary: 'Turn certificate checks back on first.', actions: [], sourceRules: [R1, R2] };
  const withRule1 = (text: string): Explanation => ({ ...good, sourceRules: [{ ruleId: 'FF-TLS-001', whyItMatters: text }, R2] });

  it('accepts one entry per matched rule', () => {
    expect(checkExplanation(input, good)).toEqual({ ok: true });
  });

  it.each([
    ['a missing rule', { ...good, sourceRules: [R1] }, /missing source rule FF-TLS-002/],
    ['an unknown rule', { ...good, sourceRules: [R1, R2, { ruleId: 'FF-XSS-001', whyItMatters: 'x' }] }, /unknown source rule FF-XSS-001/],
    ['a safety claim', withRule1('Otherwise the app is secure.'), /claims safety/],
    ['a version', withRule1('Use TLS 1.3 instead.'), /version 1\.3/],
    ['a command', withRule1('Run `unset NODE_TLS_REJECT_UNAUTHORIZED`.'), /command/],
  ])('rejects %s', (_name, out: Explanation, problem) => {
    const r = checkExplanation(input, out);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.problems.join('; ')).toMatch(problem);
  });
});

describe('explainPlan with source facts', () => {
  const facts = { repo: 'o/r', summaryLine: 'x', checkedDeps: 0, totalDeps: 0, actions: [], dependenciesChecked: false, source: source([tls1, tls2]) };
  const ai = (out: Explanation): Explainer => ({ explain: () => Promise.resolve(out) });

  it('calls the AI even with no dependency actions, and uses its source-rule text when it passes the check', async () => {
    const stored = await explainPlan(
      {
        template: new TemplateExplainer(),
        ai: ai({
          summary: 'Turn certificate checks back on, starting with the process-wide one.',
          actions: [],
          sourceRules: [
            { ruleId: 'FF-TLS-001', whyItMatters: 'Every connection the program makes accepts any certificate.' },
            { ruleId: 'FF-TLS-002', whyItMatters: 'These clients accept any certificate; they are in tests.' },
          ],
        }),
        timeoutMs: 1000,
      },
      facts,
      signal(),
    );
    expect(stored.source).toBe('ai');
    expect(stored.sourceRules?.['FF-TLS-001']).toEqual({ text: 'Every connection the program makes accepts any certificate.', source: 'ai' });
  });

  it('an AI reply that skips a matched rule falls back to the template, with the reason', async () => {
    const stored = await explainPlan(
      { template: new TemplateExplainer(), ai: ai({ summary: 'Turn checks back on.', actions: [], sourceRules: [] }), timeoutMs: 1000 },
      facts,
      signal(),
    );
    expect(stored.source).toBe('template');
    expect(stored.fallbackReason).toMatch(/missing source rule FF-TLS-001/);
    expect(stored.sourceRules?.['FF-TLS-002']?.source).toBe('template');
  });
});
