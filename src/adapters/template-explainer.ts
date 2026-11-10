/**
 * Deterministic explanations from facts only: the fallback whenever the LLM is missing, slow or wrong, and the
 * text for actions beyond the ones the LLM explains. Mentions no versions or advisory IDs (those are rendered
 * from data elsewhere) and never claims exposure, safety or a fix.
 */
import type { ActionFacts, ExplainInput, Explanation } from '../domain/explanation.ts';
import type { Explainer } from '../ports/explainer.ts';

const plural = (n: number, one: string, many = `${one}s`) => `${String(n)} ${n === 1 ? one : many}`;

export class TemplateExplainer implements Explainer {
  explain(input: ExplainInput): Promise<Explanation> {
    return Promise.resolve({
      summary: summary(input),
      actions: input.actions.map((a) => ({ actionId: a.actionId, whyItMatters: why(a) })),
    });
  }
}

function summary(input: ExplainInput): string {
  const first = input.actions[0];
  if (!first) {
    return input.checkedDeps === 0
      ? 'No dependency could be compared against advisory data, so this scan says nothing about known vulnerabilities.'
      : 'No advisory in the data used matches the dependency versions checked. New advisories are published over time, so a later rescan can differ.';
  }
  const malicious = input.actions.filter((a) => a.isMalicious).map((a) => a.package);
  const noFix = input.actions.filter((a) => a.kind === 'no_fix').length;
  const parts = [
    malicious.length === 1
      ? `Start with ${malicious[0] ?? ''}, a known malicious package: removing it and rotating secrets come before any upgrade.`
      : malicious.length > 1
        ? `Start with the known malicious packages (${malicious.slice(0, 3).join(', ')}${malicious.length > 3 ? ', …' : ''}): removing them and rotating secrets come before any upgrade.`
        : `Start with ${first.package}: it ranks first by severity and exposure.`,
  ];
  const upgrades = input.actions.filter((a) => a.kind === 'upgrade').length;
  if (upgrades > 0) parts.push(`${plural(upgrades, 'package')} ${upgrades === 1 ? 'has' : 'have'} a candidate version to try; each needs tests and a rescan to confirm.`);
  if (noFix > 0) parts.push(`${plural(noFix, 'package')} ${noFix === 1 ? 'has' : 'have'} no fixed version published and need a decision: replace, accept with mitigations, or wait.`);
  return parts.join(' ');
}

function why(a: ActionFacts): string {
  if (a.isMalicious) {
    return 'Known malicious code runs with the permissions of whatever installs or imports it, so credentials on those machines may have been exposed.';
  }
  const severity =
    a.severity === 'unknown'
      ? 'The advisory data gives no severity rating, so judge the impact from the advisory text.'
      : `Advisory data rates the worst issue here ${a.severity}.`;
  const exposure =
    a.scope === 'dev'
      ? 'It is a development dependency: it runs on developer machines and in CI rather than in production.'
      : 'It is installed at runtime, so it ships with the application.';
  const route = a.isDirect ? '' : ` It arrives through ${parents(a.directParents)}, so the change is usually made there.`;
  const jump = a.majorJump ? ' The suggested candidate crosses a major version, so expect breaking changes.' : '';
  return `${severity} ${exposure}${route}${jump}`;
}

function parents(names: string[]): string {
  if (names.length === 0) return 'another dependency';
  if (names.length <= 2) return names.join(' and ');
  return `${names.slice(0, 2).join(', ')} and ${plural(names.length - 2, 'other')}`;
}
