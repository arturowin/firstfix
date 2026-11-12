/**
 * Deterministic explanations from facts only: the fallback whenever the LLM is missing, slow or wrong, and the
 * text for actions beyond the ones the LLM explains. Mentions no versions or advisory IDs (those are rendered
 * from data elsewhere) and never claims exposure, safety or a fix.
 */
import { MAX_SUMMARY_CHARS, MAX_WHY_CHARS, type ActionFacts, type ExplainInput, type Explanation, type SourceFacts, type SourceRuleFacts } from '../domain/explanation.ts';
import { SOURCE_RULES } from '../domain/source-rules.ts';
import type { Explainer } from '../ports/explainer.ts';

const plural = (n: number, one: string, many = `${one}s`) => `${String(n)} ${n === 1 ? one : many}`;

export class TemplateExplainer implements Explainer {
  explain(input: ExplainInput): Promise<Explanation> {
    return Promise.resolve({
      summary: summary(input),
      actions: input.actions.map((a) => ({ actionId: a.actionId, whyItMatters: why(a) })),
      sourceRules: (input.source?.rules ?? []).map((r) => ({ ruleId: r.ruleId, whyItMatters: ruleWhy(r) })),
    });
  }
}

/** The dependency part first (as before source checks), then what the source checks found. */
function summary(input: ExplainInput): string {
  const source = input.source;
  const sourceText = source ? sourceSentence(source) : null;
  if (!input.dependenciesChecked) {
    const opening = sourceText ?? 'Dependencies were not checked for this commit, and no source check result is available.';
    return fit([opening], ['Dependencies were not checked for this commit; the report lists the reason.'], MAX_SUMMARY_CHARS);
  }
  const deps = dependencySummary(input);
  // The source sentence leads when it is the more urgent finding (process-wide TLS off) and dependencies are clean.
  const urgent = source?.rules.some((r) => r.severity === 'high') === true && input.actions.length === 0;
  if (sourceText && urgent) return fit([sourceText], [deps], MAX_SUMMARY_CHARS);
  return sourceText ? fit([deps], [sourceText], MAX_SUMMARY_CHARS) : deps;
}

function sourceSentence(source: SourceFacts): string {
  const scope = plural(source.checkedFiles, 'JavaScript/TypeScript file');
  if (source.rules.length === 0) {
    return `The source checks look only for disabled TLS certificate verification and found no match in the ${scope} checked.`;
  }
  const matches = source.rules.reduce((n, r) => n + r.matches, 0);
  const inTests = source.rules.reduce((n, r) => n + r.inTestFiles, 0);
  const processWide = source.rules.some((r) => r.ruleId === 'FF-TLS-001');
  const lead = processWide
    ? 'Start with the process-wide TLS setting: it turns off certificate checks for every connection the program makes.'
    : `The source checks found ${plural(matches, 'place')} where TLS certificate verification is turned off for a client.`;
  const tests = inTests === matches ? ' All of them are in test files.' : inTests > 0 ? ` ${String(inTests)} of them are in test files.` : '';
  return `${lead}${processWide ? '' : tests}`;
}

/** Why a matched source rule matters: the rule's own explanation, plus where the matches are. */
function ruleWhy(r: SourceRuleFacts): string {
  const base = SOURCE_RULES.find((x) => x.id === r.ruleId)?.explanation ?? 'A source check matched this code; review it in context.';
  const where =
    r.inTestFiles === r.matches
      ? `All ${plural(r.matches, 'match', 'matches')} are in test files.`
      : r.inTestFiles > 0
        ? `${String(r.inTestFiles)} of ${plural(r.matches, 'match', 'matches')} are in test files.`
        : `${plural(r.matches, 'match', 'matches')} in ${plural(r.files, 'file')}.`;
  return fit([base], [where], MAX_WHY_CHARS);
}

function dependencySummary(input: ExplainInput): string {
  const first = input.actions[0];
  if (!first) {
    return input.checkedDeps === 0
      ? 'No dependency could be compared against advisory data, so this scan says nothing about known vulnerabilities.'
      : 'No advisory in the data used matches the dependency versions checked. New advisories are published over time, so a later rescan can differ.';
  }
  const malicious = input.actions.filter((a) => a.isMalicious).map((a) => a.package);
  const noFix = input.actions.filter((a) => a.kind === 'no_fix').length;
  const upgrades = input.actions.filter((a) => a.kind === 'upgrade').length;

  // First sentence, most specific version first; generic wording if package names make it too long.
  const opening = [
    malicious.length === 1
      ? `Start with ${malicious[0] ?? ''}, a known malicious package: removing it and rotating secrets come before any upgrade.`
      : malicious.length > 1
        ? `Start with the known malicious packages (${malicious.slice(0, 3).join(', ')}${malicious.length > 3 ? ', …' : ''}): removing them and rotating secrets come before any upgrade.`
        : `Start with ${first.package}: it ranks first by severity and position in the dependency tree.`,
    malicious.length > 0
      ? 'Start with the known malicious packages: removing them and rotating secrets come before any upgrade.'
      : 'Start with the first action: it ranks first by severity and position in the dependency tree.',
  ];
  const rest: string[] = [];
  if (upgrades > 0) rest.push(`${plural(upgrades, 'package')} ${upgrades === 1 ? 'has' : 'have'} a candidate version to try; each needs tests and a rescan to confirm.`);
  if (noFix > 0) rest.push(`${plural(noFix, 'package')} ${noFix === 1 ? 'has' : 'have'} no fixed version published and ${noFix === 1 ? 'needs' : 'need'} a decision: replace, accept with mitigations, or wait.`);
  return fit(opening, rest, MAX_SUMMARY_CHARS);
}

/** Lockfile scope is what the scan observed; deployment and execution were not assessed. */
const SCOPE_TEXT: Record<ActionFacts['scope'], string> = {
  runtime: "Marked as a runtime dependency in the lockfile; whether the application deploys or executes it wasn't assessed.",
  optional: "Marked as an optional runtime dependency in the lockfile; whether it is installed or executed wasn't assessed.",
  dev: "Marked as a development dependency in the lockfile; it may affect developer or CI environments. Production exposure wasn't assessed.",
};

function why(a: ActionFacts): string {
  if (a.isMalicious) {
    return 'Known malicious code runs with the permissions of whatever installs or imports it, so credentials on those machines may have been exposed.';
  }
  const severity =
    a.severity === 'unknown'
      ? 'The advisory data gives no severity rating, so judge the impact from the advisory text.'
      : `Advisory data rates the worst issue here ${a.severity}.`;
  const optional: string[] = [];
  if (!a.isDirect) optional.push(`It arrives through ${parents(a.directParents)}, so the change is usually made there.`);
  if (a.majorJump) optional.push('The suggested candidate crosses a major version, so expect breaking changes.');
  return fit([`${severity} ${SCOPE_TEXT[a.scope]}`, SCOPE_TEXT[a.scope]], optional, MAX_WHY_CHARS);
}

/**
 * The first opening that fits, plus as many of the optional sentences (in order) as still fit. Package names
 * have no length bound we control, so the text is bounded here rather than trusted to be short.
 */
function fit(openings: string[], optional: string[], max: number): string {
  const opening = openings.find((o) => o.length <= max) ?? openings[openings.length - 1]?.slice(0, max) ?? '';
  let text = opening;
  for (const sentence of optional) {
    if (text.length + 1 + sentence.length <= max) text = `${text} ${sentence}`;
  }
  return text;
}
function parents(names: string[]): string {
  if (names.length === 0) return 'another dependency';
  if (names.length <= 2) return names.join(' and ');
  return `${names.slice(0, 2).join(', ')} and ${plural(names.length - 2, 'other')}`;
}
