/**
 * Coding-agent handoff prompt (docs/ARCHITECTURE.md "Coding-agent handoff prompt"). Facts, candidate changes and
 * instructions are built from a template, never by AI. When the scan's explanations were AI-written (and passed
 * the facts check), they are added as a marked context section that ranks below the facts.
 */
import type { RemediationHints } from './ecosystems/types.ts';
import type { Action } from './fix-plan.ts';
import { actionId } from './explanation.ts';
import { describeAction } from './report-text.ts';

export interface PromptInput {
  repoUrl: string;
  commitSha: string;
  lockfilePath: string;
  advisorySource: string;
  scannedAt: string;
  actions: readonly Action[];
  hintsFor: (ecosystem: string) => RemediationHints | null;
  /**
   * AI-written context, only when the scan's explanations came from the AI and passed the facts check:
   * the summary paragraph and "why it matters" per action id. Added as a marked section; null → no section,
   * and the prompt is fully template-built.
   */
  aiContext?: { summary: string; actions: Readonly<Record<string, string>> } | null;
}

/** Large plans are cut here; the prompt says how many were left out. */
export const PROMPT_MAX_ACTIONS = 20;

/** The AI context, marked as such and ranked below the facts. Empty without AI explanations. */
function contextSection(input: PromptInput, shown: readonly Action[]): string[] {
  const ctx = input.aiContext;
  if (!ctx) return [];
  const why = shown.flatMap((a) => {
    const text = ctx.actions[actionId(a)];
    return text ? [`- ${a.package}: ${text}`] : [];
  });
  return [
    '',
    '## Context (AI-written, checked against the scan data; where it differs from the facts below, the facts win)',
    ctx.summary,
    ...(why.length > 0 ? ['', ...why] : []),
  ];
}

export function buildAgentPrompt(input: PromptInput): string | null {
  if (input.actions.length === 0) return null;
  const shown = input.actions.slice(0, PROMPT_MAX_ACTIONS);
  const hidden = input.actions.length - shown.length;
  const anyHints = shown.map((a) => input.hintsFor(a.ecosystem)).find((h) => h !== null) ?? null;

  const facts = shown.flatMap((a) => [
    `${String(a.rank)}. ${a.package} (${a.ecosystem})${a.isMalicious ? ': KNOWN MALICIOUS' : ''}`,
    ...a.versions.flatMap((v) => [
      `   - installed ${v.installedVersion}, ${v.scope}, ${v.isDirect ? 'direct' : `via ${v.directParents.join(', ') || 'unknown parent'}`}`,
      ...v.advisories.map((adv) => `     - ${adv.id} (${adv.severity})${adv.title ? `: ${adv.title}` : ''}`),
    ]),
  ]);

  const changes = shown.flatMap((a) => {
    const hints = input.hintsFor(a.ecosystem);
    if (!hints) return [`${String(a.rank)}. ${a.package}: see the advisories; no version guidance for ${a.ecosystem}.`];
    const text = describeAction(a, hints);
    return [`${String(a.rank)}. ${text.headline}`, ...text.steps.map((s) => `   - ${s}`), `   - Verify: ${text.verify}`];
  });

  const lines = [
    `You are working in ${input.repoUrl} at commit ${input.commitSha}.`,
    `A dependency scan of ${input.lockfilePath} (advisory data: ${input.advisorySource}, ${input.scannedAt}) found the issues below.`,
    'Candidate versions come from advisory data. They are not confirmed fixes: compatibility, resolution and tests are still to verify.',
    ...contextSection(input, shown),
    '',
    '## Facts from the scan',
    ...facts,
    '',
    '## Candidate changes (verify each one)',
    ...changes,
    ...(hidden > 0 ? ['', `${String(hidden)} more ${hidden === 1 ? 'package is' : 'packages are'} in the full report; handle the ones above first.`] : []),
    '',
    '## How to work',
    `- Inspect the dependency graph first${anyHints ? ` (e.g. \`${anyHints.inspectCommand('<package>')}\`)` : ''} to see what pulls each package in.`,
    '- Change only what is listed here. Keep unrelated changes out of this work.',
    ...(anyHints
      ? [
          `- For a direct dependency, use \`${anyHints.upgradeCommand('<package>', '<version>')}\`. For a transitive one, upgrade the direct dependency that pulls it in; if that is not possible, use ${anyHints.transitiveFix}.`,
        ]
      : []),
    '- If a candidate is a major-version jump, stop and report before making that change.',
    '- Known malicious packages: remove them, do not upgrade them, and list the secrets that may have been exposed.',
    '- Run the test suite after the changes.',
    '- Rescan the repository afterwards. Report what is still unresolved, including advisories with no fixed version published.',
  ];
  return lines.join('\n');
}
