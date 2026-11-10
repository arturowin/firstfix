/**
 * Coding-agent handoff prompt (docs/ARCHITECTURE.md "Coding-agent handoff prompt"). Built from a template, no AI.
 * Facts (from the scan) are kept apart from candidate changes (to verify).
 */
import type { RemediationHints } from './ecosystems/types.ts';
import type { Action } from './fix-plan.ts';
import { describeAction } from './report-text.ts';

export interface PromptInput {
  repoUrl: string;
  commitSha: string;
  lockfilePath: string;
  advisorySource: string;
  scannedAt: string;
  actions: readonly Action[];
  hintsFor: (ecosystem: string) => RemediationHints | null;
}

/** Large plans are cut here; the prompt says how many were left out. */
export const PROMPT_MAX_ACTIONS = 20;

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
    '',
    '## Facts from the scan',
    ...facts,
    '',
    '## Candidate changes (verify each one)',
    ...changes,
    ...(hidden > 0 ? ['', `${String(hidden)} more ${hidden === 1 ? 'package is' : 'packages are'} in the full report; handle the ones above first.`] : []),
    '',
    '## How to work',
    `- Inspect the dependency graph first${anyHints ? ` (e.g. \`${anyHints.inspectTemplate}\`)` : ''} to see what pulls each package in.`,
    '- Change only what is listed here. Keep unrelated changes out of this work.',
    ...(anyHints
      ? [
          `- For a direct dependency, use \`${anyHints.upgradeTemplate}\`. For a transitive one, upgrade the direct dependency that pulls it in; if that is not possible, use ${anyHints.transitiveFix}.`,
        ]
      : []),
    '- If a candidate is a major-version jump, stop and report before making that change.',
    '- Known malicious packages: remove them, do not upgrade them, and list the secrets that may have been exposed.',
    '- Run the test suite after the changes.',
    '- Rescan the repository afterwards. Report what is still unresolved, including advisories with no fixed version published.',
  ];
  return lines.join('\n');
}
