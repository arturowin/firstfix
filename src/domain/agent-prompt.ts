/**
 * Coding-agent handoff prompt (docs/ARCHITECTURE.md "Coding-agent handoff prompt"). Built from a template, no AI.
 *
 * An agent acts on this text, so it is assembled only from validated structured fields: every package name,
 * alias and parent is checked with the ecosystem's name rules, versions with its version scheme, advisory IDs,
 * severities, scopes, the repository URL, commit and lockfile path against fixed formats. Free-form text
 * (advisory titles, AI or template prose) is never included. Anything that fails validation is left out and the
 * prompt says so, which also covers rows stored before validation existed.
 */
import type { Severity } from './advisory.ts';
import type { RemediationHints, VersionScheme } from './ecosystems/types.ts';
import type { Action, ActionVersion } from './fix-plan.ts';

export interface PromptInput {
  repoUrl: string;
  commitSha: string;
  lockfilePath: string;
  advisorySource: string;
  scannedAt: string;
  actions: readonly Action[];
  hintsFor: (ecosystem: string) => RemediationHints | null;
  /** The ecosystem's version scheme, for validating versions; null → a conservative token check. */
  schemeFor?: (ecosystem: string) => VersionScheme | null;
}

/** Large plans are cut here; the prompt says how many were left out. */
export const PROMPT_MAX_ACTIONS = 20;

const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'unknown'];
const SCOPES = ['runtime', 'optional', 'dev'];
const ADVISORY_ID = /^[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+){1,6}$/;
const ECOSYSTEM_ID = /^[A-Za-z][A-Za-z0-9.]{0,31}$/;
const REPO_URL = /^https:\/\/github\.com\/[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;
const SHA = /^[0-9a-f]{40}$/;
const SAFE_PATH = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;
const SAFE_LABEL = /^[A-Za-z0-9 .()-]{1,40}$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const VERSION_TOKEN = /^[A-Za-z0-9.+_~-]{1,64}$/;

interface Check {
  name: (n: string) => boolean;
  version: (v: string) => boolean;
}

function checksFor(input: PromptInput, ecosystem: string): Check | null {
  const hints = input.hintsFor(ecosystem);
  if (!hints || !ECOSYSTEM_ID.test(ecosystem)) return null;
  const scheme = input.schemeFor?.(ecosystem) ?? null;
  return {
    name: (n) => hints.isValidPackageName(n),
    version: (v) => VERSION_TOKEN.test(v) && (scheme === null || scheme.isValid(v)),
  };
}

/** Joins the valid names; counts the rest instead of printing them. */
function names(list: readonly string[], ok: (n: string) => boolean): { text: string; omitted: number } {
  const valid = list.filter(ok);
  return { text: valid.join(', '), omitted: list.length - valid.length };
}

function versionLines(a: Action, v: ActionVersion, check: Check): string[] {
  const version = check.version(v.installedVersion) ? v.installedVersion : '[version omitted: failed validation]';
  const scope = SCOPES.includes(v.scope) ? v.scope : 'unknown scope';
  const direct = names(v.directAs.length > 0 ? v.directAs : v.isDirect ? [a.package] : [], check.name);
  const parents = names(v.directParents, check.name);
  const how = [
    ...(direct.text ? [`declared directly as ${direct.text}`] : []),
    ...(parents.text ? [`via ${parents.text}`] : []),
  ];
  const omitted = direct.omitted + parents.omitted;
  const notes = [
    ...(omitted > 0 ? [`${String(omitted)} name(s) omitted: failed validation`] : []),
    ...(v.contextTruncated ? ['dependency context truncated'] : []),
  ];
  const advisories = v.advisories.map((adv) => {
    const id = ADVISORY_ID.test(adv.id) ? adv.id : '[advisory id omitted: failed validation]';
    const severity = SEVERITIES.includes(adv.severity) ? adv.severity : 'unknown';
    return `     - ${id} (${severity})`;
  });
  return [
    `   - installed ${version}, ${scope}, ${how.length > 0 ? how.join('; ') : 'transitive'}${notes.length > 0 ? ` (${notes.join('; ')})` : ''}`,
    ...advisories,
  ];
}

function changeLines(a: Action, v: ActionVersion, hints: RemediationHints, check: Check): string[] {
  if (a.kind === 'remove_malicious') {
    const parents = names(v.directParents, check.name);
    return [
      '   - Remove it from every place it is declared; do not upgrade it.',
      ...(parents.text ? [`   - It is also pulled in by ${parents.text}: remove or replace those.`] : []),
      '   - Check how it got in and list the secrets that were available where it was installed.',
    ];
  }
  const out: string[] = [];
  const c = v.candidate;
  if (c && check.version(c.version)) {
    out.push(`   - Candidate ${c.version}: addresses ${String(c.addresses)} of ${String(v.advisories.length)} advisories according to advisory data.`);
    const remaining = c.stillAffected.filter((id) => ADVISORY_ID.test(id));
    if (remaining.length > 0) out.push(`   - Still affected at ${c.version}: ${remaining.join(', ')}. Report these after the change.`);
    const direct = v.directAs.length > 0 ? v.directAs : v.isDirect ? [a.package] : [];
    for (const declared of direct) {
      const cmd = check.name(declared) ? hints.upgradeCommand(a.package, c.version, declared) : null;
      out.push(cmd ? `   - Run: ${cmd}` : '   - One declaration needs updating by hand (its name failed validation).');
    }
    const parents = names(v.directParents, check.name);
    if (parents.text) {
      out.push(`   - Pulled in by ${parents.text}: update it so it resolves to ${a.package} ${c.version}, or use ${hints.transitiveFix}.`);
    }
    if (c.majorJump) {
      const compat = v.compatibleCandidate && check.version(v.compatibleCandidate.version) ? v.compatibleCandidate : null;
      out.push(
        compat
          ? `   - Major-version jump. ${compat.version} addresses ${String(compat.addresses)} without one. Stop and report before choosing.`
          : '   - Major-version jump: stop and report before making this change.',
      );
    }
  } else if (v.noUsefulCandidate) {
    out.push('   - No upgrade recommendation could be verified from the available advisory data. Report it for review and suggest rescanning to refresh the findings.');
  } else if (v.unresolved.length > 0) {
    out.push('   - No fixed version published: do not change it; report it as unresolved.');
  } else {
    out.push('   - No candidate version from advisory data: report it as needing review.');
  }
  return out;
}

export function buildAgentPrompt(input: PromptInput): string | null {
  if (input.actions.length === 0) return null;
  const header = {
    repo: REPO_URL.test(input.repoUrl) ? input.repoUrl : 'this repository',
    commit: SHA.test(input.commitSha) ? input.commitSha : 'the scanned commit',
    lockfile: SAFE_PATH.test(input.lockfilePath) ? input.lockfilePath : 'the lockfile',
    source: SAFE_LABEL.test(input.advisorySource) ? input.advisorySource : 'the advisory source',
    date: DATE.test(input.scannedAt) ? input.scannedAt : 'the scan date',
  };

  // An action whose own package name fails validation is not in the prompt at all.
  const usable = input.actions.flatMap((a) => {
    const check = checksFor(input, a.ecosystem);
    const hints = input.hintsFor(a.ecosystem);
    return check && hints && check.name(a.package) ? [{ a, check, hints }] : [];
  });
  const unsafe = input.actions.length - usable.length;
  const shown = usable.slice(0, PROMPT_MAX_ACTIONS);
  const hidden = usable.length - shown.length;
  const anyHints = shown[0]?.hints ?? null;

  const facts = shown.flatMap(({ a, check }, i) => [
    `${String(i + 1)}. ${a.package} (${a.ecosystem})${a.isMalicious ? ': KNOWN MALICIOUS' : ''}`,
    ...a.versions.flatMap((v) => versionLines(a, v, check)),
  ]);
  const changes = shown.flatMap(({ a, check, hints }, i) => [
    `${String(i + 1)}. ${a.package}: ${a.kind === 'remove_malicious' ? 'remove (known malicious)' : a.kind === 'upgrade' ? 'upgrade to a candidate' : a.kind === 'no_fix' ? 'no fixed version published' : 'review'}`,
    ...a.versions.flatMap((v) => [
      ...(a.versions.length > 1 && check.version(v.installedVersion) ? [`   - For ${v.installedVersion}:`] : []),
      ...changeLines(a, v, hints, check),
    ]),
  ]);

  const lines = [
    `You are working in ${header.repo} at commit ${header.commit}.`,
    `A dependency scan of ${header.lockfile} (advisory data: ${header.source}, ${header.date}) found the issues below.`,
    'Candidate versions come from advisory data. They are not confirmed fixes: compatibility, resolution and tests are still to verify.',
    '',
    '## Facts from the scan',
    ...facts,
    '',
    '## Candidate changes (verify each one)',
    ...changes,
    ...(hidden > 0 ? ['', `${String(hidden)} more ${hidden === 1 ? 'package is' : 'packages are'} in the full report; handle the ones above first.`] : []),
    ...(unsafe > 0
      ? ['', `${String(unsafe)} ${unsafe === 1 ? 'package is' : 'packages are'} left out because ${unsafe === 1 ? 'its name' : 'their names'} failed validation; see the report.`]
      : []),
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
