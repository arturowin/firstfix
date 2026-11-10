/**
 * Deterministic report wording: summary line and per-action text. Rendered from structured data only (no AI).
 * Versions are always "candidate"; nothing here says "fixed" or "secure".
 */
import type { Severity } from './advisory.ts';
import type { RemediationHints } from './ecosystems/types.ts';
import type { Action, ActionVersion, CandidateStep } from './fix-plan.ts';

const plural = (n: number, one: string, many = `${one}s`) => `${String(n)} ${n === 1 ? one : many}`;
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown'];
const severityLabel = (s: Severity) => (s === 'unknown' ? 'unknown severity' : s);

function list(items: readonly string[]): string {
  if (items.length <= 1) return items.join('');
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1] ?? ''}`;
}

function where(v: ActionVersion): string {
  const how = v.isDirect ? 'direct' : v.directParents.length > 0 ? `via ${list(v.directParents)}` : 'transitive';
  return `${how}, ${v.scope}`;
}

export interface SummaryInput {
  counts: { totalDeps: number; checkedDeps: number };
  lockfilePath: string | null;
  actions: readonly Action[];
}

/** One line at the top of the report: what was found, in how much was checked, and what to start with. */
export function summaryLine({ counts, lockfilePath, actions }: SummaryInput): string {
  if (counts.totalDeps === 0) return `No dependencies to check in ${lockfilePath ?? 'the lockfile'}.`;
  const checked = `${String(counts.checkedDeps)} of ${plural(counts.totalDeps, 'dependency', 'dependencies')} checked`;
  if (actions.length === 0) return `No known vulnerabilities in ${checked}.`;

  const malicious = actions.filter((a) => a.isMalicious).length;
  const vulnerable = actions.filter((a) => !a.isMalicious);
  const parts: string[] = [];
  if (malicious > 0) parts.push(plural(malicious, 'known malicious package'));
  if (vulnerable.length > 0) {
    const bySeverity = SEVERITIES.flatMap((s) => {
      const n = vulnerable.filter((a) => a.severity === s).length;
      return n > 0 ? [`${String(n)} ${severityLabel(s)}`] : [];
    });
    parts.push(`${plural(vulnerable.length, 'package')} with known vulnerabilities (${bySeverity.join(', ')})`);
  }
  const first = actions[0];
  const start = first ? ` Start with: ${headline(first)}.` : '';
  return `${parts.join(' and ')} in ${checked}.${start}`;
}

/** The short "what" of an action. */
export function headline(a: Action): string {
  const only = a.versions.length === 1 ? a.versions[0] : undefined;
  switch (a.kind) {
    case 'remove_malicious':
      return `remove ${a.package} (known malicious package)`;
    case 'upgrade': {
      const c = only?.candidate;
      if (only && c) return `upgrade ${a.package} ${only.installedVersion} to candidate ${c.version}`;
      return `upgrade ${a.package} (${plural(a.versions.length, 'installed version')})`;
    }
    case 'no_fix':
      return `no fixed version published for ${a.package}`;
    case 'review':
      return `review ${a.package}: check the advisory for fixed versions`;
  }
}

function candidateText(installed: string, c: CandidateStep, total: number): string {
  return `candidate ${c.version} addresses ${String(c.addresses)} of ${plural(total, 'advisory', 'advisories')} on ${installed} according to advisory data`;
}

export interface ActionText {
  headline: string;
  /** One or more lines per installed version: candidates, parents, unresolved advisories. */
  steps: string[];
  why: string;
  verify: string;
}

export function describeAction(a: Action, hints: RemediationHints): ActionText {
  const steps: string[] = [];
  for (const v of a.versions) {
    const at = `${a.package} ${v.installedVersion} (${where(v)})`;
    if (a.kind === 'remove_malicious') {
      steps.push(
        v.isDirect
          ? `${at}: remove it from your dependencies.`
          : `${at}: remove or replace ${list(v.directParents)}, which pulls it in.`,
      );
      continue;
    }
    if (v.candidate) {
      const route = v.isDirect
        ? `\`${hints.upgradeCommand(a.package, v.candidate.version)}\``
        : `upgrade ${list(v.directParents)} to a version that pulls in ${a.package} ${v.candidate.version} or later, or use ${hints.transitiveFix}`;
      steps.push(`${at}: ${candidateText(v.installedVersion, v.candidate, v.advisories.length)}. ${capitalize(route)}.`);
      if (v.candidate.majorJump) {
        steps.push(
          v.compatibleCandidate
            ? `${v.candidate.version} is a major-version jump from ${v.installedVersion}; ${v.compatibleCandidate.version} addresses ${String(v.compatibleCandidate.addresses)} of ${String(v.advisories.length)} without one. Check the changelog before choosing.`
            : `${v.candidate.version} is a major-version jump from ${v.installedVersion}: check the changelog for breaking changes.`,
        );
      }
    } else if (v.unresolved.length > 0 || v.unplaced.length > 0) {
      steps.push(`${at}: no candidate version.`);
    }
    if (v.unresolved.length > 0) {
      steps.push(
        `No fixed version published for ${list(v.unresolved)}: review the advisory and upstream guidance, and assess your exposure (or replace the package).`,
      );
    }
    if (v.unplaced.length > 0) steps.push(`${list(v.unplaced)}: see the advisory for fixed versions.`);
  }

  if (a.kind === 'remove_malicious') {
    steps.push(
      'Check how it got in (lockfile history, the dependency that added it) and rotate secrets that were available where it was installed: CI, developer machines, servers.',
    );
  }

  return { headline: capitalize(headline(a)), steps, why: whyFirst(a), verify: verify(a, hints) };
}

function whyFirst(a: Action): string {
  if (a.isMalicious) return 'Known malicious package: it can run code when installed or imported, so it outranks any vulnerability.';
  const exposure = a.scope === 'dev' ? 'a dev dependency (not shipped at runtime)' : 'installed at runtime';
  const how = a.isDirect ? 'declared directly by the project' : 'pulled in transitively';
  return `${capitalize(severityLabel(a.severity))} severity, ${exposure}, ${how}; ${plural(a.advisoryCount, 'advisory', 'advisories')}.`;
}

function verify(a: Action, hints: RemediationHints): string {
  const inspect = `\`${hints.inspectCommand(a.package)}\``;
  switch (a.kind) {
    case 'remove_malicious':
      return `${inspect} shows nothing, a rescan no longer lists it, and the exposed secrets were rotated.`;
    case 'upgrade':
      return `${inspect} shows only the candidate version, your tests pass, and a rescan confirms which advisories remain.`;
    case 'no_fix':
    case 'review':
      return `Rescan after any change, and re-check the advisory for a published fix.`;
  }
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
