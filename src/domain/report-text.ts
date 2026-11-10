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

function where(v: ActionVersion, pkg: string): string {
  const aliased = v.installedAs.length > 0;
  const parts: string[] = [];
  if (aliased) parts.push(`installed as ${list(v.installedAs)}`);
  if (v.directAs.length > 0) parts.push(aliased || v.directAs.some((n) => n !== pkg) ? `direct as ${list(v.directAs)}` : 'direct');
  if (v.directParents.length > 0) parts.push(`via ${list(v.directParents)}`);
  if (v.directAs.length === 0 && v.directParents.length === 0) parts.push('transitive');
  return `${parts.join(', ')}, ${v.scope}`;
}

/**
 * Every route that has to change for this installed version. Direct declarations each need their own update
 * (two aliases are two updates, not alternatives); transitive installs need their parents to resolve to a
 * checked version. Only the candidate was checked against the advisory ranges, so nothing says "or later".
 */
function routes(pkg: string, v: ActionVersion & { candidate: CandidateStep }, hints: RemediationHints): string[] {
  const out: string[] = [];
  const built = v.directAs.map((name) => hints.upgradeCommand(pkg, v.candidate.version, name));
  // A name or version that failed validation gets no command at all (never a partially trusted one).
  if (built.some((c) => c === null)) {
    out.push(`Update its declaration to ${v.candidate.version} by hand: no command is generated for this name.`);
  }
  const commands = built.flatMap((c) => (c === null ? [] : [`\`${c}\``]));
  if (commands.length === 1) out.push(`${commands[0] ?? ''}.`);
  if (commands.length > 1) out.push(`Update every declaration (each is a separate install): ${list(commands)}.`);
  if (v.directParents.length > 0) {
    const lead = commands.length > 0 ? `It is also pulled in by ${list(v.directParents)}: update` : 'Update';
    out.push(
      `${lead} ${list(v.directParents)} so it resolves to ${pkg} ${v.candidate.version}, or to another version checked against these advisories; if that isn't possible, use ${hints.transitiveFix}.`,
    );
  }
  return out;
}

export interface SummaryInput {
  /** failedLookups: dependencies the advisory source couldn't check (partial coverage). */
  counts: { totalDeps: number; checkedDeps: number; failedLookups?: number };
  lockfilePath: string | null;
  actions: readonly Action[];
}

/** One line at the top of the report: what was found, in how much was checked, and what to start with. */
export function summaryLine({ counts, lockfilePath, actions }: SummaryInput): string {
  if (counts.totalDeps === 0) return `No dependencies to check in ${lockfilePath ?? 'the lockfile'}.`;
  // Nothing assessed is not a clean result: say so first (review finding, M2). Only when nothing was even
  // partly looked up: incomplete lookups can still carry confirmed findings, reported below.
  if (counts.checkedDeps === 0 && (counts.failedLookups ?? 0) === 0) {
    return `No dependencies could be checked: ${counts.totalDeps === 1 ? 'the only one comes' : `all ${String(counts.totalDeps)} come`} from sources advisory data doesn't cover (git, local files or other URLs).`;
  }
  const checked = `${String(counts.checkedDeps)} of ${plural(counts.totalDeps, 'dependency', 'dependencies')} checked`;
  // Partial coverage is said in the same line, so a partial result never reads as complete.
  const failedLookups = counts.failedLookups ?? 0;
  const partial =
    failedLookups > 0
      ? ` ${plural(failedLookups, 'dependency', 'dependencies')} could not be fully checked because the advisory lookup failed; rescan for full coverage.`
      : '';
  if (actions.length === 0) return `No known vulnerabilities in ${checked}.${partial}`;

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
  return `${parts.join(' and ')} in ${checked}.${partial}${start}`;
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
    const at = `${a.package} ${v.installedVersion} (${where(v, a.package)})`;
    if (a.kind === 'remove_malicious') {
      // Every route has to go: each direct declaration and each parent that pulls it in.
      const remove: string[] = [];
      if (v.directAs.length > 0) {
        remove.push(v.directAs.length === 1 ? 'remove it from your dependencies' : `remove every declaration of it (${list(v.directAs)})`);
      }
      if (v.directParents.length > 0) remove.push(`remove or replace ${list(v.directParents)}, which pulls it in`);
      steps.push(`${at}: ${remove.length > 0 ? remove.join(', and ') : 'remove it'}.`);
      continue;
    }
    if (v.candidate) {
      const candidate = v.candidate;
      steps.push(`${at}: ${candidateText(v.installedVersion, candidate, v.advisories.length)}.`);
      steps.push(...routes(a.package, { ...v, candidate }, hints));
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
  // Lockfile classification only: the scan doesn't see what is deployed or executed.
  const exposure =
    a.scope === 'dev'
      ? 'marked as a dev dependency in the lockfile'
      : a.scope === 'optional'
        ? 'marked as an optional runtime dependency in the lockfile'
        : 'marked as a runtime dependency in the lockfile';
  const how = a.isDirect ? 'declared directly by the project' : 'pulled in transitively';
  return `${capitalize(severityLabel(a.severity))} severity, ${exposure}, ${how}; ${plural(a.advisoryCount, 'advisory', 'advisories')}.`;
}

function verify(a: Action, hints: RemediationHints): string {
  const cmd = hints.inspectCommand(a.package);
  const inspect = cmd === null ? 'The dependency tree' : `\`${cmd}\``;
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
