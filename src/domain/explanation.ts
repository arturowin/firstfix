/**
 * Explanations: the only prose in a report that isn't rendered from data (docs/ARCHITECTURE.md "Evidence vs AI
 * text"). This module builds the facts an explainer may use and checks any explainer's output against them.
 * Checking can't prove prose true; it catches invented identifiers and versions, missing or unknown actions,
 * overlong text, and claims the product never makes ("secure", "fixed").
 */
import type { Severity } from './advisory.ts';
import type { Action } from './fix-plan.ts';
import type { Scope } from './lockfile.ts';
import { headline } from './report-text.ts';

export type ExplanationSource = 'ai' | 'template';

/** Actions beyond this rank get template text only: bounds prompt size, latency and cost. */
export const EXPLAINED_ACTIONS = 10;
export const MAX_SUMMARY_CHARS = 600;
export const MAX_WHY_CHARS = 300;

export interface ActionFacts {
  /** Stable id: `<ecosystem>:<package>`. */
  actionId: string;
  rank: number;
  kind: Action['kind'];
  ecosystem: string;
  package: string;
  severity: Severity;
  isMalicious: boolean;
  scope: Scope;
  isDirect: boolean;
  directParents: string[];
  /** Other names the project installs it under (npm aliases). */
  installedAs: string[];
  installedVersions: string[];
  /** Every candidate version the report shows for this action. */
  candidateVersions: string[];
  /** Advisories with no fixed version published. */
  unresolvedCount: number;
  majorJump: boolean;
  advisories: { id: string; severity: Severity; title: string | null }[];
  /** The deterministic "what to do" line, for context. */
  headline: string;
}

/** What a completed scan keeps. */
export interface StoredExplanation {
  source: ExplanationSource;
  summary: string;
  actions: Record<string, { text: string; source: ExplanationSource }>;
  /** Why AI text was not used, when an AI explainer was configured (for operators and the eval; not shown). */
  fallbackReason?: string;
}

export interface ExplainInput {
  repo: string;
  summaryLine: string;
  checkedDeps: number;
  totalDeps: number;
  actions: ActionFacts[];
}

export interface Explanation {
  summary: string;
  actions: { actionId: string; whyItMatters: string }[];
}

export const actionId = (a: { ecosystem: string; package: string }) => `${a.ecosystem}:${a.package}`;

export function explainInput(input: {
  repo: string;
  summaryLine: string;
  checkedDeps: number;
  totalDeps: number;
  actions: readonly Action[];
}, limit = EXPLAINED_ACTIONS): ExplainInput {
  return {
    repo: input.repo,
    summaryLine: input.summaryLine,
    checkedDeps: input.checkedDeps,
    totalDeps: input.totalDeps,
    actions: input.actions.slice(0, limit).map((a): ActionFacts => {
      const candidates = a.versions.flatMap((v) => [
        ...(v.candidate ? [v.candidate.version] : []),
        ...(v.compatibleCandidate ? [v.compatibleCandidate.version] : []),
        ...v.advisories.flatMap((adv) => (adv.candidateVersion ? [adv.candidateVersion] : [])),
      ]);
      return {
        actionId: actionId(a),
        rank: a.rank,
        kind: a.kind,
        ecosystem: a.ecosystem,
        package: a.package,
        severity: a.severity,
        isMalicious: a.isMalicious,
        scope: a.scope,
        isDirect: a.isDirect,
        directParents: [...new Set(a.versions.flatMap((v) => v.directParents))].sort(),
        installedAs: [...new Set(a.versions.flatMap((v) => v.installedAs))].sort(),
        installedVersions: a.versions.map((v) => v.installedVersion),
        candidateVersions: [...new Set(candidates)],
        unresolvedCount: new Set(a.versions.flatMap((v) => v.unresolved)).size,
        majorJump: a.versions.some((v) => v.candidate?.majorJump === true),
        advisories: dedupeBy(
          a.versions.flatMap((v) => v.advisories.map((adv) => ({ id: adv.id, severity: adv.severity, title: adv.title }))),
          (x) => x.id,
        ),
        headline: headline(a),
      };
    }),
  };
}

function dedupeBy<T>(items: T[], key: (t: T) => string): T[] {
  const seen = new Map<string, T>();
  for (const i of items) if (!seen.has(key(i))) seen.set(key(i), i);
  return [...seen.values()];
}

// Version-like tokens: 1.2, 1.2.3, v1.2.3, 1.2.3-beta.1. Prose numbers like "1.5 times" are flagged too: strict
// on purpose, since a wrong version in an explanation is worse than a fallback to the template.
const VERSION = /\bv?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)\b/g;
// Advisory identifiers from the common databases.
const ADVISORY_ID = /\b(?:GHSA(?:-[0-9a-z]{4}){3}|CVE-\d{4}-\d{4,}|MAL-\d{4}-\d+|OSV-\d{4}-\d+|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+)\b/gi;
const BANNED: [RegExp, string][] = [
  [/\b(?:secure|safe|safely|guarantee[sd]?)\b/i, 'claims safety or a guarantee'],
  [/\b(?:fixed|fixes)\b/i, 'claims a fix (only candidates exist; a rescan confirms)'],
];

/**
 * Last resort when even the template's text fails the check: fixed sentences that name nothing, so they always
 * pass. Prose is an addition to the report; it must never be the reason a completed scan is lost.
 */
export function minimalExplanation(input: ExplainInput): Explanation {
  return {
    summary: 'The actions below are ordered by the ranking policy; their steps and evidence come from the scan data.',
    actions: input.actions.map((a) => ({ actionId: a.actionId, whyItMatters: 'See the steps and evidence for this package.' })),
  };
}

export type CheckResult = { ok: true } | { ok: false; problems: string[] };

interface Evidence {
  versions: Set<string>;
  ids: Set<string>;
  /** Package names (real, aliases, parents): identifiers, not prose, so they're masked before checking. */
  names: string[];
}

function evidenceOf(actions: readonly ActionFacts[]): Evidence {
  const e: Evidence = { versions: new Set(), ids: new Set(), names: [] };
  for (const a of actions) {
    for (const v of [...a.installedVersions, ...a.candidateVersions]) e.versions.add(v);
    for (const adv of a.advisories) e.ids.add(adv.id.toUpperCase());
    e.names.push(a.package, ...a.installedAs, ...a.directParents);
  }
  // Longest first, so "safe-buffer" is masked before a shorter name inside it.
  e.names = [...new Set(e.names)].sort((x, y) => y.length - x.length);
  return e;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Replaces known package names with a neutral token: "safe-buffer" is a name, not a safety claim. */
function maskNames(text: string, names: readonly string[]): string {
  let out = text;
  for (const n of names) if (n) out = out.replace(new RegExp(`(?<![\\w@/.-])${escapeRe(n)}(?![\\w/-]|\\.[\\w])`, 'gi'), '\u2063PKG\u2063');
  return out;
}

/**
 * Does this explanation stay within the facts? Applies to every explainer, the template included.
 * The summary may use any action's evidence; each action's text only its own (an explanation for one package
 * must not quote another package's advisories or versions).
 */
export function checkExplanation(input: ExplainInput, out: Explanation): CheckResult {
  const problems: string[] = [];

  const checkText = (where: string, text: string, max: number, evidence: Evidence) => {
    if (text.trim() === '') problems.push(`${where}: empty`);
    if (text.length > max) problems.push(`${where}: ${String(text.length)} characters (max ${String(max)})`);
    const prose = maskNames(text, evidence.names);
    for (const m of prose.matchAll(VERSION)) {
      if (m[1] !== undefined && !evidence.versions.has(m[1])) problems.push(`${where}: version ${m[0]} is not in this evidence`);
    }
    for (const m of prose.matchAll(ADVISORY_ID)) {
      if (!evidence.ids.has(m[0].toUpperCase())) problems.push(`${where}: advisory ${m[0]} is not in this evidence`);
    }
    // "no fixed version published" is the product's own wording for missing fixes, not a claim of one.
    const claimText = prose.replace(/\bno fixed versions?\b/gi, '');
    for (const [re, why] of BANNED) if (re.test(claimText)) problems.push(`${where}: ${why}`);
  };

  checkText('summary', out.summary, MAX_SUMMARY_CHARS, evidenceOf(input.actions));

  const byId = new Map(input.actions.map((a) => [a.actionId, a]));
  const seen = new Set<string>();
  for (const a of out.actions) {
    const facts = byId.get(a.actionId);
    if (!facts) problems.push(`unknown action ${a.actionId}`);
    else if (seen.has(a.actionId)) problems.push(`duplicate action ${a.actionId}`);
    seen.add(a.actionId);
    if (facts) checkText(`action ${a.actionId}`, a.whyItMatters, MAX_WHY_CHARS, evidenceOf([facts]));
  }
  for (const id of byId.keys()) if (!seen.has(id)) problems.push(`missing action ${id}`);

  return problems.length === 0 ? { ok: true } : { ok: false, problems };
}
