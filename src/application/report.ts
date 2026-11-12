/**
 * The report a reader sees, built on read from stored facts (docs/ARCHITECTURE.md "Report layout"):
 * ranked findings, recommended actions with their wording, the coding-agent prompt. Pure apart from its inputs;
 * the same stored scan always gives the same report.
 */
import { buildAgentPrompt } from '../domain/agent-prompt.ts';
import type { EcosystemRegistry } from '../domain/ecosystems/types.ts';
import { actionId, type ExplanationSource } from '../domain/explanation.ts';
import { buildFixPlan, rankFindings, SUMMARY_ACTIONS, type Action } from '../domain/fix-plan.ts';
import { describeAction, summaryLine, type ActionText } from '../domain/report-text.ts';
import type { FindingView, ReportData, ScanView, SourceFinding, UncheckedView } from '../ports/scan-repository.ts';
import { isTestPath } from '../domain/source-files.ts';
import { SOURCE_RULES, sourceRule, sourceSummaryLine, type SourceCheckStatus, type SourceCounts, type SourceSeverity } from '../domain/source-rules.ts';

/** A source finding with its rule's deterministic text and a link to the lines at the scanned commit. */
export interface ReportSourceFinding extends SourceFinding {
  title: string;
  explanation: string;
  nextAction: string;
  /** In test code: still reported, labelled. */
  testFile: boolean;
  url: string | null;
  /** Prose for this finding's rule, labelled with where it came from (AI or template); never a source of facts. */
  whyItMatters: { text: string; source: ExplanationSource };
}

export interface ReportSource {
  /** Null for scans from before source checks ("not run"). */
  status: SourceCheckStatus | null;
  counts: SourceCounts | null;
  error: { code: string; message: string } | null;
  summary: string;
  findings: ReportSourceFinding[];
  /** Every supported rule with its match count (0 included), so a clean result shows what was checked. */
  rules: { id: string; title: string; severity: SourceSeverity; matches: number; inTestFiles: number; shown: number }[];
}

export interface ReportAction extends Action {
  /** Among the first SUMMARY_ACTIONS: shown on the summary; the rest are listed below it. */
  onSummary: boolean;
  text: ActionText | null;
  /** Prose, labelled with where it came from; never a source of facts. */
  whyItMatters: { text: string; source: ExplanationSource } | null;
}

export interface Report {
  scan: ScanView;
  summary: string | null;
  /** The explanation paragraph under the summary line, labelled with its source. */
  explanation: { text: string; source: ExplanationSource } | null;
  /** CI checks for the scanned ecosystem, suggested on a clean result. */
  ciChecks: string[];
  actions: ReportAction[];
  findings: FindingView[];
  unchecked: UncheckedView[];
  agentPrompt: string | null;
  /** Why dependencies weren't checked, when the scan completed on its source check alone. */
  dependencyNotChecked: { status: 'unsupported' | 'failed'; message: string } | null;
  /** The source checks, kept apart from dependency findings and actions; null unless the scan completed. */
  source: ReportSource | null;
}

export function buildReport(data: ReportData, registry: EcosystemRegistry): Report {
  const { scan } = data;
  const ecosystem = (id: string) => registry.ecosystems.get(id);
  const scanned = registry.formats.find((f) => scan.lockfilePath !== null && f.fileNames.includes(scan.lockfilePath));

  // A completed scan's dependency part counts only if the dependency check completed (older scans: always).
  const depCheck = scan.checks.dependency;
  const depComplete = scan.status === 'completed' && (depCheck === null || depCheck.status === 'complete');
  const plan = depComplete ? buildFixPlan(data.findings, (e) => ecosystem(e)?.versionScheme ?? null) : [];
  const actions = plan.map((a): ReportAction => {
    const hints = ecosystem(a.ecosystem)?.hints;
    return {
      ...a,
      onSummary: a.rank <= SUMMARY_ACTIONS,
      text: hints ? describeAction(a, hints) : null,
      whyItMatters: scan.explanation?.actions[actionId(a)] ?? null,
    };
  });

  const summary = !depComplete
    ? null
    : (scan.summaryLine ?? summaryLine({ counts: scan.counts, lockfilePath: scan.lockfilePath, actions: plan }));

  // The handoff covers both checks: dependency actions when that check completed, and the stored source matches.
  const sourceCounts = scan.checks.source?.counts.rules;
  const agentPrompt =
    scan.status === 'completed' && scan.commitSha
      ? buildAgentPrompt({
          repoUrl: scan.repo.url,
          commitSha: scan.commitSha,
          lockfilePath: scan.lockfilePath ?? 'the lockfile',
          advisorySource: scan.advisorySource ?? 'unknown source',
          scannedAt: (scan.completedAt ?? scan.updatedAt).toISOString().slice(0, 10),
          actions: plan,
          hintsFor: (e) => ecosystem(e)?.hints ?? null,
          schemeFor: (e) => ecosystem(e)?.versionScheme ?? null,
          sourceFindings: data.sourceFindings,
          ...(sourceCounts ? { sourceMatches: Object.values(sourceCounts).reduce((n, r) => n + r.matches, 0) } : {}),
        })
      : null;

  return {
    scan,
    summary,
    explanation: scan.explanation ? { text: scan.explanation.summary, source: scan.explanation.source } : null,
    ciChecks: [...((scanned && ecosystem(scanned.ecosystem)?.hints.ciChecks) ?? [])],
    actions,
    findings: rankFindings(data.findings),
    unchecked: data.unchecked,
    agentPrompt,
    dependencyNotChecked:
      scan.status === 'completed' && depCheck !== null && depCheck.status !== 'complete'
        ? { status: depCheck.status, message: depCheck.error.message }
        : null,
    source: scan.status === 'completed' ? reportSource(scan, data.sourceFindings) : null,
  };
}

function reportSource(scan: ScanView, findings: SourceFinding[]): ReportSource {
  const check = scan.checks.source;
  return {
    status: check?.status ?? null,
    counts: check?.counts ?? null,
    error: check?.error ?? null,
    summary: sourceSummaryLine(check, findings),
    rules: SOURCE_RULES.map((r) => {
      // All matches found (recorded counts); older scans fall back to their stored findings.
      const recorded = check?.counts.rules?.[r.id];
      const mine = findings.filter((f) => f.ruleId === r.id);
      return {
        id: r.id,
        title: r.title,
        severity: r.severity,
        matches: recorded?.matches ?? mine.length,
        inTestFiles: recorded?.inTestFiles ?? mine.filter((f) => isTestPath(f.path)).length,
        shown: mine.length,
      };
    }),
    findings: findings.map((f) => {
      const rule = sourceRule(f.ruleId, f.ruleVersion);
      return {
        ...f,
        title: rule?.title ?? f.ruleId,
        explanation: rule?.explanation ?? 'A source check matched this code. Review it in context.',
        nextAction: rule?.nextAction ?? 'Review this code.',
        testFile: isTestPath(f.path),
        url: scan.commitSha ? sourceUrl(scan.repo, scan.commitSha, f) : null,
        whyItMatters: scan.explanation?.sourceRules?.[f.ruleId] ?? {
          text: rule?.explanation ?? 'A source check matched this code. Review it in context.',
          source: 'template' as const,
        },
      };
    }),
  };
}

/** The matched lines at exactly the scanned commit. */
function sourceUrl(repo: { owner: string; name: string }, sha: string, f: SourceFinding): string {
  const path = f.path.split('/').map(encodeURIComponent).join('/');
  const lines = f.end.line > f.start.line ? `L${String(f.start.line)}-L${String(f.end.line)}` : `L${String(f.start.line)}`;
  return `https://github.com/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/blob/${sha}/${path}#${lines}`;
}
