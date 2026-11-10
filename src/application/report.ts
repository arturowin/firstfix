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
import type { FindingView, ReportData, ScanView, UncheckedView } from '../ports/scan-repository.ts';

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
}

export function buildReport(data: ReportData, registry: EcosystemRegistry): Report {
  const { scan } = data;
  const ecosystem = (id: string) => registry.ecosystems.get(id);
  const scanned = registry.formats.find((f) => scan.lockfilePath !== null && f.fileNames.includes(scan.lockfilePath));

  const plan = scan.status === 'completed' ? buildFixPlan(data.findings, (e) => ecosystem(e)?.versionScheme ?? null) : [];
  const actions = plan.map((a): ReportAction => {
    const hints = ecosystem(a.ecosystem)?.hints;
    return {
      ...a,
      onSummary: a.rank <= SUMMARY_ACTIONS,
      text: hints ? describeAction(a, hints) : null,
      whyItMatters: scan.explanation?.actions[actionId(a)] ?? null,
    };
  });

  const summary =
    scan.status !== 'completed'
      ? null
      : (scan.summaryLine ?? summaryLine({ counts: scan.counts, lockfilePath: scan.lockfilePath, actions: plan }));

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
  };
}
