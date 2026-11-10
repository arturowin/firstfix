import { describe, expect, it } from 'vitest';
import type { AffectedRange } from '../../src/domain/advisory.ts';
import { buildAgentPrompt } from '../../src/domain/agent-prompt.ts';
import { npm } from '../../src/domain/ecosystems/npm/index.ts';
import { npmVersionScheme } from '../../src/domain/ecosystems/npm/version.ts';
import { buildFixPlan, rankFindings, type PlanFinding } from '../../src/domain/fix-plan.ts';
import { describeAction, summaryLine } from '../../src/domain/report-text.ts';

const scheme = () => npmVersionScheme;

function f(over: Partial<PlanFinding> & Pick<PlanFinding, 'package' | 'advisoryId'>): PlanFinding {
  return {
    ecosystem: 'npm',
    installedAs: [],
    installedVersion: '1.0.0',
    scope: 'runtime',
    isDirect: true,
    directParents: [],
    severity: 'medium',
    isMalicious: false,
    title: null,
    candidateVersion: null,
    fixStatus: 'no_fix',
    affectedRanges: [range('0', null)],
    ...over,
  };
}
function range(introduced: string, fixed: string | null): AffectedRange {
  return { kind: 'range', introduced, fixed, lastAffected: null };
}
/** A candidate with the simplest ranges behind it: everything below it is affected. */
const cand = (version: string) => ({
  candidateVersion: version,
  fixStatus: 'candidate' as const,
  affectedRanges: [range('0', version)],
});

describe('ranking policy', () => {
  it('malicious first, then severity, then runtime before dev, then direct before transitive', () => {
    const ranked = rankFindings([
      f({ package: 'dev-direct-critical', advisoryId: 'A', severity: 'critical', scope: 'dev' }),
      f({ package: 'low', advisoryId: 'B', severity: 'low' }),
      f({ package: 'rt-transitive-critical', advisoryId: 'C', severity: 'critical', isDirect: false }),
      f({ package: 'mal', advisoryId: 'MAL-1', severity: 'unknown', isMalicious: true }),
      f({ package: 'unknown', advisoryId: 'D', severity: 'unknown' }),
      f({ package: 'rt-direct-critical', advisoryId: 'E', severity: 'critical' }),
      f({ package: 'optional-critical', advisoryId: 'F', severity: 'critical', scope: 'optional' }),
    ]);
    expect(ranked.map((x) => x.package)).toEqual([
      'mal',
      'rt-direct-critical',
      'rt-transitive-critical',
      'optional-critical',
      'dev-direct-critical',
      'low',
      'unknown', // shown, never hidden
    ]);
  });

  it('fix information shapes the action, not the rank', () => {
    const plan = buildFixPlan(
      [
        f({ package: 'nofix', advisoryId: 'A', severity: 'high' }),
        f({ package: 'fixable', advisoryId: 'B', severity: 'medium', ...cand('1.0.1') }),
      ],
      scheme,
    );
    expect(plan.map((a) => [a.rank, a.package, a.kind])).toEqual([
      [1, 'nofix', 'no_fix'],
      [2, 'fixable', 'upgrade'],
    ]);
  });
});

describe('grouping into actions', () => {
  it('one action per package across installed versions, with severity = the highest', () => {
    const plan = buildFixPlan(
      [
        f({ package: 'qs', installedVersion: '6.7.0', isDirect: false, directParents: ['express'], advisoryId: 'A', severity: 'high', ...cand('6.7.3') }),
        f({ package: 'qs', installedVersion: '6.5.5', isDirect: false, directParents: ['request'], advisoryId: 'A', severity: 'high', ...cand('6.5.3') }),
        f({ package: 'qs', installedVersion: '6.5.5', isDirect: false, directParents: ['request'], advisoryId: 'B', severity: 'critical', ...cand('6.5.6') }),
      ],
      scheme,
    );
    expect(plan).toHaveLength(1);
    const [qs] = plan;
    expect(qs).toMatchObject({ kind: 'upgrade', severity: 'critical', isDirect: false, advisoryCount: 2 });
    expect(qs?.versions.map((v) => [v.installedVersion, v.directParents, v.candidate?.version, v.candidate?.addresses])).toEqual([
      ['6.5.5', ['request'], '6.5.6', 2],
      ['6.7.0', ['express'], '6.7.3', 1],
    ]);
  });

  it('several advisories, one crossing a major: both candidates, major jump flagged, no-fix listed as unresolved', () => {
    const [a] = buildFixPlan(
      [
        f({ package: 'lib', installedVersion: '4.2.0', advisoryId: 'A', ...cand('4.5.0') }),
        f({ package: 'lib', installedVersion: '4.2.0', advisoryId: 'B', ...cand('4.9.1') }),
        f({ package: 'lib', installedVersion: '4.2.0', advisoryId: 'C', ...cand('5.0.0') }),
        f({ package: 'lib', installedVersion: '4.2.0', advisoryId: 'D' }),
      ],
      scheme,
    );
    expect(a?.versions[0]).toMatchObject({
      candidate: { version: '5.0.0', addresses: 3, majorJump: true },
      compatibleCandidate: { version: '4.9.1', addresses: 2, majorJump: false },
      unresolved: ['D'],
    });
    const text = describeAction(a ?? expect.fail(), npm.hints);
    expect(text.steps).toEqual([
      'lib 4.2.0 (direct, runtime): candidate 5.0.0 addresses 3 of 4 advisories on 4.2.0 according to advisory data. `npm install lib@5.0.0`.',
      '5.0.0 is a major-version jump from 4.2.0; 4.9.1 addresses 2 of 4 without one. Check the changelog before choosing.',
      'No fixed version published for D: review the advisory and upstream guidance, and assess your exposure (or replace the package).',
    ]);
  });

  it('separate affected intervals: a proposed version inside one is moved past it, never counted as addressed', () => {
    // Review reproduction. A affects <1.2.0 and [2.0.0, 2.2.0); B affects <2.0.0. Installed 1.0.0.
    // Per-advisory candidates are 1.2.0 (A) and 2.0.0 (B), but 2.0.0 is still affected by A.
    const [a] = buildFixPlan(
      [
        f({ package: 'lib', installedVersion: '1.0.0', advisoryId: 'A', candidateVersion: '1.2.0', fixStatus: 'candidate', affectedRanges: [range('0', '1.2.0'), range('2.0.0', '2.2.0')] }),
        f({ package: 'lib', installedVersion: '1.0.0', advisoryId: 'B', candidateVersion: '2.0.0', fixStatus: 'candidate', affectedRanges: [range('0', '2.0.0')] }),
      ],
      scheme,
    );
    expect(a?.versions[0]?.candidate).toEqual({ version: '2.2.0', addresses: 2, majorJump: true });
    // The compatible 1.x choice addresses only A.
    expect(a?.versions[0]?.compatibleCandidate).toEqual({ version: '1.2.0', addresses: 1, majorJump: false });
  });

  it('a later interval with no fix: the proposed version addresses only what it really leaves', () => {
    const [a] = buildFixPlan(
      [
        f({ package: 'lib', installedVersion: '1.0.0', advisoryId: 'A', candidateVersion: '1.2.0', fixStatus: 'candidate', affectedRanges: [range('0', '1.2.0'), range('1.5.0', null)] }),
        f({ package: 'lib', installedVersion: '1.0.0', advisoryId: 'B', candidateVersion: '1.6.0', fixStatus: 'candidate', affectedRanges: [range('0', '1.6.0')] }),
      ],
      scheme,
    );
    expect(a?.versions[0]?.candidate).toEqual({ version: '1.6.0', addresses: 1, majorJump: false });
  });

  it('without stored ranges nothing is claimed as addressed', () => {
    const [a] = buildFixPlan(
      [f({ package: 'lib', installedVersion: '1.0.0', advisoryId: 'A', candidateVersion: '1.2.0', fixStatus: 'candidate', affectedRanges: null })],
      scheme,
    );
    expect(a?.versions[0]?.candidate).toMatchObject({ version: '1.2.0', addresses: 0 });
  });

  it('malicious: remove + rotate secrets, even when another advisory on it has a candidate', () => {
    const [a] = buildFixPlan(
      [
        f({ package: 'flatmap-stream', installedVersion: '0.1.1', advisoryId: 'MAL-2025-20690', severity: 'unknown', isMalicious: true }),
        f({ package: 'flatmap-stream', installedVersion: '0.1.1', advisoryId: 'GHSA-x', severity: 'critical', isMalicious: true, ...cand('0.2.0') }),
      ],
      scheme,
    );
    expect(a).toMatchObject({ kind: 'remove_malicious', severity: 'critical', isMalicious: true });
    const text = describeAction(a ?? expect.fail(), npm.hints);
    expect(text.headline).toBe('Remove flatmap-stream (known malicious package)');
    expect(text.steps.join(' ')).toMatch(/rotate secrets/);
    expect(text.steps.join(' ')).not.toMatch(/candidate|upgrade/i);
  });

  it('a transitive package names its direct parent and the override route', () => {
    const [a] = buildFixPlan(
      [f({ package: 'qs', installedVersion: '6.5.5', isDirect: false, directParents: ['request'], advisoryId: 'A', ...cand('6.5.6') })],
      scheme,
    );
    expect(describeAction(a ?? expect.fail(), npm.hints).steps[0]).toBe(
      'qs 6.5.5 (via request, runtime): candidate 6.5.6 addresses 1 of 1 advisory on 6.5.5 according to advisory data. Upgrade request to a version that pulls in qs 6.5.6 or later, or use an `overrides` entry in package.json.',
    );
  });

  it('an aliased install is named, and its upgrade command keeps the alias', () => {
    const [a] = buildFixPlan(
      [f({ package: 'lodash', installedAs: ['lodash', 'my-lodash'], installedVersion: '4.17.20', advisoryId: 'A', ...cand('4.17.21') })],
      scheme,
    );
    expect(describeAction(a ?? expect.fail(), npm.hints).steps[0]).toBe(
      'lodash 4.17.20 (installed as lodash and my-lodash, direct, runtime): candidate 4.17.21 addresses 1 of 1 advisory on 4.17.20 according to advisory data. `npm install lodash@4.17.21` or `npm install my-lodash@npm:lodash@4.17.21`.',
    );
  });

  it('package names keep their case in headlines', () => {
    const [a] = buildFixPlan([f({ package: 'request', advisoryId: 'A' })], scheme);
    expect(describeAction(a ?? expect.fail(), npm.hints).headline).toBe('No fixed version published for request');
  });

  it('no version scheme: no candidate, no major-jump flag', () => {
    const [a] = buildFixPlan([f({ package: 'x', advisoryId: 'A', fixStatus: 'unknown' })], () => null);
    expect(a).toMatchObject({ kind: 'review', versions: [{ candidate: null, unplaced: ['A'] }] });
  });
});

describe('summary line', () => {
  const plan = buildFixPlan(
    [
      f({ package: 'flatmap-stream', advisoryId: 'MAL-1', severity: 'unknown', isMalicious: true }),
      f({ package: 'lodash', installedVersion: '4.17.20', advisoryId: 'A', severity: 'high', ...cand('4.17.21') }),
      f({ package: 'request', advisoryId: 'B', severity: 'medium' }),
      f({ package: 'minimist', scope: 'dev', advisoryId: 'C', severity: 'critical', ...cand('1.2.6') }),
    ],
    scheme,
  );

  it('counts by category and says where to start', () => {
    expect(summaryLine({ counts: { totalDeps: 107, checkedDeps: 106 }, lockfilePath: 'package-lock.json', actions: plan })).toBe(
      '1 known malicious package and 3 packages with known vulnerabilities (1 critical, 1 high, 1 medium) in 106 of 107 dependencies checked. Start with: remove flatmap-stream (known malicious package).',
    );
  });

  it('clean and empty lockfiles never say "secure"', () => {
    const clean = summaryLine({ counts: { totalDeps: 12, checkedDeps: 12 }, lockfilePath: 'package-lock.json', actions: [] });
    const empty = summaryLine({ counts: { totalDeps: 0, checkedDeps: 0 }, lockfilePath: 'package-lock.json', actions: [] });
    expect(clean).toBe('No known vulnerabilities in 12 of 12 dependencies checked.');
    expect(empty).toBe('No dependencies to check in package-lock.json.');
    expect(`${clean} ${empty}`).not.toMatch(/secure|safe/i);
  });

  it('nothing checked is not reported as "no known vulnerabilities"', () => {
    const none = summaryLine({ counts: { totalDeps: 3, checkedDeps: 0 }, lockfilePath: 'package-lock.json', actions: [] });
    expect(none).toBe(
      "No dependencies could be checked: all 3 come from sources advisory data doesn't cover (git, local files or other URLs).",
    );
    expect(none).not.toMatch(/no known vulnerabilities/i);
  });
});

describe('coding-agent prompt', () => {
  const findings: PlanFinding[] = [
    f({ package: 'flatmap-stream', installedVersion: '0.1.1', advisoryId: 'MAL-2025-20690', severity: 'unknown', isMalicious: true }),
    f({ package: 'lodash', installedVersion: '4.17.20', advisoryId: 'GHSA-29mw-wpgm-hmr9', title: 'ReDoS in lodash', ...cand('4.17.21') }),
    f({ package: 'qs', installedVersion: '6.5.2', isDirect: false, directParents: ['request'], advisoryId: 'GHSA-hrpp-h998-j3pp', severity: 'high', ...cand('6.5.3') }),
    f({ package: 'request', installedVersion: '2.88.2', advisoryId: 'GHSA-p8p7-x288-28g6', title: 'Server-Side Request Forgery in Request' }),
    f({ package: 'postcss', installedVersion: '7.0.35', advisoryId: 'GHSA-7fh5-64p2-3v2j', ...cand('8.4.31') }),
  ];
  const prompt = () =>
    buildAgentPrompt({
      repoUrl: 'https://github.com/arturowin/scan-review-demo',
      commitSha: '2c18531'.padEnd(40, '0'),
      lockfilePath: 'package-lock.json',
      advisorySource: 'OSV.dev',
      scannedAt: '2026-11-10',
      actions: buildFixPlan(findings, scheme),
      hintsFor: () => npm.hints,
    });

  it('matches the template (snapshot)', () => {
    expect(prompt()).toMatchSnapshot();
  });

  it('keeps facts apart from candidates and never claims a fix', () => {
    const text = prompt() ?? '';
    expect(text.indexOf('## Facts from the scan')).toBeLessThan(text.indexOf('## Candidate changes'));
    expect(text).toMatch(/major-version jump, stop and report/);
    expect(text).not.toMatch(/\bfixed\b(?! version published)/i);
  });

  it('no findings → no prompt', () => {
    expect(
      buildAgentPrompt({ repoUrl: 'u', commitSha: 's', lockfilePath: 'p', advisorySource: 'OSV.dev', scannedAt: 'd', actions: [], hintsFor: () => npm.hints }),
    ).toBeNull();
  });
});
