import { groupByOwner, noticeFromQuery, signInHref, type MeJson, type RepoJson } from './account.ts';
import { SubmissionFlow } from './submission.ts';
import { sourceBadge, sourceHeadline, sourceTotals, type Tone } from './source-text.ts';

// Submit, follow progress, and show the report in the frozen layout (docs/ARCHITECTURE.md "Report layout"):
// 1. summary + date + commit + coverage + advisory source, 2. up to three next actions, 3. evidence per action,
// 4. all findings + unchecked dependencies, 5. coding-agent prompt preview / scan again.
// All API data is rendered with textContent / attributes, never innerHTML.

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
type Scope = 'runtime' | 'optional' | 'dev';
type FixStatus = 'candidate' | 'no_fix' | 'unknown';

interface ScanJson {
  id: string;
  repo: { url: string };
  visibility?: 'public' | 'private';
  commitSha: string | null;
  lockfilePath: string | null;
  advisorySource: string | null;
  status: 'queued' | 'running' | 'retrying' | 'completed' | 'unsupported' | 'failed';
  stage: 'fetching' | 'scanning' | 'analyzing' | 'source' | null;
  counts: { totalDeps: number; checkedDeps: number; unsupportedDeps: number; failedLookups: number };
  coverage: 'full' | 'partial' | null;
  error: { code: string; message: string } | null;
  completedAt: string | null;
}

interface FindingJson {
  ecosystem: string;
  package: string;
  installedVersion: string;
  scope: Scope;
  isDirect: boolean;
  directParents: string[];
  installPaths: string[][];
  contextTruncated?: boolean;
  advisoryId: string;
  aliases: string[];
  severity: Severity;
  isMalicious: boolean;
  title: string | null;
  candidateVersion: string | null;
  fixStatus: FixStatus;
}

interface ActionVersionJson {
  installedVersion: string;
  installedAs: string[];
  directAs: string[];
  scope: Scope;
  isDirect: boolean;
  directParents: string[];
  advisories: { id: string; severity: Severity; title: string | null; fixStatus: FixStatus; candidateVersion: string | null }[];
}

interface ActionJson {
  rank: number;
  kind: 'remove_malicious' | 'upgrade' | 'no_fix' | 'review';
  ecosystem: string;
  package: string;
  severity: Severity;
  isMalicious: boolean;
  onSummary: boolean;
  versions: ActionVersionJson[];
  text: { headline: string; steps: string[]; why: string; verify: string } | null;
  whyItMatters: ProseJson | null;
}

/** Prose: AI-written (checked against the scan data) or from the template. Never a source of facts. */
interface ProseJson {
  text: string;
  source: 'ai' | 'template';
}

interface SourceFindingJson {
  ruleId: string;
  severity: 'high' | 'medium';
  path: string;
  start: { line: number; column: number };
  end: { line: number; column: number };
  excerpt: string;
  title: string;
  explanation: string;
  nextAction: string;
  testFile: boolean;
  url: string | null;
  whyItMatters?: ProseJson;
}

interface SourceCountsJson {
  eligible: number;
  checked: number;
  skippedLimit: number;
  skippedSize: number;
  skippedLinks: number;
  skippedTime: number;
  fetchFailed: number;
  skippedParse?: number;
  listingTruncated: boolean;
  findingsTruncated: boolean;
}

interface ReportJson {
  scan: ScanJson;
  summary: string | null;
  explanation: ProseJson | null;
  ciChecks: string[];
  actions: ActionJson[];
  findings: FindingJson[];
  unchecked: { ecosystem: string; package: string; version: string | null; reason: 'unsupported_source' | 'lookup_failed' | 'invalid_name' }[];
  agentPrompt: string | null;
  dependencyNotChecked?: { status: 'unsupported' | 'failed'; message: string } | null;
  source?: {
    status: 'complete' | 'partial' | 'no_files' | 'failed' | null;
    counts: SourceCountsJson | null;
    summary: string;
    findings: SourceFindingJson[];
    rules?: { id: string; title: string; severity: 'high' | 'medium'; matches: number; inTestFiles: number; shown?: number }[];
  } | null;
}

const TERMINAL = new Set(['completed', 'unsupported', 'failed']);
const SCAN_PATH = /^\/scans\/([0-9a-f-]{36})$/;

function byId(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el;
}

const form = byId('scan-form') as HTMLFormElement;
const input = byId('repo-url') as HTMLInputElement;
const button = byId('submit') as HTMLButtonElement;
const formError = byId('form-error');
const result = byId('result');
const authBox = byId('auth');
const heroSignIn = byId('hero-signin') as HTMLAnchorElement;
const picker = byId('picker');

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, className?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function link(text: string, href: string): HTMLAnchorElement {
  const a = el('a', text);
  a.href = href;
  a.rel = 'noopener noreferrer';
  a.target = '_blank';
  return a;
}

/** Renders `code` spans from backticks in our own deterministic text (still textContent only). */
function richText(tag: 'p' | 'li' | 'div', text: string, className?: string): HTMLElement {
  const node = el(tag, undefined, className);
  text.split('`').forEach((part, i) => {
    if (part) node.append(i % 2 === 1 ? el('code', part) : part);
  });
  return node;
}

async function api(path: string, init?: RequestInit): Promise<{ status: number; body: unknown }> {
  const headers = new Headers(init?.headers);
  headers.set('accept', 'application/json');
  const res = await fetch(path, { ...init, headers });
  // An error page from a proxy may not be JSON; the status still tells the caller what happened.
  return { status: res.status, body: await res.json().catch(() => null) };
}

// One Idempotency-Key per intended submission; retries reuse it (src/web/submission.ts).
const submissions = new SubmissionFlow(
  async (repoUrl, key) =>
    api('/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'idempotency-key': key },
      body: JSON.stringify({ repoUrl }),
    }),
  () => crypto.randomUUID(),
);

// A held-down Enter repeats; only the first press may submit (a repeat would fire a burst of requests).
form.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && event.repeat) event.preventDefault();
});

form.addEventListener('submit', (event) => {
  event.preventDefault();
  void submit(input.value.trim());
});

const LABELS: Record<SubmissionFlow['phase'], { main: string; again: string }> = {
  idle: { main: 'Scan repository', again: 'Scan again' },
  submitting: { main: 'Submitting…', again: 'Submitting…' },
  scanning: { main: 'Scanning…', again: 'Scanning…' },
};

/**
 * Every submit control (the form button and any "Scan again") reflects one shared state: disabled while
 * submitting or while the followed scan is still running. Called whenever that state may have changed.
 */
function syncButtons(): void {
  const phase = submissions.phase;
  const { main, again } = LABELS[phase];
  button.disabled = phase !== 'idle';
  button.textContent = main;
  for (const b of document.querySelectorAll<HTMLButtonElement>('button.scan-again')) {
    b.disabled = phase !== 'idle';
    b.textContent = again;
  }
}

/** The one entry point for starting a scan (button click, Enter in the form, "Scan again"). */
async function submit(repoUrl: string): Promise<void> {
  if (submissions.busy) return; // shared guard: rapid clicks and Enter can't start a second scan
  formError.className = 'error';
  formError.textContent = '';
  const pending = submissions.submit(repoUrl);
  syncButtons(); // disabled at once, before the request returns
  const outcome = await pending;
  syncButtons();
  if (outcome.kind === 'accepted') {
    history.pushState(null, '', `/scans/${outcome.scanId}`);
    void follow(outcome.scanId);
  } else if (outcome.kind === 'error') {
    formError.textContent = outcome.message;
    // The session ended (the server has dropped its cookie): show "Sign in" again; the next scan is anonymous.
    if (outcome.status === 401) void loadMe();
  }
}

/** Ends following `scanId` (terminal or not found); a stale scan id changes nothing. */
function settle(scanId: string): void {
  submissions.settle(scanId);
  syncButtons();
}

let following: string | null = null;

async function follow(scanId: string): Promise<void> {
  following = scanId;
  // Locked until this scan settles, also when it was opened by reloading its page.
  submissions.follow(scanId);
  syncButtons();
  document.body.classList.add('has-scan'); // compact hero while a scan is on screen
  for (;;) {
    if (following !== scanId) return; // user started another scan
    let scan: ScanJson;
    try {
      const res = await api(`/scans/${scanId}`);
      if (following !== scanId) return;
      if (res.status === 401 || res.status === 404) {
        // Not retried: only signing in (again) can change the answer.
        settle(scanId);
        await renderAccessProblem(scanId, res.status);
        return;
      }
      if (res.status !== 200) {
        await pollProblem(scanId, `The server answered ${String(res.status)} while checking progress.`);
        continue;
      }
      scan = res.body as ScanJson;
    } catch {
      if (following !== scanId) return;
      await pollProblem(scanId, 'Lost connection to the server.');
      continue;
    }
    if (TERMINAL.has(scan.status)) {
      settle(scanId); // terminal: starting another scan is allowed again
      if (input.value === '') input.value = scan.repo.url;
      if (scan.status === 'completed') {
        await showReport(scanId);
      } else {
        renderOutcome(scan);
      }
      return;
    }
    renderProgress(scan);
    await sleep(1500);
  }
}

/**
 * The scan has finished; fetch its report until it arrives. A lost connection or an error answer shows a
 * recovery message and retries, and nothing is rendered once the user has moved on to another scan.
 */
async function showReport(scanId: string): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    if (following !== scanId) return;
    let problem: string;
    try {
      const res = await api(`/scans/${scanId}/report`);
      if (following !== scanId) return;
      if (res.status === 200) {
        renderReport(res.body as ReportJson);
        return;
      }
      if (res.status === 401 || res.status === 404) {
        await renderAccessProblem(scanId, res.status);
        return;
      }
      problem = `the server answered ${String(res.status)}`;
    } catch {
      problem = 'the connection was lost';
    }
    renderMessage(`The scan finished, but loading its report failed (${problem}). Retrying…`);
    await sleep(Math.min(1500 * attempt, 10_000));
  }
}

/**
 * A temporary error while checking progress: the scan keeps running and the buttons stay locked. The status is
 * checked again automatically, or right away with "Check again"; nothing is resubmitted.
 */
async function pollProblem(scanId: string, message: string): Promise<void> {
  let wake: () => void = () => undefined;
  const box = el('div', undefined, 'card');
  const retry = el('button', 'Check again', 'secondary');
  retry.type = 'button';
  retry.addEventListener('click', () => {
    wake();
  });
  const row = el('div', undefined, 'row');
  row.append(retry);
  box.append(el('div', `${message} The scan is still running; checking its status again shortly.`, 'muted'), row);
  if (following === scanId) result.replaceChildren(box);
  await new Promise<void>((resolve) => {
    wake = resolve;
    setTimeout(resolve, 3000);
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function repoTitle(scan: ScanJson): HTMLElement {
  const title = el('div', undefined, 'repo');
  const a = link(scan.repo.url, scan.repo.url);
  title.append(a);
  if (scan.visibility === 'private') title.append(' ', el('span', 'Private', 'tag private-tag'));
  if (scan.commitSha) title.append(' at commit ', el('code', scan.commitSha.slice(0, 7)));
  return title;
}

function renderMessage(text: string): void {
  result.replaceChildren(el('div', text, 'card'));
}

const STAGES: { stage: NonNullable<ScanJson['stage']>; label: string }[] = [
  { stage: 'fetching', label: 'Read dependencies' },
  { stage: 'scanning', label: 'Check for known vulnerabilities' },
  { stage: 'source', label: 'Check source code' },
  { stage: 'analyzing', label: 'Prioritize findings' },
];

/** Queued → fetch → check → rank, with the current step highlighted. */
function stepsBar(scan: ScanJson): HTMLElement {
  const bar = el('ol', undefined, 'steps-bar');
  const current = scan.status === 'running' && scan.stage ? STAGES.findIndex((s) => s.stage === scan.stage) : -1;
  bar.append(el('li', 'Waiting to start', scan.status === 'queued' ? 'active' : 'done'));
  STAGES.forEach((s, i) => {
    bar.append(el('li', s.label, i < current ? 'done' : i === current ? 'active' : ''));
  });
  return bar;
}

function renderProgress(scan: ScanJson): void {
  const box = el('div', undefined, 'card');
  const c = scan.counts;
  const line =
    scan.status === 'queued'
      ? 'Waiting for a worker…'
      : scan.status === 'retrying'
        ? `A temporary problem occurred${scan.error ? ` (${scan.error.message})` : ''}. Retrying automatically…`
        : scan.stage === 'fetching'
          ? 'Fetching the lockfile…'
          : scan.stage === 'scanning'
            ? `Checking ${String(c.totalDeps - c.unsupportedDeps)} dependencies against advisory data…`
            : scan.stage === 'source'
              ? 'Checking JavaScript/TypeScript source for disabled TLS verification…'
              : 'Preparing your report…';
  const status = el('div', undefined, scan.status === 'retrying' ? 'error' : 'muted');
  status.append(el('span', undefined, 'spinner'), line);
  box.append(repoTitle(scan), stepsBar(scan), status);
  result.replaceChildren(box);
}

function renderOutcome(scan: ScanJson): void {
  const box = el('div', undefined, 'card');
  const label = scan.status === 'unsupported' ? 'Could not scan this repository' : 'Scan failed';
  box.append(repoTitle(scan), el('div', label, 'error'), el('div', scan.error?.message ?? ''), scanAgainButton(scan));
  result.replaceChildren(box);
}

const dateOf = (scan: ScanJson) => (scan.completedAt ? new Date(scan.completedAt).toLocaleString() : '');

/** 1. Summary line, with date, commit, lockfile, coverage and advisory source always beside it. */
function summaryCard(report: ReportJson): HTMLElement {
  const { scan } = report;
  const c = scan.counts;
  const box = el('section', undefined, 'card');
  box.append(repoTitle(scan));
  box.append(el('p', `${report.summary ?? ''}${sourceHeadline(report.source)}`, 'summary'));
  // Both independent checks first, then the dependency details.
  box.append(checksOverview(report));
  box.append(statTiles(report));
  if (report.explanation) box.append(prose(report.explanation, 'explanation'));
  const meta = el('ul', undefined, 'meta');
  const coverage =
    scan.coverage === 'partial'
      ? `Coverage: partial (${String(c.checkedDeps)} of ${String(c.totalDeps)} checked)`
      : `Coverage: ${String(c.checkedDeps)} of ${String(c.totalDeps)} dependencies checked`;
  for (const item of [
    `Scanned ${dateOf(scan)}`,
    scan.lockfilePath ? `Lockfile: ${scan.lockfilePath}` : null,
    coverage,
    scan.advisorySource ? `Advisory data: ${scan.advisorySource}` : null,
  ]) {
    if (item) meta.append(el('li', item));
  }
  box.append(meta);
  // Two different reasons, two different remedies: keep them apart.
  const unsupported = report.unchecked.filter((u) => u.reason === 'unsupported_source');
  const lookupFailed = report.unchecked.filter((u) => u.reason === 'lookup_failed');
  if (unsupported.length > 0) {
    box.append(el('p', `Not checked, non-registry source: ${names(unsupported)}.`, 'muted'));
  }
  if (lookupFailed.length > 0) {
    box.append(el('p', `Not fully checked, advisory lookup failed (temporary): ${names(lookupFailed)}. Scan again to check them.`, 'muted'));
  }
  const invalid = report.unchecked.filter((u) => u.reason === 'invalid_name');
  if (invalid.length > 0) {
    box.append(el('p', `Not checked, not a valid npm package name: ${String(invalid.length)}. Review them by hand; see below.`, 'error'));
  }
  return box;
}

/** Dashboard-style counts, all straight from the report data. */
function statTiles(report: ReportJson): HTMLElement {
  const c = report.scan.counts;
  const malicious = report.actions.filter((a) => a.isMalicious).length;
  const tiles: [string, string, boolean][] = [
    [`${String(c.checkedDeps)} / ${String(c.totalDeps)}`, 'dependencies checked', false],
    [String(report.actions.length), report.actions.length === 1 ? 'package to act on' : 'packages to act on', false],
    [String(malicious), malicious === 1 ? 'known malicious' : 'known malicious', malicious > 0],
    [String(report.findings.length), report.findings.length === 1 ? 'advisory record' : 'advisory records', false],
  ];
  const grid = el('div', undefined, 'stats');
  for (const [value, label, alert] of tiles) {
    const tile = el('div', undefined, alert ? 'stat alert' : 'stat');
    tile.append(el('b', value), el('span', label));
    grid.append(tile);
  }
  return grid;
}

const KIND_LABEL: Record<ActionJson['kind'], string> = {
  remove_malicious: 'Malicious',
  upgrade: 'Upgrade',
  no_fix: 'No fix published',
  review: 'Review',
};

function severityTag(severity: Severity, malicious: boolean): HTMLElement {
  return malicious ? el('span', 'malicious', 'tag mal') : el('span', severity, `tag sev-${severity}`);
}

/** 2 + 3. One recommended action: what, why first, how to verify; evidence expandable. */
function actionCard(a: ActionJson, findings: FindingJson[]): HTMLElement {
  const card = el('article', undefined, `action action-${a.kind}`);
  const head = el('div', undefined, 'action-head');
  head.append(el('span', String(a.rank), 'rank'), severityTag(a.severity, a.isMalicious));
  // The malicious tag already says it; repeating "Malicious" beside it adds nothing.
  if (!a.isMalicious) head.append(el('span', KIND_LABEL[a.kind], 'kind'));
  card.append(head);
  if (a.text) {
    card.append(el('h3', a.text.headline));
    const steps = el('ul', undefined, 'steps');
    for (const s of a.text.steps) steps.append(richText('li', s));
    card.append(steps);
    card.append(labelled('Why first', a.text.why));
    if (a.whyItMatters) card.append(prose(a.whyItMatters, 'why-matters', 'Why it matters: '));
    card.append(labelled('How to verify', a.text.verify));
  } else {
    card.append(el('h3', `${a.package} (${a.ecosystem})`), el('p', 'See the advisories for fixed versions.', 'muted'));
  }

  const evidence = el('details', undefined, 'evidence');
  const records = a.versions.reduce((n, v) => n + v.advisories.length, 0);
  evidence.append(el('summary', `Evidence: ${String(records)} advisory ${records === 1 ? 'record' : 'records'}`));
  for (const v of a.versions) {
    const f = findings.find((x) => x.ecosystem === a.ecosystem && x.package === a.package && x.installedVersion === v.installedVersion);
    const block = el('div', undefined, 'evidence-version');
    block.append(
      el('div', [`${a.package} ${v.installedVersion}`, v.scope, ...routesOf(a.package, v)].join(' · '), 'strong'),
    );
    const paths = f?.installPaths ?? [];
    if (paths.length > 0) block.append(el('div', `Install path: ${paths.map((p) => p.join(' › ')).join('  |  ')}`, 'muted'));
    if (f?.contextTruncated === true) {
      block.append(
        el('div', 'Dependency context truncated: the install graph was too large or deep to list every parent and path. The finding itself is complete.', 'muted'),
      );
    }
    const list = el('ul');
    for (const adv of v.advisories) {
      const li = el('li');
      li.append(link(adv.id, `https://osv.dev/vulnerability/${encodeURIComponent(adv.id)}`), ' ', severityTag(adv.severity, false));
      if (adv.title) li.append(' ', adv.title);
      li.append(
        el(
          'span',
          adv.fixStatus === 'candidate'
            ? ` · candidate ${adv.candidateVersion ?? ''}`
            : adv.fixStatus === 'no_fix'
              ? ' · no fixed version published'
              : ' · see the advisory for fixed versions',
          'muted',
        ),
      );
      list.append(li);
    }
    block.append(list);
    evidence.append(block);
  }
  card.append(evidence);
  return card;
}

/** Every way this version is installed: each direct declaration (aliases named) and each parent. */
function routesOf(pkg: string, v: ActionVersionJson): string[] {
  const out: string[] = [];
  if (v.directAs.length > 0) out.push(v.directAs.every((n) => n === pkg) ? 'direct' : `direct as ${v.directAs.join(', ')}`);
  if (v.directParents.length > 0) out.push(`via ${v.directParents.join(', ')}`);
  return out.length > 0 ? out : ['transitive'];
}

const SOURCE_LABEL: Record<ProseJson['source'], { tag: string; title: string }> = {
  ai: { tag: 'AI', title: 'Written by an AI model and checked against the scan data. Versions, IDs and steps come from the scan, not from this text.' },
  template: { tag: 'Template', title: 'Generated from the scan data by a fixed template.' },
};

/** A piece of prose with its source shown beside it, so AI text is never mistaken for scan facts. */
function prose(p: ProseJson, className: string, lead = ''): HTMLElement {
  const box = el('p', undefined, `prose ${className}`);
  const tag = el('span', SOURCE_LABEL[p.source].tag, `source source-${p.source}`);
  tag.title = SOURCE_LABEL[p.source].title;
  box.append(tag, ' ', lead ? el('strong', lead) : '', p.text);
  return box;
}

function labelled(label: string, text: string): HTMLElement {
  const p = richText('p', `${label}: ${text}`, 'labelled');
  return p;
}

/** 4. All findings (ranked) and the dependencies that were not checked. */
function findingsSection(report: ReportJson): HTMLElement {
  const section = el('section');
  section.append(el('h2', `All findings (${String(report.findings.length)})`));
  const table = el('table');
  const head = el('tr');
  for (const h of ['Package', 'Version', 'Severity', 'Advisory', 'Dependency', 'Candidate']) head.append(el('th', h));
  table.append(el('thead'), el('tbody'));
  table.tHead?.append(head);
  for (const f of report.findings) {
    const row = el('tr');
    row.append(el('td', f.package), el('td', f.installedVersion));
    const sev = el('td');
    sev.append(severityTag(f.severity, f.isMalicious));
    const adv = el('td');
    adv.append(link(f.advisoryId, `https://osv.dev/vulnerability/${encodeURIComponent(f.advisoryId)}`));
    if (f.title) adv.append(el('div', f.title, 'muted'));
    const dep = `${f.isDirect ? 'direct' : `via ${f.directParents.join(', ') || '?'}`}, ${f.scope}${f.contextTruncated === true ? ' (context truncated)' : ''}`;
    const candidate = f.fixStatus === 'candidate' ? (f.candidateVersion ?? '') : f.fixStatus === 'no_fix' ? 'none published' : 'see advisory';
    row.append(sev, adv, el('td', dep), el('td', candidate));
    table.tBodies[0]?.append(row);
  }
  const wrap = el('div', undefined, 'table-wrap');
  wrap.append(table);
  section.append(wrap);
  if (report.unchecked.length > 0) {
    const card = el('div', undefined, 'card');
    card.append(uncheckedList(report));
    section.append(card);
  }
  return section;
}

type Unchecked = ReportJson['unchecked'][number];

function names(items: Unchecked[], max = 8): string {
  const shown = items.slice(0, max).map((u) => u.package);
  return items.length > max ? `${shown.join(', ')} and ${String(items.length - max)} more` : shown.join(', ');
}

const UNCHECKED_GROUPS: { reason: Unchecked['reason']; title: string; advice: string }[] = [
  {
    reason: 'lookup_failed',
    title: 'Advisory lookup failed',
    advice:
      'Registry packages the advisory source could not be asked about, or only partly, this time. Any advisories that did arrive are listed with the findings. This is usually temporary: scan again to check them fully.',
  },
  {
    reason: 'invalid_name',
    title: 'Not a valid npm package name',
    advice:
      'The lockfile names these with characters no registry package can have (spaces, quotes, shell syntax). They were not checked and no command is generated for them. Treat them as suspicious and review the lockfile by hand.',
  },
  {
    reason: 'unsupported_source',
    title: 'Non-registry source',
    advice: 'Installed from git, a local file or another URL. Advisory data covers registry versions only, so these need a manual review.',
  },
];

/** Unchecked dependencies, grouped by reason, each with what to do about it. */
function uncheckedList(report: ReportJson): HTMLElement {
  const box = el('div');
  box.append(el('h3', `Not checked (${String(report.unchecked.length)})`));
  for (const g of UNCHECKED_GROUPS) {
    const items = report.unchecked.filter((u) => u.reason === g.reason);
    if (items.length === 0) continue;
    box.append(el('h4', `${g.title} (${String(items.length)})`), el('p', g.advice, 'muted'));
    const list = el('ul');
    for (const u of items) list.append(el('li', `${u.package}${u.version ? ` ${u.version}` : ''}`));
    box.append(list);
  }
  return box;
}

/** 5. Coding-agent prompt: preview before copy. */
function promptSection(report: ReportJson): HTMLElement {
  const section = el('section', undefined, 'card');
  section.append(el('h2', 'Hand off to a coding agent'));
  section.append(el('p', 'Built from the findings above, so it holds only scan data. Read it before you paste it.', 'muted'));
  const preview = el('details');
  preview.append(el('summary', 'Preview prompt'), el('pre', report.agentPrompt ?? ''));
  const copy = el('button', 'Copy prompt', 'primary');
  copy.type = 'button';
  copy.addEventListener('click', () => {
    void navigator.clipboard.writeText(report.agentPrompt ?? '').then(
      () => {
        copy.textContent = 'Copied';
        setTimeout(() => (copy.textContent = 'Copy prompt'), 2000);
      },
      () => {
        preview.open = true;
        copy.textContent = 'Copy failed: select the text in the preview';
      },
    );
  });
  const row = el('div', undefined, 'row');
  row.append(copy, scanAgainButton(report.scan));
  section.append(preview, row);
  return section;
}

function scanAgainButton(scan: ScanJson): HTMLButtonElement {
  const again = el('button', LABELS[submissions.phase].again, 'secondary scan-again');
  again.type = 'button';
  again.disabled = submissions.busy;
  again.addEventListener('click', () => {
    // Same flow as the form: a retry after a lost answer reuses the pending key; after a successful scan the
    // pending submission is cleared, so a deliberate rescan gets a new key.
    input.value = scan.repo.url;
    void submit(scan.repo.url);
  });
  return again;
}

/** Clean result: what was checked, what wasn't, and why to rescan. Never "secure"; partial is never clean. */
function cleanCard(report: ReportJson): HTMLElement {
  const { scan } = report;
  const c = scan.counts;
  const box = el('section', undefined, 'card');
  box.append(repoTitle(scan));
  if (c.totalDeps === 0) {
    box.append(el('p', `${report.summary ?? 'No dependencies to check.'}${sourceHeadline(report.source)}`, 'summary'));
  } else if (c.checkedDeps === 0 && c.failedLookups === 0) {
    // Nothing was assessed: not a clean result.
    box.append(el('p', `No dependencies could be checked.${sourceHeadline(report.source)}`, 'summary'));
    box.append(
      el('p', 'Every dependency in the lockfile comes from a source advisory data does not cover (git, local files or other URLs), so no dependency assessment was possible. They are listed below.'),
    );
    if (report.unchecked.length > 0) box.append(uncheckedList(report));
    const row = el('div', undefined, 'row');
    row.append(scanAgainButton(scan));
    box.append(row);
    return box;
  } else {
    const at = scan.commitSha ? ` at commit ${scan.commitSha.slice(0, 7)}` : '';
    const notChecked = c.totalDeps - c.checkedDeps;
    // A partial result leads with "partial", so it never reads as clean overall.
    box.append(
      el(
        'p',
        scan.coverage === 'partial'
          ? `Partial result: no known vulnerabilities in the ${String(c.checkedDeps)} of ${String(c.totalDeps)} dependencies that could be checked${at} on ${dateOf(scan)}. ${String(notChecked)} were not checked; see below.${sourceHeadline(report.source)}`
          : `No known vulnerabilities in ${String(c.checkedDeps)} of ${String(c.totalDeps)} dependencies checked${at} on ${dateOf(scan)}.${sourceHeadline(report.source)}`,
        'summary',
      ),
    );
  }
  box.append(checksOverview(report));
  const notes = el('ul', undefined, 'notes');
  notes.append(
    el('li', `Checked: ${scan.lockfilePath ?? 'the lockfile'} against ${scan.advisorySource ?? 'advisory data'}. Source code is covered only by the targeted source checks below.`),
    el('li', 'Advisories are published all the time: rescan later, or after dependency changes.'),
  );
  if (report.ciChecks.length > 0) notes.append(richText('li', `To catch new advisories automatically, add ${report.ciChecks.join(' or ')}.`));
  box.append(notes);
  if (report.unchecked.length > 0) box.append(uncheckedList(report));
  const row = el('div', undefined, 'row');
  row.append(scanAgainButton(scan));
  box.append(row);
  return box;
}

function renderReport(report: ReportJson): void {
  const source = sourceSection(report);
  if (report.dependencyNotChecked) {
    result.replaceChildren(dependencyNotCheckedCard(report), source);
    return;
  }
  if (report.findings.length === 0) {
    result.replaceChildren(cleanCard(report), source);
    return;
  }
  const nodes: HTMLElement[] = [summaryCard(report)];

  const top = report.actions.filter((a) => a.onSummary);
  const rest = report.actions.filter((a) => !a.onSummary);
  const actions = el('section');
  actions.append(el('h2', 'Recommended next actions'));
  for (const a of top) actions.append(actionCard(a, report.findings));
  if (rest.length > 0) {
    const more = el('details', undefined, 'more');
    more.append(el('summary', `${String(rest.length)} more ${rest.length === 1 ? 'action' : 'actions'}`));
    for (const a of rest) more.append(actionCard(a, report.findings));
    actions.append(more);
  }
  nodes.push(actions, findingsSection(report), source);
  if (report.agentPrompt) nodes.push(promptSection(report));
  result.replaceChildren(...nodes);
}

/**
 * The scan completed on its source check alone. Lead with what was checked (the source result), then show both
 * checks side by side, so a missing or old lockfile doesn't read as if the whole scan stopped.
 */
function dependencyNotCheckedCard(report: ReportJson): HTMLElement {
  const box = el('section', undefined, 'card');
  box.append(repoTitle(report.scan));
  box.append(el('p', report.source?.summary ?? 'Source checks finished.', 'summary'));
  if (report.explanation) box.append(prose(report.explanation, 'explanation'));
  box.append(checksOverview(report));
  const row = el('div', undefined, 'row');
  row.append(scanAgainButton(report.scan));
  box.append(row);
  return box;
}

/**
 * Source checks, apart from dependency findings: their own summary and coverage, then each finding with its
 * location at the scanned commit, the matched code, and what to do. Never claims the code is secure.
 */
/** Where the source check stands, as a short label and a colour (see sourceBadge). */
function sourceState(report: ReportJson): { label: string; tone: Tone } {
  return sourceBadge(report.source);
}

function dependencyState(report: ReportJson): { label: string; detail: string; tone: Tone } {
  const note = report.dependencyNotChecked;
  if (note) return { label: note.status === 'failed' ? 'Could not be checked' : 'Not checked', detail: note.message, tone: 'warn' };
  const c = report.scan.counts;
  const detail = `${String(c.checkedDeps)} of ${String(c.totalDeps)} dependencies checked`;
  if (c.totalDeps === 0) return { label: 'No dependencies', detail: 'The lockfile lists no dependencies.', tone: 'muted' };
  if (c.checkedDeps === 0) return { label: 'Not assessed', detail, tone: 'warn' };
  const n = report.actions.length;
  if (n === 0) return { label: report.scan.coverage === 'partial' ? 'No known vulnerabilities (partial)' : 'No known vulnerabilities', detail, tone: report.scan.coverage === 'partial' ? 'warn' : 'ok' };
  const serious = report.actions.some((a) => a.isMalicious || a.severity === 'critical' || a.severity === 'high');
  return { label: `${String(n)} ${n === 1 ? 'package' : 'packages'} to act on`, detail, tone: serious ? 'danger' : 'warn' };
}

function pill(label: string, tone: Tone): HTMLElement {
  return el('span', label, `pill pill-${tone}`);
}

/** The two independent checks side by side, at the top of every report. */
function checksOverview(report: ReportJson): HTMLElement {
  const grid = el('div', undefined, 'checks-overview');
  const dep = dependencyState(report);
  const depTile = el('div', undefined, `check-tile tone-${dep.tone}`);
  depTile.append(el('span', 'Dependencies', 'check-tile-name'), pill(dep.label, dep.tone), el('span', dep.detail, 'check-tile-detail'));

  const src = sourceState(report);
  const c = report.source?.counts;
  const srcTile = el('a', undefined, `check-tile tone-${src.tone}`);
  srcTile.href = '#source-checks';
  srcTile.append(
    el('span', 'Source code', 'check-tile-name'),
    pill(src.label, src.tone),
    el('span', c ? `${String(c.checked)} of ${String(c.eligible)} JavaScript/TypeScript files checked` : 'Not part of this scan', 'check-tile-detail'),
    el('span', 'View source checks ↓', 'check-tile-link'),
  );
  grid.append(depTile, srcTile);
  return grid;
}

/**
 * The source checks: an independent part of the scan, with its own status, coverage and rule checklist, then the
 * findings grouped by rule. Never claims the code is secure.
 */
function sourceSection(report: ReportJson): HTMLElement {
  const section = el('section', undefined, 'card source-card');
  section.id = 'source-checks';
  const src = report.source;
  const state = sourceState(report);

  const head = el('div', undefined, 'source-head');
  const titles = el('div');
  titles.append(el('span', 'Independent check', 'eyebrow'), el('h2', 'Source code checks'));
  const summary = src ? src.summary.replace(/^(Source checks|Partial source check): /, '') : 'Source checks were not run for this scan.';
  titles.append(el('p', summary.charAt(0).toUpperCase() + summary.slice(1), 'muted'));
  const pills = el('div', undefined, 'pills');
  pills.append(pill(state.label, state.tone));
  if (src?.status === 'partial') pills.append(pill('Partial coverage', 'warn'));
  head.append(titles, pills);
  section.append(head);
  if (!src || src.status === null) return section;

  const c = src.counts;
  if (c && src.status !== 'failed') {
    const { total, high } = sourceTotals(src);
    const medium = total - high;
    const grid = el('div', undefined, 'stats');
    const tiles: [string, string, boolean][] = [
      [`${String(c.checked)} / ${String(c.eligible)}`, 'JS/TS files checked', false],
      [String(total), total === 1 ? 'finding' : 'findings', false],
      [String(high), 'high', high > 0],
      [String(medium), 'medium', false],
    ];
    for (const [value, label, alert] of tiles) {
      const tile = el('div', undefined, alert ? 'stat alert' : 'stat');
      tile.append(el('b', value), el('span', label));
      grid.append(tile);
    }
    section.append(grid);
  }

  // What was checked: every rule, with its result. A clean result shows exactly what "no issues" covers.
  if (src.rules && src.status !== 'failed' && src.status !== 'no_files') {
    const list = el('ul', undefined, 'rule-list');
    for (const r of src.rules) {
      const li = el('li', undefined, r.matches > 0 ? 'rule-hit' : 'rule-clear');
      li.append(el('span', r.matches > 0 ? String(r.matches) : '✓', `rule-mark rule-mark-${r.matches > 0 ? r.severity : 'clear'}`));
      const text = el('div', undefined, 'rule-text');
      text.append(el('span', r.title, 'strong'), el('code', r.id));
      li.append(text);
      const result =
        r.matches === 0
          ? 'No match'
          : `${String(r.matches)} ${r.matches === 1 ? 'match' : 'matches'}${r.inTestFiles > 0 ? ` · ${String(r.inTestFiles)} in tests` : ''}`;
      li.append(el('span', result, 'rule-result'));
      list.append(li);
    }
    section.append(list);
  }

  if (c && src.status !== 'failed') {
    const notes = el('ul', undefined, 'notes muted');
    const n = (k: number, text: string) => {
      if (k > 0) notes.append(el('li', `${String(k)} ${text}`));
    };
    n(c.skippedLimit, 'files not checked: over the file-count or total-size limit.');
    n(c.skippedSize, 'files not checked: larger than the per-file limit.');
    n(c.skippedTime, 'files not checked: the time budget ran out.');
    n(c.fetchFailed, 'files could not be fetched from GitHub.');
    n(c.skippedParse ?? 0, 'files could not be read as code (nested too deeply) and were not checked.');
    n(c.skippedLinks, 'symbolic links or submodules not followed.');
    if (c.listingTruncated) notes.append(el('li', 'GitHub cut the file listing short: some files were not seen.'));
    if (notes.childElementCount > 0) section.append(notes);
  }

  // One card per rule: why it matters and what to do once, then every location.
  const byRule = new Map<string, SourceFindingJson[]>();
  for (const f of src.findings) byRule.set(f.ruleId, [...(byRule.get(f.ruleId) ?? []), f]);
  for (const group of byRule.values()) section.append(sourceRuleCard(group, src.rules?.find((r) => r.id === group[0]?.ruleId)));
  section.append(
    el(
      'p',
      'Targeted checks for disabled TLS certificate verification in .js, .jsx, .ts and .tsx files at the scanned commit. A match is not proof that the code runs or can be exploited, and no match does not mean the code is secure.',
      'muted small-print',
    ),
  );
  return section;
}

/** Matches listed before "N more". */
const SHOWN_LOCATIONS = 10;

function sourceRuleCard(group: SourceFindingJson[], rule?: { matches: number; inTestFiles: number }): HTMLElement {
  const first = group[0];
  const card = el('div', undefined, `action source-finding source-${first?.severity ?? 'medium'}`);
  if (!first) return card;
  const head = el('div', undefined, 'action-head');
  // Counts are of every match found; the list below may show only the highest-priority examples.
  const matches = rule?.matches ?? group.length;
  const tests = rule?.inTestFiles ?? group.filter((f) => f.testFile).length;
  const shown = matches > group.length ? ` (${String(group.length)} shown)` : '';
  head.append(
    el('span', first.severity, `tag sev-${first.severity}`),
    el('span', first.title, 'strong'),
    el('span', `${String(matches)} ${matches === 1 ? 'match' : 'matches'}${tests > 0 ? `, ${String(tests)} in test files` : ''}${shown}`, 'muted'),
  );
  card.append(head);
  card.append(first.whyItMatters ? prose(first.whyItMatters, 'why', 'Why it matters: ') : el('p', first.explanation), labelled('Next', first.nextAction));
  const list = el('ul', undefined, 'source-locations');
  for (const f of group.slice(0, SHOWN_LOCATIONS)) list.append(locationItem(f));
  card.append(list);
  if (group.length > SHOWN_LOCATIONS) {
    const more = el('details', undefined, 'more');
    more.append(el('summary', `${String(group.length - SHOWN_LOCATIONS)} more`));
    const rest = el('ul', undefined, 'source-locations');
    for (const f of group.slice(SHOWN_LOCATIONS)) rest.append(locationItem(f));
    more.append(rest);
    card.append(more);
  }
  return card;
}

/** One match: where (linked to the line at the scanned commit), whether it is test code, and the matched code. */
function locationItem(f: SourceFindingJson): HTMLElement {
  const li = el('li');
  const where = `${f.path}:${String(f.start.line)}:${String(f.start.column)}`;
  const loc = el('div', undefined, 'source-location');
  loc.append(f.url ? link(where, f.url) : el('code', where));
  if (f.testFile) loc.append(' ', el('span', 'test file', 'tag test-tag'));
  li.append(loc, el('code', f.excerpt, 'source-excerpt'));
  return li;
}

// --- GitHub sign-in, installations and the repository picker -------------------------------------------

let me: MeJson | null = null;

/** 401: the session expired; 404: missing, or private and not visible to this viewer. Never polled again. */
async function renderAccessProblem(scanId: string, status: number): Promise<void> {
  // Whether to offer sign-in depends on /me: wait for it, then render only if this scan is still on screen.
  if (me === null || status === 401) await loadMe();
  if (following !== scanId) return;
  const box = el('div', undefined, 'card');
  const signIn = me?.signInEnabled === true;
  if (status === 401) {
    box.append(el('p', 'Your session has expired. Sign in again to continue.', 'strong'));
  } else {
    box.append(el('p', 'Scan not found.', 'strong'));
    if (signIn && me?.session !== 'active') box.append(el('p', 'If this is a private scan, sign in to view it.', 'muted'));
  }
  if (signIn && (status === 401 || me?.session !== 'active')) {
    const a = el('a', 'Sign in with GitHub', 'button-link');
    a.href = signInHref(location.pathname);
    const row = el('div', undefined, 'row');
    row.append(a);
    box.append(row);
  }
  result.replaceChildren(box);
}

async function loadMe(): Promise<void> {
  try {
    const res = await api('/me');
    me = res.status === 200 ? (res.body as MeJson) : me;
  } catch {
    // Keep whatever we had; the page still works for public scans.
  }
  renderAuth();
  renderPicker();
}

function renderAuth(): void {
  authBox.replaceChildren();
  document.body.classList.toggle('signed-in', me?.session === 'active');
  // The hero's sign-in button: only when sign-in exists and nobody is signed in; returns to the current page.
  heroSignIn.hidden = !me?.signInEnabled || me.session === 'active';
  heroSignIn.href = signInHref(location.pathname);
  if (!me?.signInEnabled) return;
  if (me.session === 'active' && me.user) {
    const out = el('button', 'Sign out', 'secondary small');
    out.type = 'button';
    out.addEventListener('click', () => void signOut());
    authBox.append(el('span', `@${me.user.login}`, 'muted'), out);
  } else {
    const a = el('a', 'Sign in with GitHub', 'button-link small');
    a.href = signInHref(location.pathname);
    authBox.append(a);
  }
}

/** Logout ends the session, stops following any scan and removes everything rendered for it. */
async function signOut(): Promise<void> {
  following = null;
  submissions.unfollow();
  result.replaceChildren();
  picker.replaceChildren();
  document.body.classList.remove('has-scan');
  input.value = '';
  history.pushState(null, '', '/');
  syncButtons();
  try {
    await api('/auth/logout', { method: 'POST' });
  } catch {
    // The cookie may still be set; the next page load will show the real state.
  }
  me = me ? { ...me, session: 'none', user: null, installations: null } : null;
  await loadMe();
}

/**
 * Signed in: one dropdown of every repository both the user and the app can access, grouped by owner, right
 * under the URL field. Picking one fills the field; the same "Scan repository" button starts the scan.
 */
function renderPicker(): void {
  picker.replaceChildren();
  if (!me?.signInEnabled || me.session !== 'active') return;
  const installations = me.installations;

  if (installations === null) {
    picker.append(el('p', 'GitHub did not answer, so your repositories could not be listed. Reload to try again.', 'picker-note'));
    return;
  }
  if (installations.length === 0) {
    const cta = el('div', undefined, 'picker-cta');
    const text = el('div');
    text.append(el('strong', 'Scan private repositories'), el('span', 'Install the FirstFix app on your account or organization. Members can request it from an owner.'));
    const connect = el('a', 'Connect GitHub', 'picker-button');
    connect.href = '/github/connect';
    cta.append(text, connect);
    picker.append(cta);
    return;
  }

  const row = el('div', undefined, 'picker-row');
  const select = el('select');
  select.id = 'repo-select';
  select.setAttribute('aria-label', 'Choose one of your repositories');
  select.disabled = true;
  const placeholder = el('option', 'Loading your repositories…');
  placeholder.value = '';
  placeholder.selected = true;
  placeholder.disabled = true;
  select.append(placeholder);
  row.append(el('span', 'or', 'picker-or'), select);

  const meta = el('div', undefined, 'picker-meta');
  const accounts = el('span', undefined, 'picker-accounts');
  accounts.append(el('span', 'Connected:', 'picker-label'));
  for (const inst of installations) accounts.append(el('span', inst.account, 'picker-chip'));
  const manage = el('a', 'Manage access');
  manage.href = '/github/connect';
  meta.append(accounts, manage);
  const note = el('p', undefined, 'picker-note');
  picker.append(row, meta, note);

  select.addEventListener('change', () => {
    if (!select.value) return;
    input.value = `https://github.com/${select.value}`;
    formError.textContent = '';
    button.focus();
  });

  void (async () => {
    const results = await Promise.all(
      installations.map(async (inst) => {
        try {
          return await api(`/installations/${String(inst.id)}/repos`);
        } catch {
          return { status: 0, body: null };
        }
      }),
    );
    if (results.some((r) => r.status === 401)) {
      void loadMe(); // session expired: the header switches back to "Sign in with GitHub"
      return;
    }
    const ok = results.filter((r) => r.status === 200).map((r) => r.body as { repositories: RepoJson[]; truncated: boolean });
    const repos = ok.flatMap((r) => r.repositories);
    for (const [owner, list] of groupByOwner(repos)) {
      const group = el('optgroup');
      group.label = owner;
      for (const r of list) {
        const option = el('option', r.private ? `${r.name}  ·  private` : r.name);
        option.value = r.fullName;
        group.append(option);
      }
      select.append(group);
    }
    placeholder.textContent = repos.length > 0 ? `Choose a repository (${String(repos.length)})` : 'No repositories yet: use Manage access to add some';
    select.disabled = repos.length === 0;
    const problems: string[] = [];
    if (ok.length < results.length) problems.push('Some repositories could not be loaded; reload to try again.');
    if (ok.some((r) => r.truncated)) problems.push('Only the first 10,000 repositories per account are listed.');
    note.textContent = problems.join(' ');
  })();
}

function showQueryNotice(): void {
  const notice = noticeFromQuery(location.search);
  if (!notice) return;
  history.replaceState(null, '', location.pathname);
  formError.className = notice.error ? 'error' : 'notice';
  formError.textContent = notice.text;
}

function route(): void {
  const match = SCAN_PATH.exec(location.pathname);
  if (match?.[1]) {
    void follow(match[1]);
  } else {
    following = null;
    submissions.unfollow(); // not following a scan any more: a new one may be started
    syncButtons();
    document.body.classList.remove('has-scan');
    result.replaceChildren();
  }
}

window.addEventListener('popstate', route);
showQueryNotice();
route();
void loadMe();
