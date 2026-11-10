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
  commitSha: string | null;
  lockfilePath: string | null;
  advisorySource: string | null;
  status: 'queued' | 'running' | 'retrying' | 'completed' | 'unsupported' | 'failed';
  stage: 'fetching' | 'scanning' | 'analyzing' | null;
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

interface ReportJson {
  scan: ScanJson;
  summary: string | null;
  explanation: ProseJson | null;
  ciChecks: string[];
  actions: ActionJson[];
  findings: FindingJson[];
  unchecked: { ecosystem: string; package: string; version: string | null; reason: 'unsupported_source' | 'lookup_failed' | 'invalid_name' }[];
  agentPrompt: string | null;
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

// One key per intended submission: a double click or a retried request reuses it.
let pending: { url: string; key: string } | null = null;

form.addEventListener('submit', (event) => {
  event.preventDefault();
  void submit(input.value.trim());
});

async function submit(repoUrl: string, fresh = false): Promise<void> {
  formError.textContent = '';
  if (fresh || !pending || pending.url !== repoUrl) pending = { url: repoUrl, key: crypto.randomUUID() };
  button.disabled = true;
  try {
    const res = await api('/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'idempotency-key': pending.key },
      body: JSON.stringify({ repoUrl }),
    });
    const body = (res.body ?? {}) as { scanId?: string; error?: { message: string } };
    if ((res.status === 202 || res.status === 200) && body.scanId) {
      pending = null;
      history.pushState(null, '', `/scans/${body.scanId}`);
      void follow(body.scanId);
    } else {
      formError.textContent = body.error?.message ?? `Request failed (${String(res.status)})`;
    }
  } catch {
    formError.textContent = 'Could not reach the server. Try again.';
  } finally {
    button.disabled = false;
  }
}

let following: string | null = null;

async function follow(scanId: string): Promise<void> {
  following = scanId;
  document.body.classList.add('has-scan'); // compact hero while a scan is on screen
  for (;;) {
    if (following !== scanId) return; // user started another scan
    let scan: ScanJson;
    try {
      const res = await api(`/scans/${scanId}`);
      if (following !== scanId) return;
      if (res.status === 404) {
        renderMessage('Scan not found.');
        return;
      }
      if (res.status !== 200) {
        renderMessage(`The server answered ${String(res.status)} while checking progress; retrying…`);
        await sleep(3000);
        continue;
      }
      scan = res.body as ScanJson;
    } catch {
      renderMessage('Lost connection to the server; retrying…');
      await sleep(3000);
      continue;
    }
    if (TERMINAL.has(scan.status)) {
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
      if (res.status === 404) {
        renderMessage('Scan not found.');
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

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function repoTitle(scan: ScanJson): HTMLElement {
  const title = el('div', undefined, 'repo');
  const a = link(scan.repo.url, scan.repo.url);
  title.append(a);
  if (scan.commitSha) title.append(' at commit ', el('code', scan.commitSha.slice(0, 7)));
  return title;
}

function renderMessage(text: string): void {
  result.replaceChildren(el('div', text, 'card'));
}

const STAGES: { stage: NonNullable<ScanJson['stage']>; label: string }[] = [
  { stage: 'fetching', label: 'Fetch lockfile' },
  { stage: 'scanning', label: 'Check advisories' },
  { stage: 'analyzing', label: 'Rank and explain' },
];

/** Queued → fetch → check → rank, with the current step highlighted. */
function stepsBar(scan: ScanJson): HTMLElement {
  const bar = el('ol', undefined, 'steps-bar');
  const current = scan.status === 'running' && scan.stage ? STAGES.findIndex((s) => s.stage === scan.stage) : -1;
  bar.append(el('li', 'Queued', scan.status === 'queued' ? 'active' : 'done'));
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
            : 'Preparing results…';
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
  box.append(el('p', report.summary ?? '', 'summary'));
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
    [String(report.findings.length), 'advisory records', false],
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
  evidence.append(el('summary', `Evidence: ${String(a.versions.reduce((n, v) => n + v.advisories.length, 0))} advisory records`));
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
  const again = el('button', 'Scan again', 'secondary');
  again.type = 'button';
  again.addEventListener('click', () => {
    input.value = scan.repo.url;
    void submit(scan.repo.url, true);
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
    box.append(el('p', report.summary ?? 'No dependencies to check.', 'summary'));
  } else if (c.checkedDeps === 0 && c.failedLookups === 0) {
    // Nothing was assessed: not a clean result.
    box.append(el('p', 'No dependencies could be checked', 'summary'));
    box.append(
      el('p', 'Every dependency in the lockfile comes from a source advisory data does not cover (git, local files or other URLs), so no security assessment was possible. They are listed below.'),
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
          ? `Partial result: no known vulnerabilities in the ${String(c.checkedDeps)} of ${String(c.totalDeps)} dependencies that could be checked${at} on ${dateOf(scan)}. ${String(notChecked)} were not checked; see below.`
          : `No known vulnerabilities in ${String(c.checkedDeps)} of ${String(c.totalDeps)} dependencies checked${at} on ${dateOf(scan)}.`,
        'summary',
      ),
    );
  }
  const notes = el('ul', undefined, 'notes');
  notes.append(
    el('li', `Checked: ${scan.lockfilePath ?? 'the lockfile'} against ${scan.advisorySource ?? 'advisory data'}. Other files and code in the repository were not reviewed.`),
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
  if (report.findings.length === 0) {
    result.replaceChildren(cleanCard(report));
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
  nodes.push(actions, findingsSection(report));
  if (report.agentPrompt) nodes.push(promptSection(report));
  result.replaceChildren(...nodes);
}

function route(): void {
  const match = SCAN_PATH.exec(location.pathname);
  if (match?.[1]) {
    void follow(match[1]);
  } else {
    following = null;
    document.body.classList.remove('has-scan');
    result.replaceChildren();
  }
}

window.addEventListener('popstate', route);
route();
