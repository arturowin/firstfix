// Minimal M1 page: submit, follow progress, list findings. The full report layout comes in M2.
// All API data is rendered with textContent / attributes, never innerHTML.

interface ScanJson {
  id: string;
  repo: { url: string };
  commitSha: string | null;
  status: 'queued' | 'running' | 'retrying' | 'completed' | 'unsupported' | 'failed';
  stage: 'fetching' | 'scanning' | 'analyzing' | null;
  counts: { totalDeps: number; checkedDeps: number; unsupportedDeps: number; failedLookups: number };
  error: { code: string; message: string } | null;
  completedAt: string | null;
}

interface FindingJson {
  package: string;
  installedVersion: string;
  scope: 'runtime' | 'optional' | 'dev';
  isDirect: boolean;
  advisoryId: string;
  severity: string;
  isMalicious: boolean;
  title: string | null;
}

interface ReportJson {
  scan: ScanJson;
  findings: FindingJson[];
  unchecked: { package: string; version: string | null; reason: string }[];
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

async function api(path: string, init?: RequestInit): Promise<{ status: number; body: unknown }> {
  const headers = new Headers(init?.headers);
  headers.set('accept', 'application/json');
  const res = await fetch(path, { ...init, headers });
  return { status: res.status, body: await res.json() };
}

// One key per intended submission: a double click or a retried request reuses it.
let pending: { url: string; key: string } | null = null;

form.addEventListener('submit', (event) => {
  event.preventDefault();
  void submit();
});

async function submit(): Promise<void> {
  const repoUrl = input.value.trim();
  formError.textContent = '';
  if (!pending || pending.url !== repoUrl) pending = { url: repoUrl, key: crypto.randomUUID() };
  button.disabled = true;
  try {
    const res = await api('/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'idempotency-key': pending.key },
      body: JSON.stringify({ repoUrl }),
    });
    const status = res.status;
    const body = res.body as { scanId?: string; error?: { message: string } };
    if ((status === 202 || status === 200) && body.scanId) {
      pending = null;
      history.pushState(null, '', `/scans/${body.scanId}`);
      void follow(body.scanId);
    } else {
      formError.textContent = body.error?.message ?? `Request failed (${status})`;
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
  for (;;) {
    if (following !== scanId) return; // user started another scan
    let scan: ScanJson;
    try {
      const res = await api(`/scans/${scanId}`);
      if (res.status === 404) {
        renderMessage('Scan not found.');
        return;
      }
      scan = res.body as ScanJson;
    } catch {
      renderMessage('Lost connection to the server; retrying…');
      await sleep(3000);
      continue;
    }
    if (TERMINAL.has(scan.status)) {
      if (scan.status === 'completed') {
        const { body } = await api(`/scans/${scanId}/report`);
        renderReport(body as ReportJson);
      } else {
        renderOutcome(scan);
      }
      return;
    }
    renderProgress(scan);
    await sleep(1500);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function header(scan: ScanJson): HTMLElement {
  const box = el('div', undefined, 'status');
  const title = el('div');
  const link = el('a', scan.repo.url);
  link.href = scan.repo.url;
  link.rel = 'noopener noreferrer';
  title.append(link);
  if (scan.commitSha) title.append(' at commit ', el('code', scan.commitSha.slice(0, 7)));
  box.append(title);
  return box;
}

function renderMessage(text: string): void {
  result.replaceChildren(el('div', text, 'status'));
}

function renderProgress(scan: ScanJson): void {
  const box = header(scan);
  const c = scan.counts;
  const line =
    scan.status === 'queued'
      ? 'Waiting for a worker…'
      : scan.status === 'retrying'
        ? 'A temporary problem occurred; retrying…'
        : scan.stage === 'fetching'
          ? 'Fetching package-lock.json…'
          : scan.stage === 'scanning'
            ? `Checking ${c.totalDeps - c.unsupportedDeps} dependencies against OSV…`
            : 'Preparing results…';
  box.append(el('div', line, 'muted'));
  result.replaceChildren(box);
}

function renderOutcome(scan: ScanJson): void {
  const box = header(scan);
  const label = scan.status === 'unsupported' ? 'Could not scan this repository' : 'Scan failed';
  box.append(el('div', label, 'error'), el('div', scan.error?.message ?? ''));
  result.replaceChildren(box);
}

function renderReport(report: ReportJson): void {
  const { scan, findings, unchecked } = report;
  const box = header(scan);
  const c = scan.counts;
  const date = scan.completedAt ? new Date(scan.completedAt).toLocaleString() : '';
  const packages = new Set(findings.map((f) => `${f.package}@${f.installedVersion}`)).size;
  box.append(
    el(
      'div',
      findings.length === 0
        ? `No known vulnerabilities in ${c.checkedDeps} of ${c.totalDeps} dependencies checked (${date}).`
        : `${findings.length} advisories affect ${packages} package versions (${c.checkedDeps} of ${c.totalDeps} dependencies checked, ${date}).`,
    ),
  );
  if (c.unsupportedDeps > 0) {
    box.append(el('div', `Not checked: ${unchecked.map((u) => u.package).join(', ')} (non-registry source).`, 'muted'));
  }
  const nodes: HTMLElement[] = [box];

  if (findings.length > 0) {
    const table = el('table');
    const head = el('tr');
    for (const h of ['Package', 'Version', 'Severity', 'Advisory', 'Dependency']) head.append(el('th', h));
    table.append(el('thead'), el('tbody'));
    table.tHead?.append(head);
    for (const f of findings) {
      const row = el('tr');
      row.append(el('td', f.package), el('td', f.installedVersion));
      row.append(
        f.isMalicious ? el('td', 'malicious', 'mal') : el('td', f.severity, `sev-${f.severity}`),
      );
      const adv = el('td');
      const a = el('a', f.advisoryId);
      a.href = `https://osv.dev/vulnerability/${encodeURIComponent(f.advisoryId)}`;
      a.rel = 'noopener noreferrer';
      a.target = '_blank';
      adv.append(a);
      if (f.title) adv.append(el('div', f.title, 'muted'));
      row.append(adv, el('td', `${f.isDirect ? 'direct' : 'transitive'}, ${f.scope}`));
      table.tBodies[0]?.append(row);
    }
    const wrap = el('div', undefined, 'table-wrap');
    wrap.append(table);
    nodes.push(wrap);
  }
  result.replaceChildren(...nodes);
}

function route(): void {
  const match = SCAN_PATH.exec(location.pathname);
  if (match?.[1]) {
    void follow(match[1]);
  } else {
    following = null;
    result.replaceChildren();
  }
}

window.addEventListener('popstate', route);
route();
