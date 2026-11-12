// Sign-in helpers for the page, free of DOM APIs so they can be tested directly.

export interface MeJson {
  signInEnabled: boolean;
  session: 'none' | 'expired' | 'active';
  user: { login: string } | null;
  installations: { id: number; account: string }[] | null;
  installUrl: string | null;
}

export interface RepoJson {
  id: number;
  owner: string;
  name: string;
  fullName: string;
  private: boolean;
}

const SCAN_PATH = /^\/scans\/[0-9a-f-]{36}$/;

/** Sign-in link that returns to the scan being viewed, or to the start page. */
export function signInHref(pathname: string): string {
  const back = SCAN_PATH.test(pathname) ? pathname : '/';
  return `/auth/login?return_to=${encodeURIComponent(back)}`;
}

/** Repositories grouped by owner (an organization installation can still list repos of several owners). */
export function groupByOwner(repos: readonly RepoJson[]): [string, RepoJson[]][] {
  const groups = new Map<string, RepoJson[]>();
  for (const r of repos) {
    const list = groups.get(r.owner) ?? [];
    list.push(r);
    groups.set(r.owner, list);
  }
  return [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([owner, list]) => [owner, [...list].sort((x, y) => x.name.localeCompare(y.name))]);
}

/** One-time notices GitHub's redirects leave in the query string; the page shows them and drops the query. */
export function noticeFromQuery(search: string): { text: string; error: boolean } | null {
  const q = new URLSearchParams(search);
  const auth = q.get('auth_error');
  if (auth !== null) {
    const text: Record<string, string> = {
      denied: 'Sign-in was cancelled on GitHub.',
      invalid_state: 'That sign-in link expired or was already used. Please sign in again.',
      github_unavailable: 'GitHub did not answer. Please try signing in again.',
    };
    return { text: text[auth] ?? 'Sign-in failed. Please try again.', error: true };
  }
  const connect = q.get('connect');
  if (connect === 'installed') return { text: 'GitHub connected. Your repositories are listed below.', error: false };
  if (connect !== null) {
    // GitHub doesn't tell us about approval requests, so this stays truthful rather than claiming a state.
    return {
      text: "FirstFix couldn't confirm a new installation. If you requested access for an organization, an owner must approve it on GitHub; the organization appears here once approved.",
      error: false,
    };
  }
  return null;
}
