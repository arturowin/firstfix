/**
 * Who may read a scan (docs/ARCHITECTURE.md "Private repositories"). Pure: the session state and GitHub's
 * answer come in as data.
 *
 * Without a valid session, a missing and a private scan must look the same: 404 with no session cookie,
 * 401 `session_expired` with an expired or unknown one. With an active session, a private scan needs GitHub
 * to list its recorded repository id in the viewer's repositories for its recorded installation.
 */
export type SessionState = 'none' | 'expired' | 'active';

export type ScanBinding =
  | { kind: 'public' }
  | { kind: 'private'; repositoryId: number; installationId: number };

export type ReadGate =
  | { kind: 'allow' }
  | { kind: 'deny'; status: 404 | 401 }
  /** Ask GitHub whether the viewer can access this repository through this installation. */
  | { kind: 'check'; repositoryId: number; installationId: number };

export function scanReadGate(scan: ScanBinding | null, session: SessionState): ReadGate {
  if (scan?.kind === 'public') return { kind: 'allow' };
  if (session === 'none') return { kind: 'deny', status: 404 };
  if (session === 'expired') return { kind: 'deny', status: 401 };
  if (scan === null) return { kind: 'deny', status: 404 };
  return { kind: 'check', repositoryId: scan.repositoryId, installationId: scan.installationId };
}

/** The decision once GitHub has listed the viewer's repositories for the scan's installation (null: none). */
export function decideAfterCheck(repositoryId: number, accessibleIds: ReadonlySet<number> | null): ReadGate {
  return accessibleIds?.has(repositoryId) === true ? { kind: 'allow' } : { kind: 'deny', status: 404 };
}

const SCAN_PATH = /^\/scans\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Where sign-in may return to: the start page or a scan page on this site. Anything else becomes "/". */
export function safeReturnPath(input: unknown): string {
  return typeof input === 'string' && (input === '/' || SCAN_PATH.test(input)) ? input : '/';
}
