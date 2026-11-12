/**
 * How a scan may read its repository, fixed at submit:
 * - `public`: never with credentials that can read private content.
 * - `installation`: the FirstFix GitHub App's installation, scoped to exactly this repository id.
 */
export type RepoAccess =
  | { kind: 'public' }
  | { kind: 'installation'; installationId: number; repositoryId: number };

/** Read access to a repository, always pinned to a commit. Errors: see ports/errors.ts. */
export interface RepoSource {
  /** The default branch's current commit. Not found / no access → PermanentError. */
  resolveDefaultCommit(
    repo: { owner: string; name: string },
    access: RepoAccess,
    signal: AbortSignal,
  ): Promise<{ sha: string; branch: string }>;
  /** The file at `path` (relative to the repository root) at exactly `sha`; null when there is none. */
  readFile(
    repo: { owner: string; name: string },
    access: RepoAccess,
    sha: string,
    path: string,
    signal: AbortSignal,
  ): Promise<string | null>;
}
