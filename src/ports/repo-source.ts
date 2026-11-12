import type { TreeEntry } from '../domain/source-files.ts';

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
  /** The default branch's current commit and its root tree. Not found / no access → PermanentError. */
  resolveDefaultCommit(
    repo: { owner: string; name: string },
    access: RepoAccess,
    signal: AbortSignal,
  ): Promise<{ sha: string; branch: string; treeSha: string }>;
  /** The file at `path` (relative to the repository root) at exactly `sha`; null when there is none. */
  readFile(
    repo: { owner: string; name: string },
    access: RepoAccess,
    sha: string,
    path: string,
    signal: AbortSignal,
  ): Promise<string | null>;
  /** Every entry of the commit's tree (recursive). `truncated`: GitHub cut the listing short. */
  listTree(
    repo: { owner: string; name: string },
    access: RepoAccess,
    treeSha: string,
    signal: AbortSignal,
  ): Promise<{ entries: TreeEntry[]; truncated: boolean }>;
  /**
   * A source file at exactly `commitSha`, at most `maxBytes` (larger → PermanentError `source_file_too_large`);
   * null when it can't be found while access still holds.
   */
  readSourceFile(
    repo: { owner: string; name: string },
    access: RepoAccess,
    commitSha: string,
    path: string,
    maxBytes: number,
    signal: AbortSignal,
  ): Promise<string | null>;
}
