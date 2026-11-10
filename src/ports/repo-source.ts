/** Read access to a public repository, always pinned to a commit. Errors: see ports/errors.ts. */
export interface RepoSource {
  /** The default branch's current commit. Not found / private → PermanentError. */
  resolveDefaultCommit(repo: { owner: string; name: string }, signal: AbortSignal): Promise<{ sha: string; branch: string }>;
  /** The file at `path` (relative to the repository root) at exactly `sha`; null when there is none. */
  readFile(repo: { owner: string; name: string }, sha: string, path: string, signal: AbortSignal): Promise<string | null>;
}
