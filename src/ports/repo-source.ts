/** Read access to a public repository, always pinned to a commit. Errors: see ports/errors.ts. */
export interface RepoSource {
  /** The default branch's current commit. Not found / private → PermanentError. */
  resolveDefaultCommit(repo: { owner: string; name: string }, signal: AbortSignal): Promise<{ sha: string; branch: string }>;
  /** `package-lock.json` at the repository root at exactly `sha`; null when there is none. */
  readLockfile(repo: { owner: string; name: string }, sha: string, signal: AbortSignal): Promise<string | null>;
}
