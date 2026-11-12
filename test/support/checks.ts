/** Test helpers for the per-check fields added with source checks (M7). */
import { NO_SOURCE_COUNTS } from '../../src/domain/source-rules.ts';
import type { RepoSource } from '../../src/ports/repo-source.ts';
import type { DependencyCheck, SourceCheck, SourceFinding } from '../../src/ports/scan-repository.ts';

export const TREE_SHA = 'f'.repeat(40);

/** A completion's per-check fields for a scan whose dependency check completed and that had no source files. */
export const DEPENDENCIES_ONLY: { dependency: DependencyCheck; source: SourceCheck; sourceFindings: SourceFinding[] } = {
  dependency: { status: 'complete' },
  source: { status: 'no_files', counts: NO_SOURCE_COUNTS, error: null },
  sourceFindings: [],
};

/** RepoSource methods for a repository without JavaScript/TypeScript source files. */
export const NO_SOURCE_FILES: Pick<RepoSource, 'listTree' | 'readSourceFile'> = {
  listTree: () => Promise.resolve({ entries: [], truncated: false }),
  readSourceFile: () => Promise.resolve(null),
};
