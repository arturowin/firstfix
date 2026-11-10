import type { ParseLockfileResult } from '../lockfile.ts';

/**
 * Canonical ecosystem id. We use OSV's ecosystem names ('npm', 'PyPI', 'crates.io', ...) as a naming choice;
 * an advisory-source adapter maps them to its own names if they differ.
 */
export type EcosystemId = string;

/** A lockfile format: which files it reads at the repository root and how to parse them. Pure. */
export interface LockfileFormat {
  ecosystem: EcosystemId;
  /** Root-level file names, in the order they are tried. */
  fileNames: readonly string[];
  parse(text: string): ParseLockfileResult;
}

/** Per-ecosystem remediation wording used by the report and the coding-agent prompt. */
export interface RemediationHints {
  /** The command that moves a direct dependency to a version, e.g. `npm install lodash@4.17.21`. */
  upgradeCommand(pkg: string, version: string): string;
  /** CI checks suggested on a clean result. */
  ciChecks: readonly string[];
}

export interface Ecosystem {
  id: EcosystemId;
  /** Human label, e.g. "npm". */
  label: string;
  hints: RemediationHints;
}

/** Supported lockfile formats in priority order, and the ecosystems they belong to. */
export interface EcosystemRegistry {
  formats: readonly LockfileFormat[];
  ecosystems: ReadonlyMap<EcosystemId, Ecosystem>;
}
