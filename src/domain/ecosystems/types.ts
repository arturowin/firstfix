import type { AffectedRange } from '../advisory.ts';
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
  /**
   * The command that moves a direct dependency to a version, e.g. `npm install lodash@4.17.21`. `alias` is the
   * name the project uses when it differs from the package's (npm: `npm install my-lodash@npm:lodash@4.17.21`).
   */
  upgradeCommand(pkg: string, version: string, alias?: string): string | null;
  /** Shows what pulls a package in, e.g. `npm ls qs`. */
  inspectCommand(pkg: string): string | null;
  /**
   * Generic forms for instructions, e.g. `npm install <package>@<version>`. The functions above return null
   * when a name or version fails the ecosystem's validation: no command is better than one carrying
   * repository-controlled text into a shell.
   */
  upgradeTemplate: string;
  inspectTemplate: string;
  /** How to move a transitive package when its direct parent can't be upgraded, e.g. npm `overrides`. */
  transitiveFix: string;
  /** CI checks suggested on a clean result. */
  ciChecks: readonly string[];
}

/** How an ecosystem orders versions. Without one, findings get no candidate version and no major-jump flag. */
export interface VersionScheme {
  isValid(version: string): boolean;
  /** Negative, zero or positive like Array.sort; only called with valid versions. */
  compare(a: string, b: string): number;
  /** Moving up from `from` to `to` leaves the range the ecosystem treats as compatible (npm: outside `^from`). */
  isMajorJump(from: string, to: string): boolean;
  inRange(version: string, range: AffectedRange): boolean;
}

export interface Ecosystem {
  id: EcosystemId;
  /** Human label, e.g. "npm". */
  label: string;
  versionScheme: VersionScheme | null;
  hints: RemediationHints;
}

/** Supported lockfile formats in priority order, and the ecosystems they belong to. */
export interface EcosystemRegistry {
  formats: readonly LockfileFormat[];
  ecosystems: ReadonlyMap<EcosystemId, Ecosystem>;
}
