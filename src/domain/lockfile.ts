/**
 * Ecosystem-neutral result of parsing a lockfile. Each format (src/domain/ecosystems/) produces this shape.
 */

export type Scope = 'runtime' | 'optional' | 'dev';

/** One installed package@version, aggregated over every place it is installed. */
export interface LockedPackage {
  /** Canonical package name: the one advisories are published under. */
  name: string;
  /**
   * Every name it is installed under, sorted, when one differs from `name` (npm aliases, e.g. "my-lodash" for
   * npm:lodash@4.17.20); empty when it is only installed under its own name.
   */
  installedAs: string[];
  /**
   * Names the project declares it under directly (root or workspace), sorted; each needs its own update.
   * Usually [name]; two aliases give two entries; empty when only installed transitively.
   */
  directAs: string[];
  version: string;
  /** Most exposed scope across install locations: runtime > optional > dev. */
  scope: Scope;
  /** Declared by the project itself (root or a workspace) and installed where that declaration resolves. */
  isDirect: boolean;
  /** Every direct dependency that pulls it in (itself excluded), sorted. Empty for formats without a graph. */
  directParents: string[];
  /** Shortest install paths from direct dependencies, shortest first, capped at MAX_INSTALL_PATHS. */
  installPaths: string[][];
}

export const MAX_INSTALL_PATHS = 5;

/** unsupported_source: git, file or other non-registry source; invalid_name: not a name the registry could hold. */
export type UnsupportedSourceReason = 'unsupported_source' | 'invalid_name';

export interface UncheckablePackage {
  name: string;
  version: string | null;
  reason: UnsupportedSourceReason;
}

export type ParseLockfileResult =
  | { kind: 'ok'; packages: LockedPackage[]; uncheckable: UncheckablePackage[] }
  /** A lockfile we recognise but do not support (e.g. an old format version). */
  | { kind: 'unsupported'; reason: string }
  /** Not a readable lockfile at all (e.g. invalid JSON). */
  | { kind: 'invalid'; reason: string };
