/**
 * Ecosystem-neutral result of parsing a lockfile. Each format (src/domain/ecosystems/) produces this shape.
 */

export type Scope = 'runtime' | 'optional' | 'dev';

/** One installed package@version, aggregated over every place it is installed. */
export interface LockedPackage {
  name: string;
  version: string;
  /** Most exposed scope across install locations: runtime > optional > dev. */
  scope: Scope;
  /** Declared by the project itself (root or a workspace) and installed where that declaration resolves. */
  isDirect: boolean;
}

export type UnsupportedSourceReason = 'unsupported_source';

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
