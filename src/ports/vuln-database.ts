import type { Advisory } from '../domain/advisory.ts';

export interface PackageVersion {
  name: string;
  version: string;
}

/** Advisories per package@version (key `name@version`); packages with none are absent. */
export type AdvisoryLookup = Map<string, Advisory[]>;

export function packageKey(p: PackageVersion): string {
  return `${p.name}@${p.version}`;
}

export interface VulnDatabase {
  /** Known advisories for npm package versions. Any failed call → TransientError (partial results: M4). */
  lookup(packages: PackageVersion[], signal: AbortSignal): Promise<AdvisoryLookup>;
}
