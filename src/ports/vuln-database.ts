import type { Advisory } from '../domain/advisory.ts';
import type { EcosystemId } from '../domain/ecosystems/types.ts';

/** An exact package version in one ecosystem. */
export interface PackageRef {
  ecosystem: EcosystemId;
  name: string;
  version: string;
}

/** Advisories per package (key `ecosystem:name@version`, see packageKey); packages with none are absent. */
export type AdvisoryLookup = Map<string, Advisory[]>;

export function packageKey(p: PackageRef): string {
  return `${p.ecosystem}:${p.name}@${p.version}`;
}

export interface VulnDatabase {
  /** Known advisories for exact package versions. Any failed call → TransientError (partial results: M4). */
  lookup(packages: PackageRef[], signal: AbortSignal): Promise<AdvisoryLookup>;
}
