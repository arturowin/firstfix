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

/** Where advisory data comes from; named in the report next to coverage. */
export interface AdvisorySourceInfo {
  name: string;
  url: string;
}

/**
 * Advisory source contract (docs/ARCHITECTURE.md "Advisory source"); every adapter passes
 * test/contract/vuln-database.contract.ts. Adapters translate provider formats into domain/advisory.ts types.
 */
export interface VulnDatabase {
  readonly source: AdvisorySourceInfo;
  /** Known advisories for exact package versions. Any failed call → TransientError (partial results: M4). */
  lookup(packages: PackageRef[], signal: AbortSignal): Promise<AdvisoryLookup>;
}
