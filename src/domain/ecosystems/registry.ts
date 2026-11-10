import { npm } from './npm/index.ts';
import { packageLockFormat } from './npm/package-lock.ts';
import type { EcosystemRegistry } from './types.ts';

/** The supported lockfile formats, tried in this order at the repository root. Only npm today. */
export const defaultRegistry: EcosystemRegistry = {
  formats: [packageLockFormat],
  ecosystems: new Map([[npm.id, npm]]),
};

/** Shown when none of the registered lockfiles exists at the repository root. */
export function missingLockfileMessage(registry: EcosystemRegistry, shortSha: string): string {
  const files = registry.formats.flatMap((f) => f.fileNames).join(' or ');
  const ecosystems = [...registry.ecosystems.values()].map((e) => e.label).join(', ');
  return `No ${files} at the repository root (commit ${shortSha}). Only ${ecosystems} lockfiles are supported.`;
}
