/**
 * package-lock.json (lockfileVersion 2/3) parsing. Pure: takes the parsed JSON, returns dependencies.
 * Rules: docs/ARCHITECTURE.md "Lockfile parsing rules".
 */

export type Scope = 'runtime' | 'optional' | 'dev';

/** One installed package@version, aggregated over every place it is installed. */
export interface LockedPackage {
  name: string;
  version: string;
  /** Most exposed scope across install locations: runtime > optional > dev. */
  scope: Scope;
  /** Installed at the top level and listed in the root package's dependency fields. */
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
  | { kind: 'unsupported'; reason: string };

const NPM_REGISTRY = 'https://registry.npmjs.org/';
const SCOPE_RANK: Record<Scope, number> = { runtime: 2, optional: 1, dev: 0 };
const NODE_MODULES = 'node_modules/';

interface RawEntry {
  version?: unknown;
  resolved?: unknown;
  link?: unknown;
  dev?: unknown;
  optional?: unknown;
  devOptional?: unknown;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function scopeOf(entry: RawEntry): Scope {
  if (entry.dev === true || entry.devOptional === true) return 'dev';
  if (entry.optional === true) return 'optional';
  return 'runtime';
}

/** Registry tarballs are checkable; local paths, git and other hosts are not. Missing `resolved` is tolerated. */
function isSupportedSource(resolved: unknown): boolean {
  if (typeof resolved !== 'string') return true;
  return resolved.startsWith(NPM_REGISTRY);
}

function rootDependencyNames(root: unknown): Set<string> {
  const names = new Set<string>();
  if (!isRecord(root)) return names;
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    const deps = root[field];
    if (isRecord(deps)) for (const n of Object.keys(deps)) names.add(n);
  }
  return names;
}

export function parseLockfile(json: unknown): ParseLockfileResult {
  if (!isRecord(json)) return { kind: 'unsupported', reason: 'package-lock.json is not a JSON object' };

  const version = json['lockfileVersion'];
  if (version !== 2 && version !== 3) {
    return {
      kind: 'unsupported',
      reason:
        typeof version === 'number'
          ? `lockfileVersion ${version} is not supported (only 2 and 3, written by npm 7 or later)`
          : 'package-lock.json has no lockfileVersion',
    };
  }

  const packages = json['packages'];
  if (!isRecord(packages)) return { kind: 'unsupported', reason: 'package-lock.json has no "packages" section' };

  const direct = rootDependencyNames(packages['']);
  const byKey = new Map<string, LockedPackage>();
  const uncheckable = new Map<string, UncheckablePackage>();

  for (const [path, value] of Object.entries(packages)) {
    // Only node_modules/ entries are dependencies. "" is the project itself; other keys are workspace folders.
    const at = path.lastIndexOf(NODE_MODULES);
    if (at === -1 || !isRecord(value)) continue;
    const entry = value as RawEntry;
    if (entry.link === true) continue; // workspace symlink: its own dependencies are listed separately

    const name = path.slice(at + NODE_MODULES.length);
    const ver = typeof entry.version === 'string' ? entry.version : null;

    if (!isSupportedSource(entry.resolved) || ver === null) {
      const k = `${name}@${ver ?? ''}`;
      if (!uncheckable.has(k)) uncheckable.set(k, { name, version: ver, reason: 'unsupported_source' });
      continue;
    }

    const isDirect = path === `${NODE_MODULES}${name}` && direct.has(name);
    const scope = scopeOf(entry);
    const key = `${name}@${ver}`;
    const seen = byKey.get(key);
    if (!seen) {
      byKey.set(key, { name, version: ver, scope, isDirect });
    } else {
      if (SCOPE_RANK[scope] > SCOPE_RANK[seen.scope]) seen.scope = scope;
      seen.isDirect ||= isDirect;
    }
  }

  const byName = (a: { name: string; version: string | null }, b: { name: string; version: string | null }) =>
    a.name.localeCompare(b.name) || (a.version ?? '').localeCompare(b.version ?? '');
  return {
    kind: 'ok',
    packages: [...byKey.values()].sort(byName),
    uncheckable: [...uncheckable.values()].sort(byName),
  };
}
