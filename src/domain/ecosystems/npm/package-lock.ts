/**
 * npm package-lock.json (lockfileVersion 2/3) parsing. Pure: takes the parsed JSON, returns dependencies.
 * Rules: docs/ARCHITECTURE.md "Lockfile parsing rules".
 */
import { MAX_INSTALL_PATHS, type LockedPackage, type ParseLockfileResult, type Scope, type UncheckablePackage } from '../../lockfile.ts';
import type { LockfileFormat } from '../types.ts';
import { buildInstallGraph } from './graph.ts';
import { isValidNpmName } from './name.ts';

const NPM_REGISTRY = 'https://registry.npmjs.org/';
const SCOPE_RANK: Record<Scope, number> = { runtime: 2, optional: 1, dev: 0 };
const NODE_MODULES = 'node_modules/';

interface RawEntry {
  name?: unknown;
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

export function parsePackageLock(json: unknown): ParseLockfileResult {
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

  const graph = buildInstallGraph(packages);
  const byKey = new Map<string, LockedPackage & { parentSet: Set<string> }>();
  const uncheckable = new Map<string, UncheckablePackage>();

  for (const [path, value] of Object.entries(packages)) {
    // Only node_modules/ entries are dependencies. "" is the project itself; other keys are workspace folders.
    const at = path.lastIndexOf(NODE_MODULES);
    if (at === -1 || !isRecord(value)) continue;
    const entry = value as RawEntry;
    if (entry.link === true) continue; // workspace symlink: its own dependencies are listed separately

    // The folder name is what the project imports; `name` is the real package when they differ
    // (npm aliases: "my-lodash": "npm:lodash@4.17.20"). Advisories are published under the real name.
    const folderName = path.slice(at + NODE_MODULES.length);
    const name = typeof entry.name === 'string' && entry.name !== '' ? entry.name : folderName;
    const ver = typeof entry.version === 'string' ? entry.version : null;

    // Names come from a repository-controlled file and end up in commands: anything the registry couldn't hold
    // (spaces, `;`, `$(`, quotes, …) is set aside unchecked, never looked up or put into a command.
    if (!isValidNpmName(name) || !isValidNpmName(folderName)) {
      const shown = (isValidNpmName(name) ? folderName : name).slice(0, 214);
      const k = `invalid:${shown}@${ver ?? ''}`;
      if (!uncheckable.has(k)) uncheckable.set(k, { name: shown, version: ver, reason: 'invalid_name' });
      continue;
    }

    if (!isSupportedSource(entry.resolved) || ver === null) {
      const k = `${name}@${ver ?? ''}`;
      if (!uncheckable.has(k)) uncheckable.set(k, { name, version: ver, reason: 'unsupported_source' });
      continue;
    }

    const isDirect = graph.direct.has(path);
    const scope = scopeOf(entry);
    const reach = graph.reach.get(path);
    const key = `${name}@${ver}`;
    let seen = byKey.get(key);
    if (!seen) {
      seen = { name, installedAs: [], directAs: [], version: ver, scope, isDirect, directParents: [], installPaths: [], parentSet: new Set() };
      byKey.set(key, seen);
    } else {
      if (SCOPE_RANK[scope] > SCOPE_RANK[seen.scope]) seen.scope = scope;
      seen.isDirect ||= isDirect;
    }
    if (!seen.installedAs.includes(folderName)) seen.installedAs.push(folderName);
    if (isDirect && !seen.directAs.includes(folderName)) seen.directAs.push(folderName);
    for (const p of reach?.parents ?? []) if (isValidNpmName(p)) seen.parentSet.add(p);
    seen.installPaths.push(...(reach?.paths ?? []).filter((p) => p.every(isValidNpmName)));
  }

  const packagesOut: LockedPackage[] = [...byKey.values()].map(({ parentSet, ...p }) => ({
    ...p,
    // Only worth reporting when some install uses another name; then list every name, the real one included.
    installedAs: p.installedAs.every((n) => n === p.name) ? [] : p.installedAs.sort(),
    directAs: p.directAs.sort(),
    directParents: [...parentSet].sort(),
    installPaths: shortestPaths(p.installPaths),
  }));

  const byName = (a: { name: string; version: string | null }, b: { name: string; version: string | null }) =>
    a.name.localeCompare(b.name) || (a.version ?? '').localeCompare(b.version ?? '');
  return {
    kind: 'ok',
    packages: packagesOut.sort(byName),
    uncheckable: [...uncheckable.values()].sort(byName),
  };
}

/** Unique paths, shortest first (then alphabetical), capped. */
function shortestPaths(paths: string[][]): string[][] {
  const unique = new Map(paths.map((p) => [p.join('\u0000'), p]));
  return [...unique.values()]
    .sort((a, b) => a.length - b.length || a.join('/').localeCompare(b.join('/')))
    .slice(0, MAX_INSTALL_PATHS);
}

export const packageLockFormat: LockfileFormat = {
  ecosystem: 'npm',
  fileNames: ['package-lock.json'],
  parse(text) {
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      return { kind: 'invalid', reason: 'package-lock.json is not valid JSON' };
    }
    return parsePackageLock(json);
  },
};
