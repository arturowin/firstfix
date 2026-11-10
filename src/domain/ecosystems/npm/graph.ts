/**
 * The install graph of an npm lockfile (v2/v3 `packages`), for "which direct dependency pulls this in".
 *
 * - Project declarations: the root ("") and every workspace folder (a key without `node_modules/`). Their
 *   dependencies, devDependencies and optionalDependencies are direct.
 * - Installed packages depend on their dependencies, optionalDependencies and peerDependencies (npm 7+
 *   installs peers). Their devDependencies are not installed.
 * - A name resolves the way Node does: `<dir>/node_modules/<name>` from the requiring package's folder
 *   upwards to the root. A `link: true` entry points at its `resolved` folder; links into the project's own
 *   workspace folders are project code (their dependencies are declarations of their own), so they end a walk.
 */

import { workspaceMatcher } from './workspaces.ts';

const NODE_MODULES = 'node_modules/';
const PROJECT_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies'];
const INSTALLED_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'];

export interface Reach {
  /** Names of the direct dependencies that pull this location in (itself excluded). */
  parents: Set<string>;
  /** Shortest name path from each direct dependency that reaches it, e.g. ["express", "body-parser", "qs"]. */
  paths: string[][];
}

export interface InstallGraph {
  /** Install locations that a project declaration resolves to. */
  direct: Set<string>;
  reach: Map<string, Reach>;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function nameAt(location: string): string {
  return location.slice(location.lastIndexOf(NODE_MODULES) + NODE_MODULES.length);
}

const isInstalled = (location: string) => location.includes(NODE_MODULES);

function parentDir(dir: string): string {
  const slash = dir.lastIndexOf('/');
  return slash === -1 ? '' : dir.slice(0, slash);
}

function depNames(entry: unknown, fields: string[]): string[] {
  if (!isRecord(entry)) return [];
  return fields.flatMap((f) => {
    const deps = entry[f];
    return isRecord(deps) ? Object.keys(deps) : [];
  });
}

export function buildInstallGraph(
  packages: Record<string, unknown>,
  isWorkspace: (location: string) => boolean = workspaceMatcher(packages['']),
): InstallGraph {
  // Project code: the root's declared workspaces (that exist in the lockfile). Other folders a link points at
  // (file: dependencies) are dependencies, walked like any installed package.
  const isWorkspaceFolder = (location: string) => !isInstalled(location) && location in packages && isWorkspace(location);

  /** Where `name`, required from the package at `from`, is installed; null if missing or project code. */
  const resolve = (from: string, name: string): string | null => {
    for (let dir = from; ; dir = parentDir(dir)) {
      const candidate = dir === '' ? `${NODE_MODULES}${name}` : `${dir}/${NODE_MODULES}${name}`;
      const entry = packages[candidate];
      if (isRecord(entry)) {
        if (entry['link'] !== true) return candidate;
        const target = entry['resolved'];
        if (typeof target !== 'string' || isWorkspaceFolder(target) || !isRecord(packages[target])) return null;
        return target;
      }
      if (dir === '') return null;
    }
  };

  const projects = Object.keys(packages).filter((l) => l === '' || isWorkspaceFolder(l));
  const direct = new Set<string>();
  for (const project of projects) {
    for (const name of depNames(packages[project], PROJECT_FIELDS)) {
      const at = resolve(project, name);
      if (at !== null) direct.add(at);
    }
  }

  const reach = new Map<string, Reach>();
  const reachOf = (location: string): Reach => {
    let r = reach.get(location);
    if (!r) reach.set(location, (r = { parents: new Set(), paths: [] }));
    return r;
  };

  // Breadth-first from each direct dependency: the first visit of a location is its shortest path from it.
  for (const start of [...direct].sort()) {
    const root = nameAt(start);
    const pathTo = new Map<string, string[]>([[start, [root]]]);
    const queue = [start];
    for (let i = 0; i < queue.length; i++) {
      const at = queue[i];
      if (at === undefined) break;
      const path = pathTo.get(at) ?? [];
      const r = reachOf(at);
      r.paths.push(path);
      if (at !== start) r.parents.add(root);
      for (const name of depNames(packages[at], INSTALLED_FIELDS)) {
        const next = resolve(at, name);
        if (next === null || pathTo.has(next)) continue;
        pathTo.set(next, [...path, nameAt(next)]);
        queue.push(next);
      }
    }
  }
  return { direct, reach };
}
