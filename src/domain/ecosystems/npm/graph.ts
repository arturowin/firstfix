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
  /**
   * False when the walk hit MAX_GRAPH_STEPS: parents and paths are then left empty everywhere rather than
   * partly filled (an incomplete "via X" would mislead). `direct` is always complete.
   */
  complete: boolean;
}

/** Shortest paths kept per install location while walking (the parser caps per package version too). */
export const PATHS_PER_LOCATION = 5;
/**
 * Upper bound on walk steps (edges followed, over every direct dependency). The walk is
 * O(direct x (locations + edges)); this keeps a crafted lockfile from burning CPU. Real lockfiles tried
 * (npm/cli, nestjs/nest) stay far below it.
 */
export const MAX_GRAPH_STEPS = 5_000_000;

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
  maxSteps: number = MAX_GRAPH_STEPS,
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

  // Each location's resolved dependencies, computed once (resolution walks up directories).
  const edges = new Map<string, string[]>();
  const edgesOf = (at: string): string[] => {
    let out = edges.get(at);
    if (!out) {
      out = depNames(packages[at], INSTALLED_FIELDS).flatMap((name) => {
        const next = resolve(at, name);
        return next === null ? [] : [next];
      });
      edges.set(at, out);
    }
    return out;
  };

  // Breadth-first from each direct dependency: the first visit of a location is its shortest path from it.
  // Memory stays bounded: one predecessor pointer per visited location (per walk), and a path is built only if
  // it would be among the location's PATHS_PER_LOCATION shortest.
  let steps = 0;
  for (const start of [...direct].sort()) {
    const root = nameAt(start);
    const prev = new Map<string, string | null>([[start, null]]);
    const depth = new Map<string, number>([[start, 1]]);
    const queue = [start];
    for (let i = 0; i < queue.length; i++) {
      const at = queue[i];
      if (at === undefined) break;
      const r = reachOf(at);
      if (at !== start) r.parents.add(root);
      offerPath(r, depth.get(at) ?? 1, () => pathFrom(at, prev));
      for (const next of edgesOf(at)) {
        if (++steps > maxSteps) {
          for (const v of reach.values()) {
            v.parents.clear();
            v.paths.length = 0;
          }
          return { direct, reach, complete: false };
        }
        if (prev.has(next)) continue;
        prev.set(next, at);
        depth.set(next, (depth.get(at) ?? 1) + 1);
        queue.push(next);
      }
    }
  }
  return { direct, reach, complete: true };
}

/** Names along the walk from its start to `at`, rebuilt from predecessor pointers. */
function pathFrom(at: string, prev: Map<string, string | null>): string[] {
  const names: string[] = [];
  for (let cur: string | null | undefined = at; cur; cur = prev.get(cur)) names.push(nameAt(cur));
  return names.reverse();
}

/**
 * Keeps the shortest paths, building a path only when it would make the cut. Once full, a path no shorter than
 * the longest kept is skipped without being built; walks run in direct-dependency name order, so among equally
 * short paths the earliest roots win.
 */
function offerPath(r: Reach, length: number, build: () => string[]): void {
  const worst = r.paths[r.paths.length - 1];
  if (r.paths.length >= PATHS_PER_LOCATION && worst !== undefined && length >= worst.length) return;
  r.paths.push(build());
  r.paths.sort((a, b) => a.length - b.length || a.join('/').localeCompare(b.join('/')));
  if (r.paths.length > PATHS_PER_LOCATION) r.paths.length = PATHS_PER_LOCATION;
}
