/**
 * Which folders are this project's workspaces, from the root entry's `workspaces` field (an array of globs, or
 * `{ packages: [...] }`). Only links into these are project code; any other `link: true` entry (e.g. a
 * `file:../local` dependency) is a real dependency from a non-registry source.
 * Globs: `*` matches within one path segment, `**` across segments; no other syntax is needed for npm workspaces.
 */
function patternsOf(root: unknown): string[] {
  if (typeof root !== 'object' || root === null) return [];
  const ws = (root as Record<string, unknown>)['workspaces'];
  const list = Array.isArray(ws)
    ? ws
    : typeof ws === 'object' && ws !== null && Array.isArray((ws as Record<string, unknown>)['packages'])
      ? ((ws as Record<string, unknown>)['packages'] as unknown[])
      : [];
  return list.filter((p): p is string => typeof p === 'string');
}

function globToRegExp(glob: string): RegExp {
  const normalized = glob.replace(/^\.\//, '').replace(/\/+$/, '');
  const re = normalized
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .split('**')
    .map((part) => part.replace(/\*/g, '[^/]*'))
    .join('.*');
  return new RegExp(`^${re}$`);
}

export function workspaceMatcher(rootEntry: unknown): (location: string) => boolean {
  const res = patternsOf(rootEntry).map(globToRegExp);
  return (location) => location !== '' && !location.startsWith('../') && res.some((r) => r.test(location));
}
