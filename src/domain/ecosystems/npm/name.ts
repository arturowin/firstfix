/**
 * npm package names come from a repository-controlled file, and end up in commands a person or a coding agent
 * may run (`npm install <name>@<version>`, `npm ls <name>`). Anything that isn't a name the npm registry could
 * hold is rejected here, so shell syntax can't ride along.
 *
 * Rules (npm's validate-npm-package-name, with legacy uppercase allowed): at most 214 characters; optional
 * `@scope/`; then URL-safe characters only (letters, digits, `-`, `.`, `_`, `~`), not starting with `.` or `_`.
 * No spaces, quotes, `;`, `|`, `&`, `$`, backticks, slashes beyond the scope separator, or anything else.
 */
const NAME = /^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*\/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$/;

export function isValidNpmName(name: string): boolean {
  return name.length > 0 && name.length <= 214 && NAME.test(name);
}
