/**
 * Provider-neutral advisory shape (docs/ARCHITECTURE.md "Advisory source"). Advisory-source adapters translate
 * their provider's format into these types; nothing outside src/adapters/<provider>/ knows provider formats.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

/**
 * Which versions of one package an advisory affects. Versions are in the ecosystem's own syntax.
 * - `range`: from `introduced` (inclusive; '0' = all earlier versions) up to `fixed` (exclusive) or
 *   `lastAffected` (inclusive). Both null = every later version is affected (no fix published).
 *   `fixed` null means no fixed version is published for this range. `limit` (optional, exclusive) bounds a
 *   range without being a fix: versions at or above it aren't affected, but it says nothing about a fix.
 * - `versions`: an explicit list. A version is affected if it is in any range OR in any list, so lists are
 *   kept even when ranges exist.
 */
export type AffectedRange =
  | { kind: 'range'; introduced: string; fixed: string | null; lastAffected: string | null; limit?: string | null }
  | { kind: 'versions'; versions: string[] };

/** An advisory as it applies to one package (ranges for that package only). */
export interface Advisory {
  id: string;
  aliases: string[];
  title: string | null;
  severity: Severity;
  /** Known malicious package (remove + rotate secrets), set by the adapter from provider data. */
  isMalicious: boolean;
  affectedRanges: AffectedRange[];
  references: { type: string; url: string }[];
}
