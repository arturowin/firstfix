/**
 * The advisory-source contract (docs/ARCHITECTURE.md "Advisory source"). Every VulnDatabase adapter runs this
 * suite against its provider's recorded responses, through a harness that knows how to make the provider
 * answer. The expectations are provider-neutral: they mention only domain types and port errors.
 *
 * Recorded advisories used (each provider records its own response for these ids):
 * - GHSA-29mw-wpgm-hmr9: lodash 4.0.0 → fixed 4.17.21 (MODERATE); also lists lodash-rails on RubyGems
 * - GHSA-p8p7-x288-28g6: request, introduced 0, last affected 2.88.2, no fix (MODERATE)
 * - GHSA-9x64-5r7x-2q53: flatmap-stream malware, explicit version list only (CRITICAL)
 * - GHSA-wf5p-g6vw-rhxx: axios, two separate ranges (MODERATE)
 */
import { describe, expect, it } from 'vitest';
import type { Advisory } from '../../src/domain/advisory.ts';
import { PermanentError, TransientError } from '../../src/ports/errors.ts';
import type { PackageRef, VulnDatabase } from '../../src/ports/vuln-database.ts';

export interface ContractHarness {
  create(): VulnDatabase;
  /** The provider reports these recorded advisory ids for these packages (key: packageKey), none for others. */
  serveRecorded(idsByPackage: Record<string, string[]>): void;
  /** The provider reports `id` for every package, but has no details for it. */
  serveUnknownId(id: string): void;
  /** The provider is down (5xx) or unreachable. */
  serveOutage(kind: 'unavailable' | 'network'): void;
}

const signal = () => new AbortController().signal;
const npm = (name: string, version: string): PackageRef => ({ ecosystem: 'npm', name, version });

export function vulnDatabaseContract(provider: string, harness: ContractHarness): void {
  describe(`VulnDatabase contract: ${provider}`, () => {
    it('names its data source', () => {
      const { source } = harness.create();
      expect(source.name).toEqual(expect.any(String));
      expect(source.url).toMatch(/^https:\/\//);
    });

    it('normalises ranges: fixed, last affected (no fix), several ranges, explicit versions', async () => {
      harness.serveRecorded({
        'npm:lodash@4.17.20': ['GHSA-29mw-wpgm-hmr9'],
        'npm:request@2.88.2': ['GHSA-p8p7-x288-28g6'],
        'npm:axios@0.21.1': ['GHSA-wf5p-g6vw-rhxx'],
        'npm:flatmap-stream@0.1.1': ['GHSA-9x64-5r7x-2q53'],
      });
      const lookup = await harness
        .create()
        .lookup([npm('lodash', '4.17.20'), npm('request', '2.88.2'), npm('axios', '0.21.1'), npm('flatmap-stream', '0.1.1')], signal());

      expect(lookup.get('npm:lodash@4.17.20')).toEqual([
        expect.objectContaining<Partial<Advisory>>({
          id: 'GHSA-29mw-wpgm-hmr9',
          severity: 'medium',
          isMalicious: false,
          affectedRanges: [{ kind: 'range', introduced: '4.0.0', fixed: '4.17.21', lastAffected: null }],
        }),
      ]);
      expect(lookup.get('npm:request@2.88.2')?.[0]?.affectedRanges).toEqual([
        { kind: 'range', introduced: '0', fixed: null, lastAffected: '2.88.2' },
      ]);
      expect(lookup.get('npm:axios@0.21.1')?.[0]?.affectedRanges).toEqual(
        expect.arrayContaining([
          { kind: 'range', introduced: '1.0.0', fixed: '1.6.0', lastAffected: null },
          { kind: 'range', introduced: '0.8.1', fixed: '0.28.0', lastAffected: null },
        ]),
      );
      expect(lookup.get('npm:flatmap-stream@0.1.1')?.[0]).toMatchObject({
        severity: 'critical',
        isMalicious: true,
        affectedRanges: [{ kind: 'versions', versions: ['0.1.1'] }],
      });
    });

    it('a package with no advisories is absent', async () => {
      harness.serveRecorded({});
      const lookup = await harness.create().lookup([npm('left-pad', '1.3.0')], signal());
      expect(lookup.size).toBe(0);
    });

    it('filters by ecosystem and exact name', async () => {
      harness.serveRecorded({
        'npm:lodash-es@4.17.20': ['GHSA-29mw-wpgm-hmr9'],
        'RubyGems:lodash-rails@4.17.20': ['GHSA-29mw-wpgm-hmr9'],
        'npm:lodash-rails@4.17.20': ['GHSA-29mw-wpgm-hmr9'],
      });
      const lookup = await harness
        .create()
        .lookup(
          [npm('lodash-es', '4.17.20'), { ecosystem: 'RubyGems', name: 'lodash-rails', version: '4.17.20' }, npm('lodash-rails', '4.17.20')],
          signal(),
        );
      const fixed = [{ kind: 'range', introduced: '4.0.0', fixed: '4.17.21', lastAffected: null }];
      expect(lookup.get('npm:lodash-es@4.17.20')?.[0]?.affectedRanges).toEqual(fixed);
      expect(lookup.get('RubyGems:lodash-rails@4.17.20')?.[0]?.affectedRanges).toEqual(fixed);
      // The advisory covers lodash-rails only on RubyGems: nothing applies to an npm package of that name.
      expect(lookup.get('npm:lodash-rails@4.17.20')?.[0]?.affectedRanges ?? []).toEqual([]);
    });

    it('an id the provider has no details for is a transient error, not a silent gap', async () => {
      harness.serveUnknownId('GHSA-0000-0000-0000');
      await expect(harness.create().lookup([npm('a', '1.0.0')], signal())).rejects.toBeInstanceOf(TransientError);
    });

    it.each(['unavailable', 'network'] as const)('provider %s → TransientError (never a raw HTTP error)', async (kind) => {
      harness.serveOutage(kind);
      const err: unknown = await harness
        .create()
        .lookup([npm('a', '1.0.0')], signal())
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(TransientError);
      expect(err).not.toBeInstanceOf(PermanentError);
    });

    it('no packages → empty result', async () => {
      expect((await harness.create().lookup([], signal())).size).toBe(0);
    });
  });
}
