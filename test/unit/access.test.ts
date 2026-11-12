import { describe, expect, it } from 'vitest';
import { decideAfterCheck, safeReturnPath, scanReadGate, type ScanBinding, type SessionState } from '../../src/domain/access.ts';

const PUBLIC: ScanBinding = { kind: 'public' };
const PRIVATE: ScanBinding = { kind: 'private', repositoryId: 42, installationId: 7 };

describe('scanReadGate', () => {
  it.each<[string, ScanBinding | null, SessionState, ReturnType<typeof scanReadGate>]>([
    ['public, no session', PUBLIC, 'none', { kind: 'allow' }],
    ['public, expired session', PUBLIC, 'expired', { kind: 'allow' }],
    ['public, active session', PUBLIC, 'active', { kind: 'allow' }],
    ['private, no session', PRIVATE, 'none', { kind: 'deny', status: 404 }],
    ['missing, no session', null, 'none', { kind: 'deny', status: 404 }],
    ['private, expired session', PRIVATE, 'expired', { kind: 'deny', status: 401 }],
    ['missing, expired session', null, 'expired', { kind: 'deny', status: 401 }],
    ['missing, active session', null, 'active', { kind: 'deny', status: 404 }],
    ['private, active session', PRIVATE, 'active', { kind: 'check', repositoryId: 42, installationId: 7 }],
  ])('%s', (_name, scan, session, expected) => {
    expect(scanReadGate(scan, session)).toEqual(expected);
  });

  it('without a valid session, a missing scan and a private scan get the same answer', () => {
    for (const session of ['none', 'expired'] as const) {
      expect(scanReadGate(PRIVATE, session)).toEqual(scanReadGate(null, session));
    }
  });
});

describe('decideAfterCheck', () => {
  it('allows only when the exact repository id is listed', () => {
    expect(decideAfterCheck(42, new Set([1, 42]))).toEqual({ kind: 'allow' });
    expect(decideAfterCheck(42, new Set([1, 2]))).toEqual({ kind: 'deny', status: 404 });
  });

  it('denies when the installation is not the viewer’s (no listing)', () => {
    expect(decideAfterCheck(42, null)).toEqual({ kind: 'deny', status: 404 });
  });
});

describe('safeReturnPath', () => {
  it.each([
    ['/', '/'],
    ['/scans/0b6c2f6e-3a5b-4c1d-9e8f-1a2b3c4d5e6f', '/scans/0b6c2f6e-3a5b-4c1d-9e8f-1a2b3c4d5e6f'],
    ['https://evil.example/scans/x', '/'],
    ['//evil.example', '/'],
    ['/\\evil.example', '/'],
    ['/scans/../me', '/'],
    ['/scans/0b6c2f6e-3a5b-4c1d-9e8f-1a2b3c4d5e6f?x=1', '/'],
    ['/me', '/'],
    ['', '/'],
    [undefined, '/'],
    [['/'], '/'],
  ])('%j → %s', (input, expected) => {
    expect(safeReturnPath(input)).toBe(expected);
  });
});
