import { describe, expect, it } from 'vitest';
import { groupByOwner, noticeFromQuery, signInHref } from '../../src/web/account.ts';

describe('signInHref', () => {
  it('returns to the scan being viewed', () => {
    expect(signInHref('/scans/0b6c2f6e-3a5b-4c1d-9e8f-1a2b3c4d5e6f')).toBe(
      '/auth/login?return_to=%2Fscans%2F0b6c2f6e-3a5b-4c1d-9e8f-1a2b3c4d5e6f',
    );
  });

  it('otherwise returns to the start page', () => {
    expect(signInHref('/elsewhere')).toBe('/auth/login?return_to=%2F');
  });
});

describe('groupByOwner', () => {
  it('groups and sorts by owner, then name', () => {
    const r = (owner: string, name: string) => ({ id: name.length, owner, name, fullName: `${owner}/${name}`, private: true });
    expect(groupByOwner([r('org', 'zeta'), r('acme', 'b'), r('org', 'alpha')]).map(([o, list]) => [o, list.map((x) => x.name)])).toEqual([
      ['acme', ['b']],
      ['org', ['alpha', 'zeta']],
    ]);
  });
});

describe('noticeFromQuery', () => {
  it('confirms only a verified installation', () => {
    expect(noticeFromQuery('?connect=installed')?.text).toMatch(/connected/);
  });

  it('stays truthful when the installation could not be verified (e.g. an approval request)', () => {
    const notice = noticeFromQuery('?connect=unverified');
    expect(notice?.text).toMatch(/owner must approve it on GitHub/);
    expect(notice?.text).not.toMatch(/pending/i);
  });

  it('explains sign-in errors', () => {
    expect(noticeFromQuery('?auth_error=invalid_state')).toEqual({ text: expect.stringMatching(/expired or was already used/) as unknown, error: true });
  });

  it('has nothing to say otherwise', () => {
    expect(noticeFromQuery('')).toBeNull();
  });
});
