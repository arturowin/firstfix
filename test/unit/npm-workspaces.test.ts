import { describe, expect, it } from 'vitest';
import { workspaceMatcher } from '../../src/domain/ecosystems/npm/workspaces.ts';

describe('workspace globs', () => {
  it.each([
    [['packages/*'], 'packages/ws', true],
    [['packages/*'], 'packages/a/b', false],
    [['packages/**'], 'packages/a/b', true],
    [['./apps/web/'], 'apps/web', true],
    [{ packages: ['libs/*'] }, 'libs/x', true],
    [['packages/*'], '../local', false],
    [['*'], '../local', false],
    [[], 'packages/ws', false],
    [undefined, 'packages/ws', false],
  ])('%j matches %s → %s', (workspaces, location, expected) => {
    expect(workspaceMatcher({ workspaces })(location)).toBe(expected);
  });
});
