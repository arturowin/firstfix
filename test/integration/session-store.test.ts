import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PostgresSessionRetention, PostgresSessionStore } from '../../src/adapters/postgres/session-store.ts';
import { SecretBox } from '../../src/adapters/secret-box.ts';
import { createTestEnv, type TestEnv } from '../support/env.ts';

describe('PostgresSessionStore', () => {
  let env: TestEnv;
  let store: PostgresSessionStore;
  const inAnHour = () => new Date(Date.now() + 3_600_000);

  beforeAll(async () => {
    env = await createTestEnv();
    store = new PostgresSessionStore(env.pool, new SecretBox('k'.repeat(32)));
  });
  afterAll(async () => {
    await env.close();
  });

  it('creates a session and finds it by cookie; the GitHub token is never stored in clear', async () => {
    const { cookie } = await store.create({ githubUserId: 11, githubLogin: 'alice', token: 'ghu_SECRET_TOKEN', expiresAt: inAnHour() });
    const found = await store.lookup(cookie);
    expect(found.state).toBe('active');
    if (found.state === 'active') expect(found.session).toMatchObject({ githubUserId: 11, githubLogin: 'alice', token: 'ghu_SECRET_TOKEN' });

    const { rows } = await env.pool.query<{ row: string }>('SELECT s::text AS row FROM sessions s');
    for (const r of rows) {
      expect(r.row).not.toContain('ghu_SECRET_TOKEN');
      expect(r.row).not.toContain(cookie);
    }
  });

  it('an expired session is expired; an unknown cookie is unknown', async () => {
    const { cookie } = await store.create({ githubUserId: 12, githubLogin: 'bob', token: 't', expiresAt: new Date(Date.now() - 1000) });
    expect((await store.lookup(cookie)).state).toBe('expired');
    expect((await store.lookup('made-up')).state).toBe('unknown');
  });

  it('a session sealed with another secret cannot be used', async () => {
    const { cookie } = await store.create({ githubUserId: 13, githubLogin: 'carol', token: 't', expiresAt: inAnHour() });
    const rotated = new PostgresSessionStore(env.pool, new SecretBox('z'.repeat(32)));
    expect((await rotated.lookup(cookie)).state).toBe('expired');
  });

  it('delete and deleteByKey end the session', async () => {
    const a = await store.create({ githubUserId: 14, githubLogin: 'd', token: 't', expiresAt: inAnHour() });
    expect(await store.delete(a.cookie)).toBe(a.key);
    expect((await store.lookup(a.cookie)).state).toBe('unknown');
    const b = await store.create({ githubUserId: 15, githubLogin: 'e', token: 't', expiresAt: inAnHour() });
    await store.deleteByKey(b.key);
    expect((await store.lookup(b.cookie)).state).toBe('unknown');
  });

  describe('OAuth state', () => {
    it('is consumed exactly once, by the same browser', async () => {
      const state = await store.createOAuthState({ binding: 'browser-1', codeVerifier: 'verifier', returnTo: '/', ttlSeconds: 600 });
      expect(await store.consumeOAuthState(state, 'browser-1')).toEqual({ codeVerifier: 'verifier', returnTo: '/' });
      expect(await store.consumeOAuthState(state, 'browser-1')).toBeNull();
    });

    it('a different browser cannot use it, and the attempt burns it', async () => {
      const state = await store.createOAuthState({ binding: 'browser-1', codeVerifier: 'v', returnTo: '/', ttlSeconds: 600 });
      expect(await store.consumeOAuthState(state, 'browser-2')).toBeNull();
      expect(await store.consumeOAuthState(state, 'browser-1')).toBeNull();
    });

    it('expires', async () => {
      const state = await store.createOAuthState({ binding: 'b', codeVerifier: 'v', returnTo: '/', ttlSeconds: 0 });
      await new Promise((r) => setTimeout(r, 20));
      expect(await store.consumeOAuthState(state, 'b')).toBeNull();
    });

    it('stores neither the state, the binding nor the verifier in clear', async () => {
      await store.createOAuthState({ binding: 'BINDING_VALUE', codeVerifier: 'VERIFIER_VALUE', returnTo: '/', ttlSeconds: 600 });
      const { rows } = await env.pool.query<{ row: string }>('SELECT o::text AS row FROM oauth_states o');
      for (const r of rows) {
        expect(r.row).not.toContain('BINDING_VALUE');
        expect(r.row).not.toContain('VERIFIER_VALUE');
      }
    });
  });

  it('retention removes expired sessions and states only', async () => {
    const live = await store.create({ githubUserId: 16, githubLogin: 'f', token: 't', expiresAt: inAnHour() });
    await store.create({ githubUserId: 17, githubLogin: 'g', token: 't', expiresAt: new Date(Date.now() - 1000) });
    await store.createOAuthState({ binding: 'b', codeVerifier: 'v', returnTo: '/', ttlSeconds: 0 });
    await new Promise((r) => setTimeout(r, 20));
    expect(await new PostgresSessionRetention(env.pool).deleteExpired(500)).toBeGreaterThanOrEqual(2);
    expect((await store.lookup(live.cookie)).state).toBe('active');
    const { rows } = await env.pool.query<{ n: number }>('SELECT count(*)::int AS n FROM sessions WHERE expires_at < now()');
    expect(rows[0]?.n).toBe(0);
  });
});
