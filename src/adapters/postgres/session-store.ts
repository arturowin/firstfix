import { timingSafeEqual } from 'node:crypto';
import type pg from 'pg';
import type { SessionLookup, SessionRetention, SessionStore } from '../../ports/session-store.ts';
import { randomToken, sha256, type SecretBox } from '../secret-box.ts';

export class PostgresSessionStore implements SessionStore {
  private readonly pool: pg.Pool;
  private readonly box: SecretBox;

  constructor(pool: pg.Pool, box: SecretBox) {
    this.pool = pool;
    this.box = box;
  }

  async create(input: { githubUserId: number; githubLogin: string; token: string; expiresAt: Date }): Promise<{ cookie: string; key: string }> {
    const cookie = randomToken();
    const keyHash = sha256(cookie);
    await this.pool.query(
      `INSERT INTO sessions (key_hash, github_user_id, github_login, token_encrypted, expires_at) VALUES ($1, $2, $3, $4, $5)`,
      [keyHash, input.githubUserId, input.githubLogin, this.box.seal(input.token), input.expiresAt],
    );
    return { cookie, key: keyHash.toString('hex') };
  }

  async lookup(cookie: string): Promise<SessionLookup> {
    const keyHash = sha256(cookie);
    const { rows } = await this.pool.query<{
      github_user_id: string;
      github_login: string;
      token_encrypted: Buffer;
      expires_at: Date;
      active: boolean;
    }>(
      `SELECT github_user_id, github_login, token_encrypted, expires_at, expires_at > now() AS active
         FROM sessions WHERE key_hash = $1`,
      [keyHash],
    );
    const row = rows[0];
    if (!row) return { state: 'unknown' };
    if (!row.active) return { state: 'expired' };
    let token: string;
    try {
      token = this.box.open(row.token_encrypted);
    } catch {
      // Sealed with another SESSION_SECRET (rotated): the session can't be used.
      return { state: 'expired' };
    }
    return {
      state: 'active',
      session: {
        key: keyHash.toString('hex'),
        githubUserId: Number(row.github_user_id),
        githubLogin: row.github_login,
        token,
        expiresAt: row.expires_at,
      },
    };
  }

  async delete(cookie: string): Promise<string | null> {
    const keyHash = sha256(cookie);
    const res = await this.pool.query('DELETE FROM sessions WHERE key_hash = $1', [keyHash]);
    return res.rowCount === 1 ? keyHash.toString('hex') : null;
  }

  async deleteByKey(key: string): Promise<void> {
    await this.pool.query('DELETE FROM sessions WHERE key_hash = $1', [Buffer.from(key, 'hex')]);
  }

  async createOAuthState(input: { binding: string; codeVerifier: string; returnTo: string; ttlSeconds: number }): Promise<string> {
    const state = randomToken();
    await this.pool.query(
      `INSERT INTO oauth_states (state_hash, binding_hash, verifier_encrypted, return_to, expires_at)
       VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))`,
      [sha256(state), sha256(input.binding), this.box.seal(input.codeVerifier), input.returnTo, input.ttlSeconds],
    );
    return state;
  }

  async consumeOAuthState(state: string, binding: string): Promise<{ codeVerifier: string; returnTo: string } | null> {
    // DELETE … RETURNING: at most one caller ever gets the row, also under concurrent callbacks.
    const { rows } = await this.pool.query<{ binding_hash: Buffer; verifier_encrypted: Buffer; return_to: string; live: boolean }>(
      `DELETE FROM oauth_states WHERE state_hash = $1
       RETURNING binding_hash, verifier_encrypted, return_to, expires_at > now() AS live`,
      [sha256(state)],
    );
    const row = rows[0];
    if (!row?.live) return null;
    if (!timingSafeEqual(row.binding_hash, sha256(binding))) return null;
    try {
      return { codeVerifier: this.box.open(row.verifier_encrypted), returnTo: row.return_to };
    } catch {
      return null;
    }
  }
}

/** Deletes expired sessions and sign-in attempts; needs no key, so the worker can run it. */
export class PostgresSessionRetention implements SessionRetention {
  private readonly pool: pg.Pool;

  constructor(pool: pg.Pool) {
    this.pool = pool;
  }

  async deleteExpired(batchSize: number): Promise<number> {
    const sessions = await this.pool.query(
      `DELETE FROM sessions WHERE key_hash IN (SELECT key_hash FROM sessions WHERE expires_at < now() LIMIT $1)`,
      [batchSize],
    );
    const states = await this.pool.query(
      `DELETE FROM oauth_states WHERE state_hash IN (SELECT state_hash FROM oauth_states WHERE expires_at < now() LIMIT $1)`,
      [batchSize],
    );
    return (sessions.rowCount ?? 0) + (states.rowCount ?? 0);
  }
}
