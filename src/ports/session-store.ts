/**
 * Server-side sign-in state. Secrets never leave the store in clear except to the caller that needs them:
 * the cookie holds a random token (only its hash is stored), the user's GitHub token and the PKCE verifier are
 * stored encrypted.
 */
export interface Session {
  /** Stable, non-secret key for this session (cache keys, logs). */
  key: string;
  githubUserId: number;
  githubLogin: string;
  /** The user's GitHub token, decrypted. */
  token: string;
  expiresAt: Date;
}

export type SessionLookup = { state: 'active'; session: Session } | { state: 'expired' } | { state: 'unknown' };

export interface SessionStore {
  /** Returns the cookie value (a new random token). */
  create(input: { githubUserId: number; githubLogin: string; token: string; expiresAt: Date }): Promise<{ cookie: string; key: string }>;
  /** `expired` for a known session past its expiry; `unknown` for anything else. */
  lookup(cookie: string): Promise<SessionLookup>;
  /** Deletes the session; returns its key if there was one. */
  delete(cookie: string): Promise<string | null>;
  /** Removes a session by key (GitHub rejected its token). */
  deleteByKey(key: string): Promise<void>;

  /** A one-time sign-in attempt, bound to a browser nonce. Returns the `state` to send to GitHub. */
  createOAuthState(input: { binding: string; codeVerifier: string; returnTo: string; ttlSeconds: number }): Promise<string>;
  /**
   * Consumes the state: succeeds at most once, only before it expires and only with the same binding.
   * A state presented with the wrong binding is consumed too (a forged attempt can't be retried).
   */
  consumeOAuthState(state: string, binding: string): Promise<{ codeVerifier: string; returnTo: string } | null>;
}

/** Retention for the worker: expired sessions and sign-in attempts. */
export interface SessionRetention {
  deleteExpired(batchSize: number): Promise<number>;
}
