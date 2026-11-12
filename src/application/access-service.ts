import { createHash, randomBytes } from 'node:crypto';
import { decideAfterCheck, safeReturnPath, scanReadGate, type ReadGate, type ScanBinding } from '../domain/access.ts';
import type { RepoRef } from '../domain/repo-url.ts';
import { PermanentError, TransientError } from '../ports/errors.ts';
import { UserTokenRejected, type AppInstallation, type GitHubAuth, type RepositoryList } from '../ports/github-auth.ts';
import type { Session, SessionStore } from '../ports/session-store.ts';
import { TtlCache } from './ttl-cache.ts';

/** The session was valid but GitHub no longer accepts its token: it has been deleted. Answer 401. */
export class SessionInvalid extends Error {
  constructor() {
    super('session no longer valid');
    this.name = 'SessionInvalid';
  }
}

/** GitHub could not answer and nothing live is cached. Answer 503; never fall back to an older decision. */
export class GitHubUnavailable extends Error {
  constructor(options?: { cause?: unknown }) {
    super('GitHub is unavailable', options);
    this.name = 'GitHubUnavailable';
  }
}

export type ResolvedSession = { state: 'none' } | { state: 'expired' } | { state: 'active'; session: Session };

export type SignInResult = { kind: 'ok'; cookie: string; returnTo: string } | { kind: 'error'; code: 'invalid_state' | 'denied' | 'github_unavailable' | 'sign_in_failed' };

/** The longest a session lives, whatever GitHub says about the token. */
const MAX_SESSION_MS = 8 * 60 * 60 * 1000;
const STATE_TTL_SECONDS = 600;

export interface AccessServiceOptions {
  github: GitHubAuth;
  sessions: SessionStore;
  /** The OAuth callback URL registered on the GitHub App (PUBLIC_URL + /auth/callback). */
  redirectUri: string;
  cacheTtlMs?: number;
  cacheMaxEntries?: number;
  now?: () => number;
  /** Per-call timeout for GitHub requests made on behalf of a page request. */
  timeoutMs?: number;
}

/**
 * Sign-in, sessions and repository access for the API (docs/ARCHITECTURE.md "Private repositories"). GitHub is
 * the only source of permissions: the user's installations and each installation's repository list, fetched
 * with the user's token, are cached per session for a fixed time and never used past it.
 */
export class AccessService {
  private readonly github: GitHubAuth;
  private readonly sessions: SessionStore;
  private readonly redirectUri: string;
  private readonly cache: TtlCache<AppInstallation[] | RepositoryList | null>;
  private readonly now: () => number;
  private readonly timeoutMs: number;

  constructor(options: AccessServiceOptions) {
    this.github = options.github;
    this.sessions = options.sessions;
    this.redirectUri = options.redirectUri;
    this.now = options.now ?? Date.now;
    this.cache = new TtlCache({ ttlMs: options.cacheTtlMs ?? 5 * 60 * 1000, maxEntries: options.cacheMaxEntries ?? 10_000, now: this.now });
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  installUrl(): string {
    return this.github.installUrl();
  }

  // --- sign-in -------------------------------------------------------------------------------------------

  /** A new one-time sign-in attempt. `binding` goes into the browser cookie; the browser goes to `url`. */
  async startSignIn(returnTo: unknown): Promise<{ binding: string; url: string; ttlSeconds: number }> {
    const binding = randomBytes(32).toString('base64url');
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
    const state = await this.sessions.createOAuthState({
      binding,
      codeVerifier,
      returnTo: safeReturnPath(returnTo),
      ttlSeconds: STATE_TTL_SECONDS,
    });
    return { binding, url: this.github.authorizeUrl({ state, codeChallenge, redirectUri: this.redirectUri }), ttlSeconds: STATE_TTL_SECONDS };
  }

  async finishSignIn(input: { code: unknown; state: unknown; error: unknown; binding: string | undefined }): Promise<SignInResult> {
    if (typeof input.state !== 'string' || input.binding === undefined) return { kind: 'error', code: 'invalid_state' };
    // Consumed before anything else, also when the user declined: a state is good for one callback only.
    const attempt = await this.sessions.consumeOAuthState(input.state, input.binding);
    if (!attempt) return { kind: 'error', code: 'invalid_state' };
    if (input.error !== undefined) return { kind: 'error', code: 'denied' };
    if (typeof input.code !== 'string' || input.code === '') return { kind: 'error', code: 'sign_in_failed' };

    const signal = AbortSignal.timeout(this.timeoutMs);
    try {
      const token = await this.github.exchangeCode({ code: input.code, codeVerifier: attempt.codeVerifier, redirectUri: this.redirectUri }, signal);
      const user = await this.github.user(token.token, signal);
      const cap = this.now() + MAX_SESSION_MS;
      const expiresAt = new Date(Math.min(token.expiresAt?.getTime() ?? cap, cap));
      const { cookie } = await this.sessions.create({ githubUserId: user.id, githubLogin: user.login, token: token.token, expiresAt });
      return { kind: 'ok', cookie, returnTo: attempt.returnTo };
    } catch (err) {
      // Our own deadline ran out (the HTTP layer rethrows its abort as-is): GitHub didn't answer in time.
      if (signal.aborted || err instanceof TransientError) return { kind: 'error', code: 'github_unavailable' };
      if (err instanceof PermanentError || err instanceof UserTokenRejected) return { kind: 'error', code: 'sign_in_failed' };
      throw err;
    }
  }

  /** Session state from the cookie; expiry is decided here, before any access check. */
  async resolve(cookie: string | undefined): Promise<ResolvedSession> {
    if (cookie === undefined || cookie === '') return { state: 'none' };
    const found = await this.sessions.lookup(cookie);
    // An unknown cookie (logged out elsewhere, deleted, made up) is treated like an expired session.
    return found.state === 'active' ? found : { state: 'expired' };
  }

  async signOut(cookie: string | undefined): Promise<void> {
    if (cookie === undefined || cookie === '') return;
    const key = await this.sessions.delete(cookie);
    if (key) this.cache.deletePrefix(`${key}|`);
  }

  // --- GitHub's view of the user -------------------------------------------------------------------------

  installations(session: Session): Promise<AppInstallation[]> {
    return this.cached(session, `${session.key}|i`, (signal) => this.github.installations(session.token, signal));
  }

  /**
   * The user is about to change, or has just changed, what the app can access on GitHub: drop this session's
   * cached lists so the next look is fresh. Only ever makes answers fresher, never more permissive.
   */
  forgetAccess(session: Session): void {
    this.cache.deletePrefix(`${session.key}|`);
  }

  /** Fresh from GitHub (setup-URL check): is this installation one the user can access? */
  async verifyInstallation(session: Session, installationId: number): Promise<boolean> {
    this.forgetAccess(session);
    const list = await this.call(session, (signal) => this.github.installations(session.token, signal));
    this.cache.set(`${session.key}|i`, list);
    return list.some((i) => i.id === installationId);
  }

  /** Repositories the user can access through one of their installations; null when it isn't theirs. */
  async repositories(session: Session, installationId: number): Promise<RepositoryList | null> {
    const mine = await this.installations(session);
    if (!mine.some((i) => i.id === installationId)) return null;
    return this.cached(session, `${session.key}|r|${String(installationId)}`, (signal) =>
      this.github.repositories(session.token, installationId, signal),
    );
  }

  /** For submit: the private repository the user can access through the installation for its owner, if any. */
  async privateTarget(session: Session, repo: RepoRef): Promise<{ repositoryId: number; installationId: number } | null> {
    const installation = (await this.installations(session)).find((i) => i.account.toLowerCase() === repo.owner);
    if (!installation) return null;
    const list = await this.repositories(session, installation.id);
    const match = list?.repositories.find((r) => r.owner.toLowerCase() === repo.owner && r.name.toLowerCase() === repo.name);
    return match?.private === true ? { repositoryId: match.id, installationId: installation.id } : null;
  }

  /** May this viewer read this scan? Applies the domain gate, asking GitHub only for private scans. */
  async readGate(scan: ScanBinding | null, viewer: ResolvedSession): Promise<ReadGate> {
    const gate = scanReadGate(scan, viewer.state);
    if (gate.kind !== 'check' || viewer.state !== 'active') return gate;
    const list = await this.repositories(viewer.session, gate.installationId);
    return decideAfterCheck(gate.repositoryId, list ? new Set(list.repositories.map((r) => r.id)) : null);
  }

  // --- helpers -------------------------------------------------------------------------------------------

  private async cached<V extends AppInstallation[] | RepositoryList | null>(
    session: Session,
    key: string,
    load: (signal: AbortSignal) => Promise<V>,
  ): Promise<V> {
    const hit = this.cache.get(key);
    if (hit !== undefined) return hit as V;
    const value = await this.call(session, load);
    this.cache.set(key, value);
    return value;
  }

  /** GitHub call on behalf of a session: a rejected token ends the session; outages are 503, never stale data. */
  private async call<V>(session: Session, load: (signal: AbortSignal) => Promise<V>): Promise<V> {
    const signal = AbortSignal.timeout(this.timeoutMs);
    try {
      return await load(signal);
    } catch (err) {
      // The deadline for this page request expired: the HTTP layer rethrows the abort itself, not a
      // TransientError. It means GitHub didn't answer in time, never "no access".
      if (signal.aborted) throw new GitHubUnavailable({ cause: err });
      if (err instanceof UserTokenRejected) {
        await this.sessions.deleteByKey(session.key);
        this.cache.deletePrefix(`${session.key}|`);
        throw new SessionInvalid();
      }
      if (err instanceof TransientError) throw new GitHubUnavailable({ cause: err });
      throw err;
    }
  }
}
