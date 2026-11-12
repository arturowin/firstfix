/**
 * GitHub sign-in and the user's view of the FirstFix GitHub App, through the user's own token. GitHub limits
 * that token to what both the user and the app can access, so these listings are the access check.
 *
 * Errors: `UserTokenRejected` when GitHub refuses the token (signed out on GitHub, revoked, expired);
 * TransientError for timeouts, 5xx and rate limits; PermanentError for anything else.
 */
export interface GitHubUserToken {
  token: string;
  /** Null when GitHub issued a non-expiring token. */
  expiresAt: Date | null;
}

export interface GitHubUser {
  id: number;
  login: string;
}

export interface AppInstallation {
  id: number;
  /** The user or organization the app is installed on. */
  account: string;
}

export interface AccessibleRepository {
  id: number;
  owner: string;
  name: string;
  private: boolean;
}

export interface RepositoryList {
  repositories: AccessibleRepository[];
  /** More than the listing cap: the rest is not shown and can't be used. */
  truncated: boolean;
}

export class UserTokenRejected extends Error {
  constructor() {
    super('GitHub rejected the user token');
    this.name = 'UserTokenRejected';
  }
}

export interface GitHubAuth {
  /** Where to send the browser to sign in (OAuth for the app's user tokens, with state and PKCE S256). */
  authorizeUrl(input: { state: string; codeChallenge: string; redirectUri: string }): string;
  /** The app's install page ("Connect GitHub"). */
  installUrl(): string;
  /** Code → user token. An invalid or used code is a PermanentError. */
  exchangeCode(input: { code: string; codeVerifier: string; redirectUri: string }, signal: AbortSignal): Promise<GitHubUserToken>;
  user(token: string, signal: AbortSignal): Promise<GitHubUser>;
  /** Every installation of the app the user can access (all pages). */
  installations(token: string, signal: AbortSignal): Promise<AppInstallation[]>;
  /** Repositories both the user and the app can access through one installation; null when it isn't the user's. */
  repositories(token: string, installationId: number, signal: AbortSignal): Promise<RepositoryList | null>;
}
