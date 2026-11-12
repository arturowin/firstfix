import { PermanentError, TransientError } from '../../ports/errors.ts';

export const API_VERSION = '2022-11-28';

/** GitHub's rate-limit answers: 429, or 403 with an exhausted limit or a Retry-After. */
export function isRateLimited(res: Response): boolean {
  return res.status === 429 || (res.status === 403 && (res.headers.get('x-ratelimit-remaining') === '0' || res.headers.has('retry-after')));
}

/** Timeouts are raised by fetchWithTimeout; this covers answers: 5xx and rate limits retry, the rest doesn't. */
export function transientOrPermanent(res: Response, what: string): Error {
  if (isRateLimited(res)) return new TransientError('github_rate_limited', `GitHub rate limit reached (${what}); will retry`);
  if (res.status >= 500) return new TransientError('github_unavailable', `GitHub answered ${String(res.status)} (${what})`);
  return new PermanentError('github_error', `GitHub answered ${String(res.status)} (${what})`);
}

/**
 * The `rel="next"` URL from a Link header, only if it stays on the same API origin: a token is never sent to a
 * URL that came from a response pointing elsewhere.
 */
export function nextPage(res: Response, apiBase: string): string | null {
  const link = res.headers.get('link');
  if (!link) return null;
  for (const part of link.split(',')) {
    const match = /<([^>]+)>\s*;\s*rel="next"/.exec(part);
    if (!match?.[1]) continue;
    try {
      const url = new URL(match[1]);
      return url.origin === new URL(apiBase).origin ? url.toString() : null;
    } catch {
      return null;
    }
  }
  return null;
}
