/**
 * GitHub sign-in settings for the API. All or nothing: none set → sign-in off (public scans only, as before);
 * some set → refuse to start, so a half-configured server never runs.
 */
export interface SignInConfig {
  clientId: string;
  clientSecret: string;
  slug: string;
  sessionSecret: string;
  publicUrl: string;
}

const NAMES = ['GITHUB_APP_CLIENT_ID', 'GITHUB_APP_CLIENT_SECRET', 'GITHUB_APP_SLUG', 'SESSION_SECRET', 'PUBLIC_URL'] as const;

export function signInConfig(env: Record<string, string | undefined>): SignInConfig | null {
  const values = NAMES.map((n) => env[n]?.trim() ?? '');
  const set = values.filter((v) => v !== '').length;
  if (set === 0) return null;
  if (set < NAMES.length) {
    const missing = NAMES.filter((_, i) => values[i] === '');
    throw new Error(`GitHub sign-in is partly configured; also set ${missing.join(', ')} (or unset all of ${NAMES.join(', ')})`);
  }
  const [clientId, clientSecret, slug, sessionSecret, publicUrl] = values as [string, string, string, string, string];
  let url: URL;
  try {
    url = new URL(publicUrl);
  } catch {
    throw new Error('PUBLIC_URL must be an absolute URL, e.g. https://firstfix.example.com');
  }
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
    throw new Error('PUBLIC_URL must use https (http is accepted only for localhost): session cookies are Secure');
  }
  if (sessionSecret.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters (e.g. openssl rand -hex 32)');
  return { clientId, clientSecret, slug, sessionSecret, publicUrl: url.origin };
}
