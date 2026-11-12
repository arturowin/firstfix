import { describe, expect, it } from 'vitest';
import { signInConfig } from '../../src/api/sign-in-config.ts';

const FULL = {
  GITHUB_APP_CLIENT_ID: 'Iv1.abc',
  GITHUB_APP_CLIENT_SECRET: 'secret',
  GITHUB_APP_SLUG: 'firstfix',
  SESSION_SECRET: 's'.repeat(32),
  PUBLIC_URL: 'https://firstfix.example.com/',
};

describe('signInConfig', () => {
  it('is off when nothing is set', () => {
    expect(signInConfig({})).toBeNull();
  });

  it('refuses a partial configuration and names what is missing', () => {
    expect(() => signInConfig({ GITHUB_APP_CLIENT_ID: 'x' })).toThrow(/GITHUB_APP_CLIENT_SECRET/);
  });

  it('accepts a full configuration and normalises the public URL to its origin', () => {
    expect(signInConfig(FULL)?.publicUrl).toBe('https://firstfix.example.com');
  });

  it.each(['http://firstfix.example.com', 'http://192.168.1.4:3000', 'not a url'])('refuses PUBLIC_URL %s', (url) => {
    expect(() => signInConfig({ ...FULL, PUBLIC_URL: url })).toThrow(/PUBLIC_URL/);
  });

  it('accepts http only on localhost', () => {
    expect(signInConfig({ ...FULL, PUBLIC_URL: 'http://localhost:3000' })?.publicUrl).toBe('http://localhost:3000');
  });

  it('refuses a short session secret', () => {
    expect(() => signInConfig({ ...FULL, SESSION_SECRET: 'short' })).toThrow(/SESSION_SECRET/);
  });
});
