import { describe, expect, it } from 'vitest';
import { SubmissionFlow, type PostResponse } from '../../src/web/submission.ts';

/**
 * A fake server with real idempotency: a key it has seen before gets the same scan back (200); a new key
 * creates a scan (202). `lose` drops the response of the next request after the server has acted on it.
 */
function fakeServer() {
  const scansByKey = new Map<string, string>();
  const keysSent: string[] = [];
  const control = { lose: false, status: null as number | null };
  let n = 0;
  const post = (repoUrl: string, key: string): Promise<PostResponse> => {
    keysSent.push(key);
    if (control.status !== null) {
      const status = control.status;
      control.status = null;
      return Promise.resolve({ status, body: { error: { message: `status ${String(status)}` } } });
    }
    const existing = scansByKey.get(key);
    const scanId = existing ?? `scan-${String(++n)}-${repoUrl}`;
    if (!existing) scansByKey.set(key, scanId);
    if (control.lose) {
      control.lose = false;
      return Promise.reject(new TypeError('Failed to fetch')); // created on the server, answer lost
    }
    return Promise.resolve({ status: existing ? 200 : 202, body: { scanId } });
  };
  let k = 0;
  return { post, newKey: () => `key-${String(++k)}`, keysSent, scansByKey, control };
}

describe('browser submission flow (Scan again idempotency, review finding)', () => {
  it('a rescan whose response is lost is retried with the same key; the server returns the scan it created', async () => {
    const s = fakeServer();
    const flow = new SubmissionFlow(s.post, s.newKey);
    const url = 'https://github.com/o/r';

    expect(await flow.submit(url)).toMatchObject({ kind: 'accepted' }); // the first scan
    s.control.lose = true;
    expect(await flow.submit(url)).toEqual({ kind: 'error', message: 'Could not reach the server. Try again.', retryable: true });
    const retry = await flow.submit(url); // the user clicks "Scan again" again
    expect(retry).toEqual({ kind: 'accepted', scanId: 'scan-2-https://github.com/o/r' });
    expect(s.keysSent).toEqual(['key-1', 'key-2', 'key-2']);
    expect(s.scansByKey.size).toBe(2); // one scan per intent, no duplicate

    // A deliberate rescan after that success is a new intent: new key, new scan.
    expect(await flow.submit(url)).toEqual({ kind: 'accepted', scanId: 'scan-3-https://github.com/o/r' });
    expect(s.keysSent.at(-1)).toBe('key-3');
  });

  it.each([429, 503])('a %i is retried with the same key', async (status) => {
    const s = fakeServer();
    const flow = new SubmissionFlow(s.post, s.newKey);
    s.control.status = status;
    expect(await flow.submit('https://github.com/o/r')).toMatchObject({ kind: 'error', retryable: true });
    expect(await flow.submit('https://github.com/o/r')).toMatchObject({ kind: 'accepted' });
    expect(s.keysSent).toEqual(['key-1', 'key-1']);
  });

  it('clicks while a request is in flight send nothing', async () => {
    const s = fakeServer();
    let release: (r: PostResponse) => void = () => undefined;
    let calls = 0;
    const flow = new SubmissionFlow(
      () => {
        calls++;
        return new Promise<PostResponse>((r) => (release = r));
      },
      s.newKey,
    );
    const first = flow.submit('https://github.com/o/r');
    expect(flow.busy).toBe(true);
    expect(await flow.submit('https://github.com/o/r')).toEqual({ kind: 'ignored' });
    expect(await flow.submit('https://github.com/o/r')).toEqual({ kind: 'ignored' });
    release({ status: 202, body: { scanId: 's1' } });
    expect(await first).toEqual({ kind: 'accepted', scanId: 's1' });
    expect(calls).toBe(1);
    expect(flow.busy).toBe(false);
  });

  it('the regular form keeps its behaviour: same repo after a failure reuses the key, another repo gets a new one, a 4xx starts fresh', async () => {
    const s = fakeServer();
    const flow = new SubmissionFlow(s.post, s.newKey);
    s.control.lose = true;
    await flow.submit('https://github.com/o/a');
    await flow.submit('https://github.com/o/b'); // changed their mind: a different repository
    s.control.status = 400;
    expect(await flow.submit('https://github.com/o/c')).toMatchObject({ kind: 'error', retryable: false, message: 'status 400' });
    await flow.submit('https://github.com/o/c'); // fixed input: a new attempt, new key
    expect(s.keysSent).toEqual(['key-1', 'key-2', 'key-3', 'key-4']);
  });
});
