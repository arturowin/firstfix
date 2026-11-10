// Browser-side submission state for POST /scans, kept free of DOM APIs so it can be tested directly.
//
// One Idempotency-Key per intended submission: a retry of the same repository (after a network error, a
// lost response, 429 or 503) reuses the key, so the server answers with the scan it may already have created
// instead of enqueuing a duplicate. Only a successful answer with a scan id ends the submission; the next
// deliberate scan, from the form or "Scan again", then starts with a new key. While a request is in flight,
// further submits are ignored (double clicks).

export interface PostResponse {
  status: number;
  body: unknown;
}

export type SubmitOutcome =
  | { kind: 'accepted'; scanId: string }
  /** Not accepted; `retryable` means the same key is kept for the next attempt. */
  | { kind: 'error'; message: string; retryable: boolean }
  /** A request is already in flight; nothing was sent. */
  | { kind: 'ignored' };

export class SubmissionFlow {
  private readonly post: (repoUrl: string, idempotencyKey: string) => Promise<PostResponse>;
  private readonly newKey: () => string;
  private pending: { url: string; key: string } | null = null;
  private inFlight = false;

  constructor(post: (repoUrl: string, idempotencyKey: string) => Promise<PostResponse>, newKey: () => string) {
    this.post = post;
    this.newKey = newKey;
  }

  /** True while a request is in flight: submit buttons should be disabled. */
  get busy(): boolean {
    return this.inFlight;
  }

  async submit(repoUrl: string): Promise<SubmitOutcome> {
    if (this.inFlight) return { kind: 'ignored' };
    // A different repository is a different intent; the same one is a retry of the pending submission.
    if (!this.pending || this.pending.url !== repoUrl) this.pending = { url: repoUrl, key: this.newKey() };
    const { key } = this.pending;

    this.inFlight = true;
    let res: PostResponse;
    try {
      res = await this.post(repoUrl, key);
    } catch {
      // The server may have created the scan and the answer was lost: keep the key for the retry.
      return { kind: 'error', message: 'Could not reach the server. Try again.', retryable: true };
    } finally {
      this.inFlight = false;
    }

    const body = (res.body ?? {}) as { scanId?: unknown; error?: { message?: unknown } };
    if ((res.status === 202 || res.status === 200) && typeof body.scanId === 'string') {
      this.pending = null; // done: the next deliberate scan gets a new key
      return { kind: 'accepted', scanId: body.scanId };
    }
    const message =
      typeof body.error?.message === 'string' ? body.error.message : `Request failed (${String(res.status)})`;
    // 429, 503 and server errors are worth retrying with the same key. A 4xx about the request itself (invalid
    // URL, key already used for another repository) won't change on retry: start fresh next time.
    const retryable = res.status === 429 || res.status >= 500;
    if (!retryable) this.pending = null;
    return { kind: 'error', message, retryable };
  }
}
