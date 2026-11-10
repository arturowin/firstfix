import { TransientError } from '../ports/errors.ts';

export const USER_AGENT = 'ai-scan-review';

/** fetch with a per-call timeout combined with the job's signal. Network failures and timeouts are transient. */
export async function fetchWithTimeout(
  url: string,
  init: RequestInit & { timeoutMs: number; signal: AbortSignal; service: string },
): Promise<Response> {
  const { timeoutMs, service, signal, ...rest } = init;
  try {
    return await fetch(url, { ...rest, signal: AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) });
  } catch (err) {
    if (signal.aborted) throw err; // the job itself was cancelled (expired / claim lost): don't dress it up
    const timedOut = err instanceof DOMException && err.name === 'TimeoutError';
    throw new TransientError(
      timedOut ? `${service}_timeout` : `${service}_unreachable`,
      timedOut ? `${service} did not answer within ${timeoutMs / 1000}s` : `Could not reach ${service}`,
      { cause: err },
    );
  }
}
