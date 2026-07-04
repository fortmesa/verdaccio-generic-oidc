import {ISessionStorage} from './types';
import {TokenSet} from 'openid-client';

const GC_INTERVAL_MS = 60_000;

type CacheEntry = {value: TokenSet | null; cachedAt: number};

/**
 * Wraps any ISessionStorage backend with a bounded-staleness in-memory
 * cache. `authenticate()` calls ss.get() on every single authenticated
 * npm/yarn request (package fetches, publishes, whoami -- not just logins),
 * so this is the hot path; caching it cuts a Redis/DynamoDB round-trip down
 * to one per session per `ttlSec` window instead of one per request.
 *
 * Negative results (a session that doesn't exist) are cached too, with the
 * same TTL -- safe because a client can only ever present a sessionId
 * after saveSession() has already durably written it (the /-/oidc/callback
 * handler awaits that write before the token reaches the browser), so
 * there's no "not yet written" race to worry about. This also means a
 * client retrying with an expired/revoked sessionId gets deflected locally
 * instead of re-querying the backend on every request -- though it does
 * NOT help against an attacker sending many *distinct* fake sessionIds,
 * since each one is still a first-time cache miss.
 *
 * Trade-off worth knowing: this introduces up to `ttlSec` of staleness
 * across replicas (each has its own independent cache), which would only
 * matter if something needed to invalidate a session sooner than its own
 * natural TTL -- there's no such mechanism today.
 */
export function NewCachedSessionStorage(
  inner: ISessionStorage,
  ttlSec: number,
): ISessionStorage {
  const cache = new Map<string, CacheEntry>();
  const ttlMs = ttlSec * 1000;

  const gcTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of cache) {
      if (now - entry.cachedAt >= ttlMs) cache.delete(key);
    }
  }, GC_INTERVAL_MS);
  gcTimer.unref?.();

  return {
    async close(): Promise<void> {
      clearInterval(gcTimer);
      await inner.close();
    },

    async set(key: string, value: TokenSet, expiresSec: number): Promise<void> {
      await inner.set(key, value, expiresSec);
      cache.set(key, {value, cachedAt: Date.now()});
    },

    async get(key: string): Promise<TokenSet | null> {
      const entry = cache.get(key);
      if (entry != null && Date.now() - entry.cachedAt < ttlMs) {
        return entry.value;
      }

      const value = await inner.get(key);
      cache.set(key, {value, cachedAt: Date.now()});
      return value;
    },
  };
}
