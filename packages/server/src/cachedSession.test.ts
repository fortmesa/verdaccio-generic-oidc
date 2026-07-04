import {describe, it, expect, vi, beforeEach, afterEach} from 'vitest';
import {NewCachedSessionStorage} from './cachedSession';
import {ISessionStorage} from './types';
import {TokenSet} from 'openid-client';

function makeInner(): ISessionStorage & {getCalls: number; setCalls: number} {
  const store = new Map<string, TokenSet>();
  return {
    getCalls: 0,
    setCalls: 0,
    async close() {},
    async set(key: string, value: TokenSet) {
      this.setCalls++;
      store.set(key, value);
    },
    async get(key: string) {
      this.getCalls++;
      return store.get(key) ?? null;
    },
  };
}

const TTL_SEC = 5 * 60;
const tokenSet = {access_token: 'abc'} as TokenSet;

describe('NewCachedSessionStorage', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('serves get() from the cache populated by set(), never hitting the backend', async () => {
    const inner = makeInner();
    const cached = NewCachedSessionStorage(inner, TTL_SEC);

    await cached.set('session:1', tokenSet, 300);
    expect(await cached.get('session:1')).toEqual(tokenSet);
    expect(await cached.get('session:1')).toEqual(tokenSet);
    expect(inner.getCalls).toBe(0);
  });

  it('falls through to the backend on a cache miss, then serves the cache after', async () => {
    const inner = makeInner();
    await inner.set('session:1', tokenSet, 300);
    const cached = NewCachedSessionStorage(inner, TTL_SEC);

    expect(await cached.get('session:1')).toEqual(tokenSet);
    expect(await cached.get('session:1')).toEqual(tokenSet);
    expect(inner.getCalls).toBe(1);
  });

  it('re-fetches from the backend once the cache entry expires', async () => {
    const inner = makeInner();
    await inner.set('session:1', tokenSet, 300);
    const cached = NewCachedSessionStorage(inner, TTL_SEC);

    await cached.get('session:1');
    vi.advanceTimersByTime(TTL_SEC * 1000 + 1);
    await cached.get('session:1');

    expect(inner.getCalls).toBe(2);
  });

  it('caches a negative (not-found) result too', async () => {
    const inner = makeInner();
    const cached = NewCachedSessionStorage(inner, TTL_SEC);

    expect(await cached.get('session:missing')).toBeNull();
    expect(await cached.get('session:missing')).toBeNull();
    expect(inner.getCalls).toBe(1);
  });

  it('updates the cache on set() (write-through), reflected on the next get()', async () => {
    const inner = makeInner();
    const cached = NewCachedSessionStorage(inner, TTL_SEC);

    await cached.set('session:1', tokenSet, 300);
    const updated = {access_token: 'updated'} as TokenSet;
    await cached.set('session:1', updated, 300);

    expect(await cached.get('session:1')).toEqual(updated);
    expect(inner.getCalls).toBe(0);
  });

  it('closes the inner storage', async () => {
    const inner = makeInner();
    let closed = false;
    inner.close = async () => {
      closed = true;
    };
    const cached = NewCachedSessionStorage(inner, TTL_SEC);
    await cached.close();
    expect(closed).toBe(true);
  });
});
