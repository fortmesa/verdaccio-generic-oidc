/**
 * Fakes ioredis at the client-class level (matching this repo's storage
 * backends: real logic, hand-rolled fake I/O, no real Redis server needed)
 * with a store shared across every `new Redis()` instance created during a
 * test -- this backend creates a second, pooled connection purely for the
 * blocking XREAD call, and a real Redis deployment would have both
 * connections see the same server-side data.
 */
import {describe, it, expect, vi, beforeEach} from 'vitest';

type StreamEntry = [string, [string, string]];
type FakeEntry =
  {type: 'string'; value: string} | {type: 'stream'; entries: StreamEntry[]};

let store: Map<string, FakeEntry>;

vi.mock('ioredis', () => {
  class FakeRedis {
    async connect() {}
    async quit() {}

    async set(key: string, value: string, _mode: string, _ttl: number) {
      store.set(key, {type: 'string', value});
      return 'OK';
    }

    async get(key: string) {
      const entry = store.get(key);
      return entry?.type === 'string' ? entry.value : null;
    }

    async xadd(key: string, _id: string, field: string, value: string) {
      let entry = store.get(key);
      if (entry?.type !== 'stream') {
        entry = {type: 'stream', entries: []};
        store.set(key, entry);
      }
      const id = `${entry.entries.length}-0`;
      entry.entries.push([id, [field, value]]);
      return id;
    }

    async expire(_key: string, _ttl: number) {
      return 1;
    }

    async xread(
      _block: string,
      _timeoutMs: number,
      _streamsKw: string,
      key: string,
      _cursor: string,
    ) {
      const entry = store.get(key);
      if (entry?.type === 'stream' && entry.entries.length > 0) {
        return [[key, entry.entries]];
      }
      return null;
    }
  }

  return {Redis: FakeRedis};
});

import {NewRedisStorage} from './redis';
import {TokenSet} from 'openid-client';

beforeEach(() => {
  store = new Map();
});

describe('NewRedisStorage: session storage', () => {
  it('round-trips a session through set() and get()', async () => {
    const {ss} = NewRedisStorage({url: 'redis://fake'});
    const tokenSet = new TokenSet({access_token: 'abc'});

    await ss.set('session:1', tokenSet, 300);
    const result = await ss.get('session:1');

    expect(result).toEqual({access_token: 'abc'});
  });

  it('returns null for a session that was never set', async () => {
    const {ss} = NewRedisStorage({url: 'redis://fake'});
    expect(await ss.get('session:missing')).toBeNull();
  });

  it('namespaces keys with keyPrefix, isolating same-name keys', async () => {
    const a = NewRedisStorage({url: 'redis://fake', keyPrefix: 'a-'});
    const b = NewRedisStorage({url: 'redis://fake', keyPrefix: 'b-'});

    await a.ss.set('session:1', new TokenSet({access_token: 'a-token'}), 300);
    await b.ss.set('session:1', new TokenSet({access_token: 'b-token'}), 300);

    expect(await a.ss.get('session:1')).toEqual({access_token: 'a-token'});
    expect(await b.ss.get('session:1')).toEqual({access_token: 'b-token'});
    expect(store.has('a-session:1')).toBe(true);
    expect(store.has('b-session:1')).toBe(true);
  });

  it('defaults to no prefix when keyPrefix is omitted', async () => {
    const {ss} = NewRedisStorage({url: 'redis://fake'});
    await ss.set('session:1', new TokenSet({access_token: 'abc'}), 300);
    expect(store.has('session:1')).toBe(true);
  });
});

describe('NewRedisStorage: token storage', () => {
  it('round-trips a token through set() and get()', async () => {
    const {ts} = NewRedisStorage({url: 'redis://fake'});

    await ts.set('login:1', 'npm-token-value', 300);
    const result = await ts.get('login:1', 5);

    expect(result).toBe('npm-token-value');
  });

  it('returns null when polling a token that was never set', async () => {
    const {ts} = NewRedisStorage({url: 'redis://fake'});
    expect(await ts.get('login:missing', 5)).toBeNull();
  });

  it('namespaces keys with keyPrefix, isolating same-name keys', async () => {
    const a = NewRedisStorage({url: 'redis://fake', keyPrefix: 'a-'});
    const b = NewRedisStorage({url: 'redis://fake', keyPrefix: 'b-'});

    await a.ts.set('login:1', 'a-token', 300);
    await b.ts.set('login:1', 'b-token', 300);

    expect(await a.ts.get('login:1', 5)).toBe('a-token');
    expect(await b.ts.get('login:1', 5)).toBe('b-token');
  });
});

describe('NewRedisStorage: close()', () => {
  it('closes both session and token storage without throwing', async () => {
    const {ss, ts} = NewRedisStorage({url: 'redis://fake'});
    await expect(ss.close()).resolves.toBeUndefined();
    await expect(ts.close()).resolves.toBeUndefined();
  });
});
