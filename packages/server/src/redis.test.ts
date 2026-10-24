/**
 * Fakes ioredis at the client-class level (matching this repo's storage
 * backends: real logic, hand-rolled fake I/O, no real Redis server needed)
 * with a store shared across every `new Redis()` instance created during a
 * test, the way a real Redis deployment is one server however many
 * connections reach it. The fake's MULTI runs its queued commands back to
 * back with nothing in between, as Redis runs a transaction.
 */
import {describe, it, expect, vi, beforeEach} from 'vitest';

type FakeEntry = {value: string; ttlSec: number};

let store: Map<string, FakeEntry>;

vi.mock('ioredis', () => {
  class FakeMulti {
    private ops: Array<() => unknown> = [];
    get(key: string) {
      this.ops.push(() => store.get(key)?.value ?? null);
      return this;
    }
    del(key: string) {
      this.ops.push(() => (store.delete(key) ? 1 : 0));
      return this;
    }
    async exec() {
      return this.ops.map(op => [null, op()]);
    }
  }

  class FakeRedis {
    async quit() {
      return 'OK';
    }

    async set(key: string, value: string, mode: string, ttlSec: number) {
      if (mode !== 'EX') throw new Error(`unexpected SET mode ${mode}`);
      store.set(key, {value, ttlSec});
      return 'OK';
    }

    multi() {
      return new FakeMulti();
    }
  }

  return {Redis: FakeRedis};
});

import {NewRedisStorage} from './redis';

beforeEach(() => {
  store = new Map();
});

describe('NewRedisStorage: token storage', () => {
  it('round-trips a token through set() and consume(), with the expiry set in the same command', async () => {
    const {ts} = NewRedisStorage({url: 'redis://fake'});

    await ts.set('login:1', 'npm-token-value', 300);
    expect(store.get('login:1')).toEqual({
      value: 'npm-token-value',
      ttlSec: 300,
    });
    expect(await ts.consume('login:1', 1)).toBe('npm-token-value');
  });

  it('hands a value out once: consume() deletes it', async () => {
    const {ts} = NewRedisStorage({url: 'redis://fake'});

    await ts.set('login:1', 'npm-token-value', 300);
    expect(await ts.consume('login:1', 1)).toBe('npm-token-value');
    expect(store.has('login:1')).toBe(false);
    expect(await ts.consume('login:1', 0.2)).toBeNull();
  });

  it('gives the value to exactly one of several concurrent consumers', async () => {
    const {ts} = NewRedisStorage({url: 'redis://fake'});

    await ts.set('login:1', 'npm-token-value', 300);
    const results = await Promise.all(
      Array.from({length: 8}, () => ts.consume('login:1', 0.2)),
    );
    expect(results.filter(r => r === 'npm-token-value')).toHaveLength(1);
  });

  it('polls and picks up a value written shortly after consume() starts', async () => {
    const {ts} = NewRedisStorage({url: 'redis://fake'});

    const pending = ts.consume('login:1', 2);
    await new Promise(r => setTimeout(r, 100));
    await ts.set('login:1', 'late-token', 300);

    expect(await pending).toBe('late-token');
  });

  it('returns null when polling a token that was never set', async () => {
    const {ts} = NewRedisStorage({url: 'redis://fake'});
    expect(await ts.consume('login:missing', 0.2)).toBeNull();
  });

  it('namespaces keys with keyPrefix, isolating same-name keys', async () => {
    const a = NewRedisStorage({url: 'redis://fake', keyPrefix: 'a-'});
    const b = NewRedisStorage({url: 'redis://fake', keyPrefix: 'b-'});

    await a.ts.set('login:1', 'a-token', 300);
    await b.ts.set('login:1', 'b-token', 300);

    expect(store.has('a-login:1')).toBe(true);
    expect(store.has('b-login:1')).toBe(true);
    expect(await a.ts.consume('login:1', 1)).toBe('a-token');
    expect(await b.ts.consume('login:1', 1)).toBe('b-token');
  });
});

describe('NewRedisStorage: close()', () => {
  it('closes without throwing, and a second close is a no-op', async () => {
    const {ts} = NewRedisStorage({url: 'redis://fake'});
    await expect(ts.close()).resolves.toBeUndefined();
    await expect(ts.close()).resolves.toBeUndefined();
  });
});
