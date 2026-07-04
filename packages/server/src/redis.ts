import {ISessionStorage, ITokenStorage} from './types';
import {Redis} from 'ioredis';
import {createPool, Pool} from 'generic-pool';
import {TokenSet} from 'openid-client';

export interface RedisStorageConfig {
  url: string;
  /** Namespaces every key, so this Redis instance can be shared legibly with other consumers. */
  keyPrefix?: string;
}

export function NewRedisStorage(config: RedisStorageConfig): {
  ss: ISessionStorage;
  ts: ITokenStorage;
} {
  const {url: redisUri, keyPrefix = ''} = config;
  const redis = createRedis(redisUri);

  const redisPool = createPool<Redis>(
    {
      async create() {
        const redis = createRedis(redisUri);
        await redis.connect();

        return redis;
      },
      async destroy(redis) {
        await redis.quit();
      },
    },
    {
      min: 0,
      max: 1000,
      evictionRunIntervalMillis: 10_000,
      acquireTimeoutMillis: 10_000,
    },
  );

  let closed = false;
  const closeFn = () => {
    if (closed) return Promise.resolve();
    closed = true;

    redis.quit();
    redisPool.drain();
    return Promise.resolve();
  };

  return {
    ss: new RedisSessionStorage(redis, redisPool, closeFn, keyPrefix),
    ts: new RedisTokenStorage(redis, redisPool, closeFn, keyPrefix),
  };
}

class RedisTokenStorage implements ITokenStorage {
  constructor(
    private redis: Redis,
    private redisPool: Pool<Redis>,
    private fnClose: () => Promise<void>,
    private keyPrefix: string,
  ) {}

  public close(): Promise<void> {
    return this.fnClose();
  }

  public async set(
    key: string,
    value: string,
    expires_sec: number,
  ): Promise<void> {
    const prefixedKey = `${this.keyPrefix}${key}`;
    await this.redis.xadd(prefixedKey, '*', 'token', value);
    await this.redis.expire(prefixedKey, expires_sec);
  }

  public async get(key: string, timeoutSec: number): Promise<string | null> {
    const prefixedKey = `${this.keyPrefix}${key}`;
    // XREAD's own BLOCK option is natively milliseconds -- converting right
    // here, at the one place that actually calls it, keeps that requirement
    // from leaking into ITokenStorage's own (seconds) interface.
    const result = await this.redisPool.use(redis =>
      redis.xread('BLOCK', timeoutSec * 1000, 'STREAMS', prefixedKey, '0-0'),
    );

    if (result == null || result.length === 0) {
      return null;
    }

    return result[0][1][0][1][1]; // omg sorry
  }
}

class RedisSessionStorage implements ISessionStorage {
  constructor(
    private redis: Redis,
    _redisPool: Pool<Redis>,
    private fnClose: () => Promise<void>,
    private keyPrefix: string,
  ) {}

  public close(): Promise<void> {
    return this.fnClose();
  }

  public async set(
    key: string,
    value: TokenSet,
    expires_sec: number,
  ): Promise<void> {
    await this.redis.set(
      `${this.keyPrefix}${key}`,
      JSON.stringify(value),
      'EX',
      expires_sec,
    );
  }

  public async get(key: string): Promise<TokenSet | null> {
    const rawData = await this.redis.get(`${this.keyPrefix}${key}`);
    if (rawData == null) {
      return null;
    }

    const rv = JSON.parse(rawData);
    return rv;
  }
}

function createRedis(uri: string): Redis {
  return new Redis(uri, {
    lazyConnect: true,
    retryStrategy: (attempt: number) => {
      const baseMs = 100;
      const maxDelayMs = 10_000;

      const backoff = Math.min(maxDelayMs, Math.pow(2, attempt) * baseMs);

      return Math.round((backoff * (1 + Math.random())) / 2);
    },
  });
}
