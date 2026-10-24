import {ITokenStorage} from './types';
import {Redis} from 'ioredis';

export interface RedisStorageConfig {
  url: string;
  /** Namespaces every key, so this Redis instance can be shared legibly with other consumers. */
  keyPrefix?: string;
}

const POLL_INTERVAL_MS = 250;

export function NewRedisStorage(config: RedisStorageConfig): {
  ts: ITokenStorage;
} {
  const {url: redisUri, keyPrefix = ''} = config;
  return {ts: new RedisTokenStorage(createRedis(redisUri), keyPrefix)};
}

// One connection for everything: every command here is non-blocking, so
// they share it the way ioredis pipelines commands, and a waiting consume()
// polls instead of holding a connection in a blocking read.
class RedisTokenStorage implements ITokenStorage {
  private closed = false;

  constructor(
    private redis: Redis,
    private keyPrefix: string,
  ) {}

  public async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.redis.quit();
  }

  public async set(
    key: string,
    value: string,
    expires_sec: number,
  ): Promise<void> {
    // One command, so the value can never exist without its expiry.
    await this.redis.set(`${this.keyPrefix}${key}`, value, 'EX', expires_sec);
  }

  public async consume(
    key: string,
    timeoutSec: number,
  ): Promise<string | null> {
    const prefixedKey = `${this.keyPrefix}${key}`;
    const deadline = Date.now() + timeoutSec * 1000;
    for (;;) {
      // GET and DEL in one transaction (GETDEL needs Redis 6.2+), so two
      // concurrent callers can't both read the value.
      const results = await this.redis
        .multi()
        .get(prefixedKey)
        .del(prefixedKey)
        .exec();
      if (results == null) throw new Error('redis transaction was aborted');
      const [getErr, value] = results[0];
      if (getErr) throw getErr;
      if (typeof value === 'string') return value;

      const remaining = deadline - Date.now();
      if (remaining <= 0) return null;
      await new Promise(resolve =>
        setTimeout(resolve, Math.min(POLL_INTERVAL_MS, remaining)),
      );
    }
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
