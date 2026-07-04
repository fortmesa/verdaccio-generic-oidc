import type {DynamoDBClient} from '@aws-sdk/client-dynamodb';
import type {
  DynamoDBDocumentClient as DynamoDBDocumentClientType,
  GetCommand as GetCommandType,
  PutCommand as PutCommandType,
} from '@aws-sdk/lib-dynamodb';
import {ISessionStorage, ITokenStorage} from './types';
import {TokenSet} from 'openid-client';

export interface DynamoStorageConfig {
  tableName: string;
  region?: string;
  /** Namespaces `pk` values, so this table can be shared legibly with other consumers. */
  keyPrefix?: string;
  /**
   * A fixed sort-key value to write on every item. Required only when reusing
   * a table whose key schema declares a sort key (`pk` + `sk`) -- DynamoDB
   * rejects writes missing any attribute that's part of the declared key
   * schema. Omit entirely for a dedicated hash-key-only table.
   */
  sortKeyValue?: string;
  /** Must match the attribute name the table has DynamoDB TTL enabled on. */
  ttlAttribute?: string;
}

const DEFAULT_TTL_ATTRIBUTE = 'expireTime';
const POLL_INTERVAL_MS = 250;

export interface DynamoClientDeps {
  client: {
    send(command: unknown): Promise<{Item?: Record<string, unknown>}>;
    destroy(): void;
  };
  PutCommand: new (input: {
    TableName: string;
    Item: Record<string, unknown>;
  }) => unknown;
  GetCommand: new (input: {
    TableName: string;
    Key: Record<string, string>;
  }) => unknown;
}

/**
 * @aws-sdk/* is an optional peer dependency -- in production this module
 * must only ever be reached via a runtime-conditional require() from
 * index.ts's storage selection branch, never a static top-level import, or
 * every Redis/filesystem-only install would suddenly need the AWS SDK on
 * disk too. `deps` exists solely as a test seam: it lets dynamo.test.ts
 * inject a fake client/commands directly, since vitest's module mocking
 * can't reliably intercept a bare runtime require() of an external package
 * the way it can a static import (see dynamo.test.ts for why).
 */
export function NewDynamoStorage(
  config: DynamoStorageConfig,
  deps?: DynamoClientDeps,
): {
  ss: ISessionStorage;
  ts: ITokenStorage;
} {
  const {client, PutCommand, GetCommand} = deps ?? realDynamoClientDeps(config);

  const keyPrefix = config.keyPrefix ?? '';
  const ttlAttribute = config.ttlAttribute ?? DEFAULT_TTL_ATTRIBUTE;

  const itemKey = (pk: string): Record<string, string> => {
    const key: Record<string, string> = {pk};
    if (config.sortKeyValue != null) {
      key.sk = config.sortKeyValue;
    }
    return key;
  };

  async function putValue(
    pk: string,
    value: string,
    expiresSec: number,
  ): Promise<void> {
    await client.send(
      new PutCommand({
        TableName: config.tableName,
        Item: {
          ...itemKey(pk),
          value,
          // DynamoDB TTL is an epoch *seconds* timestamp, not a duration --
          // expiresSec is already seconds (matching this codebase's own
          // convention), so this just adds it to the current epoch second.
          [ttlAttribute]: Math.floor(Date.now() / 1000) + expiresSec,
        },
      }),
    );
  }

  async function getValue(pk: string): Promise<string | null> {
    const result = await client.send(
      new GetCommand({TableName: config.tableName, Key: itemKey(pk)}),
    );
    const item = result.Item;
    if (item == null) return null;
    // DynamoDB's TTL sweep isn't instantaneous (AWS documents up to ~48h in
    // the worst case), so don't trust an expired item to already be gone.
    const ttlValue = item[ttlAttribute];
    if (typeof ttlValue === 'number' && ttlValue * 1000 < Date.now()) {
      return null;
    }
    return typeof item.value === 'string' ? item.value : null;
  }

  const close = async (): Promise<void> => {
    client.destroy();
  };

  const ss: ISessionStorage = {
    close,
    async set(key: string, value: TokenSet, expiresSec: number): Promise<void> {
      await putValue(
        `${keyPrefix}SESSION#${key}`,
        JSON.stringify(value),
        expiresSec,
      );
    },
    async get(key: string): Promise<TokenSet | null> {
      const raw = await getValue(`${keyPrefix}SESSION#${key}`);
      return raw == null ? null : JSON.parse(raw);
    },
  };

  const ts: ITokenStorage = {
    close,
    async set(key: string, value: string, expiresSec: number): Promise<void> {
      await putValue(`${keyPrefix}TOKEN#${key}`, value, expiresSec);
    },
    // DynamoDB has no native blocking-read primitive, so poll -- the same
    // problem the filesystem backend already has to solve, for the same
    // reason. timeoutSec matches ITokenStorage's own (seconds) interface;
    // POLL_INTERVAL_MS is an internal implementation detail (setTimeout is
    // natively milliseconds, and genuinely needs sub-second granularity
    // here to avoid adding up to POLL_INTERVAL_MS of detection lag).
    async get(key: string, timeoutSec: number): Promise<string | null> {
      const pk = `${keyPrefix}TOKEN#${key}`;
      const deadline = Date.now() + timeoutSec * 1000;
      for (;;) {
        const value = await getValue(pk);
        if (value != null) return value;
        const remaining = deadline - Date.now();
        if (remaining <= 0) return null;
        await new Promise(resolve =>
          setTimeout(resolve, Math.min(POLL_INTERVAL_MS, remaining)),
        );
      }
    },
  };

  return {ss, ts};
}

function realDynamoClientDeps(config: DynamoStorageConfig): DynamoClientDeps {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const {DynamoDBClient: RealDynamoDBClient} =
    require('@aws-sdk/client-dynamodb') as {
      DynamoDBClient: typeof DynamoDBClient;
    };
  const {
    DynamoDBDocumentClient,
    GetCommand,
    PutCommand,
    // eslint-disable-next-line @typescript-eslint/no-var-requires
  } = require('@aws-sdk/lib-dynamodb') as {
    DynamoDBDocumentClient: typeof DynamoDBDocumentClientType;
    GetCommand: typeof GetCommandType;
    PutCommand: typeof PutCommandType;
  };

  const client = DynamoDBDocumentClient.from(
    new RealDynamoDBClient(config.region ? {region: config.region} : {}),
  );

  return {client, PutCommand, GetCommand};
}
