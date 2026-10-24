import type {DynamoDBClient} from '@aws-sdk/client-dynamodb';
import type {
  DeleteCommand as DeleteCommandType,
  DynamoDBDocumentClient as DynamoDBDocumentClientType,
  GetCommand as GetCommandType,
  PutCommand as PutCommandType,
} from '@aws-sdk/lib-dynamodb';
import {ITokenStorage} from './types';

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
    send(command: unknown): Promise<{
      Item?: Record<string, unknown>;
      Attributes?: Record<string, unknown>;
    }>;
    destroy(): void;
  };
  PutCommand: new (input: {
    TableName: string;
    Item: Record<string, unknown>;
  }) => unknown;
  GetCommand: new (input: {
    TableName: string;
    Key: Record<string, string>;
    ConsistentRead?: boolean;
  }) => unknown;
  DeleteCommand: new (input: {
    TableName: string;
    Key: Record<string, string>;
    ConditionExpression?: string;
    ReturnValues?: 'ALL_OLD';
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
  ts: ITokenStorage;
} {
  const {client, PutCommand, GetCommand, DeleteCommand} =
    deps ?? realDynamoClientDeps(config);

  const keyPrefix = config.keyPrefix ?? '';
  const ttlAttribute = config.ttlAttribute ?? DEFAULT_TTL_ATTRIBUTE;

  const itemKey = (pk: string): Record<string, string> => {
    const key: Record<string, string> = {pk};
    if (config.sortKeyValue != null) {
      key.sk = config.sortKeyValue;
    }
    return key;
  };

  // DynamoDB's TTL sweep isn't instantaneous (AWS documents up to ~48h in
  // the worst case), so an expired item may still be there.
  const liveValue = (item: Record<string, unknown> | undefined) => {
    if (item == null) return null;
    const ttlValue = item[ttlAttribute];
    if (typeof ttlValue === 'number' && ttlValue * 1000 < Date.now()) {
      return null;
    }
    return typeof item.value === 'string' ? item.value : null;
  };

  // Deletes the item only if it still exists and returns what it held, so
  // of two callers that both saw it, one gets the value and the other gets
  // null.
  async function claim(pk: string): Promise<string | null> {
    try {
      const result = await client.send(
        new DeleteCommand({
          TableName: config.tableName,
          Key: itemKey(pk),
          ConditionExpression: 'attribute_exists(pk)',
          ReturnValues: 'ALL_OLD',
        }),
      );
      return liveValue(result.Attributes);
    } catch (err) {
      if ((err as {name?: string}).name === 'ConditionalCheckFailedException') {
        return null;
      }
      throw err;
    }
  }

  const ts: ITokenStorage = {
    async close(): Promise<void> {
      client.destroy();
    },
    async set(key: string, value: string, expiresSec: number): Promise<void> {
      await client.send(
        new PutCommand({
          TableName: config.tableName,
          Item: {
            ...itemKey(`${keyPrefix}TOKEN#${key}`),
            value,
            // DynamoDB TTL is an epoch *seconds* timestamp, not a duration --
            // expiresSec is already seconds (matching this codebase's own
            // convention), so this just adds it to the current epoch second.
            [ttlAttribute]: Math.floor(Date.now() / 1000) + expiresSec,
          },
        }),
      );
    },
    // DynamoDB has no native blocking-read primitive, so poll -- the same
    // problem the filesystem backend already has to solve, for the same
    // reason. Polling uses consistent reads, so a value written moments ago
    // isn't missed; the delete that claims it only runs once one is seen.
    async consume(key: string, timeoutSec: number): Promise<string | null> {
      const pk = `${keyPrefix}TOKEN#${key}`;
      const deadline = Date.now() + timeoutSec * 1000;
      for (;;) {
        const result = await client.send(
          new GetCommand({
            TableName: config.tableName,
            Key: itemKey(pk),
            ConsistentRead: true,
          }),
        );
        if (result.Item != null) {
          if (liveValue(result.Item) == null) return null;
          return claim(pk);
        }
        const remaining = deadline - Date.now();
        if (remaining <= 0) return null;
        await new Promise(resolve =>
          setTimeout(resolve, Math.min(POLL_INTERVAL_MS, remaining)),
        );
      }
    },
  };

  return {ts};
}

function realDynamoClientDeps(config: DynamoStorageConfig): DynamoClientDeps {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const {DynamoDBClient: RealDynamoDBClient} =
    require('@aws-sdk/client-dynamodb') as {
      DynamoDBClient: typeof DynamoDBClient;
    };
  const {
    DeleteCommand,
    DynamoDBDocumentClient,
    GetCommand,
    PutCommand,
    // eslint-disable-next-line @typescript-eslint/no-var-requires
  } = require('@aws-sdk/lib-dynamodb') as {
    DeleteCommand: typeof DeleteCommandType;
    DynamoDBDocumentClient: typeof DynamoDBDocumentClientType;
    GetCommand: typeof GetCommandType;
    PutCommand: typeof PutCommandType;
  };

  const client = DynamoDBDocumentClient.from(
    new RealDynamoDBClient(config.region ? {region: config.region} : {}),
  );

  return {client, PutCommand, GetCommand, DeleteCommand};
}
