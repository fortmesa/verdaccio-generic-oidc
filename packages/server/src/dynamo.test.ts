/**
 * dynamo.ts's second (optional) NewDynamoStorage argument exists solely for
 * this file: vitest's module mocking can't reliably intercept a bare runtime
 * require() of an external package the way it can a static import, and
 * dynamo.ts deliberately requires the AWS SDK lazily to keep it an optional
 * peer dependency -- so tests inject a hand-rolled fake client/commands
 * directly instead. The fake store is shared across every fake client
 * created during a test, mirroring how a real DynamoDB table is one shared
 * server regardless of how many clients connect to it. The fake's
 * conditional delete fails the way DynamoDB's does, with a
 * ConditionalCheckFailedException.
 */
import {describe, it, expect, beforeEach} from 'vitest';
import {NewDynamoStorage, DynamoClientDeps} from './dynamo';

type Item = Record<string, unknown>;
type Key = {pk: string; sk?: string};

let store: Map<string, Item>;
let commands: unknown[];

function keyOf(key: Key): string {
  return `${key.pk}|${key.sk ?? ''}`;
}

class FakePutCommand {
  constructor(public input: {TableName: string; Item: Item}) {}
}

class FakeGetCommand {
  constructor(
    public input: {TableName: string; Key: Key; ConsistentRead?: boolean},
  ) {}
}

class FakeDeleteCommand {
  constructor(
    public input: {
      TableName: string;
      Key: Key;
      ConditionExpression?: string;
      ReturnValues?: string;
    },
  ) {}
}

function fakeDeps(): DynamoClientDeps {
  return {
    PutCommand: FakePutCommand,
    GetCommand: FakeGetCommand,
    DeleteCommand: FakeDeleteCommand,
    client: {
      async send(command: unknown) {
        commands.push(command);
        if (command instanceof FakePutCommand) {
          store.set(keyOf(command.input.Item as Key), {...command.input.Item});
          return {};
        }
        if (command instanceof FakeGetCommand) {
          return {Item: store.get(keyOf(command.input.Key))};
        }
        if (command instanceof FakeDeleteCommand) {
          const key = keyOf(command.input.Key);
          const existing = store.get(key);
          if (
            command.input.ConditionExpression === 'attribute_exists(pk)' &&
            existing == null
          ) {
            throw Object.assign(new Error('The conditional request failed'), {
              name: 'ConditionalCheckFailedException',
            });
          }
          store.delete(key);
          return {Attributes: existing};
        }
        throw new Error('unexpected command');
      },
      destroy() {},
    },
  };
}

const TABLE = 'my-table';

beforeEach(() => {
  store = new Map();
  commands = [];
});

describe('NewDynamoStorage: token storage', () => {
  it('round-trips a token through set() and consume()', async () => {
    const {ts} = NewDynamoStorage({tableName: TABLE}, fakeDeps());

    await ts.set('login:1', 'npm-token-value', 300);
    expect(await ts.consume('login:1', 1)).toBe('npm-token-value');
  });

  it('hands a value out once: consume() deletes the item', async () => {
    const {ts} = NewDynamoStorage({tableName: TABLE}, fakeDeps());

    await ts.set('login:1', 'npm-token-value', 300);
    expect(await ts.consume('login:1', 1)).toBe('npm-token-value');
    expect(store.size).toBe(0);
    expect(await ts.consume('login:1', 0.1)).toBeNull();
  });

  it('gives the value to exactly one of several concurrent consumers', async () => {
    const {ts} = NewDynamoStorage({tableName: TABLE}, fakeDeps());

    await ts.set('login:1', 'npm-token-value', 300);
    const results = await Promise.all(
      Array.from({length: 8}, () => ts.consume('login:1', 0.1)),
    );
    expect(results.filter(r => r === 'npm-token-value')).toHaveLength(1);
  });

  it('polls with consistent reads, and deletes only once it has seen the item', async () => {
    const {ts} = NewDynamoStorage({tableName: TABLE}, fakeDeps());

    const pending = ts.consume('login:1', 2);
    await new Promise(r => setTimeout(r, 300));
    await ts.set('login:1', 'late-token', 300);
    expect(await pending).toBe('late-token');

    const gets = commands.filter(c => c instanceof FakeGetCommand);
    expect(gets.length).toBeGreaterThan(1);
    expect(
      gets.every(c => (c as FakeGetCommand).input.ConsistentRead === true),
    ).toBe(true);
    expect(commands.filter(c => c instanceof FakeDeleteCommand)).toHaveLength(
      1,
    );
  });

  it('returns null for a token that was never set', async () => {
    const {ts} = NewDynamoStorage({tableName: TABLE}, fakeDeps());
    expect(await ts.consume('login:missing', 0.1)).toBeNull();
  });

  it('namespaces keys with keyPrefix, isolating same-name keys', async () => {
    const deps = fakeDeps();
    const a = NewDynamoStorage({tableName: TABLE, keyPrefix: 'a-'}, deps);
    const b = NewDynamoStorage({tableName: TABLE, keyPrefix: 'b-'}, deps);

    await a.ts.set('login:1', 'a-token', 300);
    await b.ts.set('login:1', 'b-token', 300);

    expect(store.has('a-TOKEN#login:1|')).toBe(true);
    expect(store.has('b-TOKEN#login:1|')).toBe(true);
    expect(await a.ts.consume('login:1', 1)).toBe('a-token');
    expect(await b.ts.consume('login:1', 1)).toBe('b-token');
  });
});

describe('NewDynamoStorage: sort key', () => {
  it('omits sk entirely when sortKeyValue is not configured', async () => {
    const {ts} = NewDynamoStorage({tableName: TABLE}, fakeDeps());
    await ts.set('login:1', 'value', 300);

    const stored = store.get('TOKEN#login:1|');
    expect(stored).toBeDefined();
    expect(stored).not.toHaveProperty('sk');
  });

  it('writes, reads and deletes with the configured sk when sortKeyValue is set', async () => {
    const {ts} = NewDynamoStorage(
      {tableName: TABLE, sortKeyValue: 'OIDC'},
      fakeDeps(),
    );
    await ts.set('login:1', 'value', 300);

    const stored = store.get('TOKEN#login:1|OIDC');
    expect(stored?.sk).toBe('OIDC');
    expect(await ts.consume('login:1', 1)).toBe('value');
    expect(store.size).toBe(0);
  });
});

describe('NewDynamoStorage: TTL', () => {
  it('writes an epoch-seconds TTL under the default attribute name', async () => {
    const {ts} = NewDynamoStorage({tableName: TABLE}, fakeDeps());
    const before = Math.floor(Date.now() / 1000);

    await ts.set('login:1', 'value', 300);

    const stored = store.get('TOKEN#login:1|');
    expect(stored?.expireTime).toBeGreaterThanOrEqual(before + 300);
    expect(stored?.expireTime).toBeLessThanOrEqual(before + 302);
  });

  it('honors a custom ttlAttribute name', async () => {
    const {ts} = NewDynamoStorage(
      {tableName: TABLE, ttlAttribute: 'ttl'},
      fakeDeps(),
    );
    await ts.set('login:1', 'value', 300);

    const stored = store.get('TOKEN#login:1|');
    expect(stored).toHaveProperty('ttl');
    expect(stored).not.toHaveProperty('expireTime');
  });

  it("treats an item past its TTL as gone, even if DynamoDB hasn't swept it yet", async () => {
    const {ts} = NewDynamoStorage({tableName: TABLE}, fakeDeps());
    // Simulate an unswept-but-expired item directly, bypassing set() (which
    // always writes a future TTL) -- mirrors real DynamoDB's documented
    // up-to-~48h sweep lag.
    store.set('TOKEN#login:1|', {
      pk: 'TOKEN#login:1',
      value: 'stale-value',
      expireTime: Math.floor(Date.now() / 1000) - 10,
    });

    expect(await ts.consume('login:1', 0.1)).toBeNull();
  });
});

describe('NewDynamoStorage: close()', () => {
  it('closes without throwing', async () => {
    const {ts} = NewDynamoStorage({tableName: TABLE}, fakeDeps());
    await expect(ts.close()).resolves.toBeUndefined();
  });
});
