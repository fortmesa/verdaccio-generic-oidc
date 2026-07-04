/**
 * dynamo.ts's second (optional) NewDynamoStorage argument exists solely for
 * this file: vitest's module mocking can't reliably intercept a bare runtime
 * require() of an external package the way it can a static import, and
 * dynamo.ts deliberately requires the AWS SDK lazily to keep it an optional
 * peer dependency -- so tests inject a hand-rolled fake client/commands
 * directly instead. The fake store is shared across every fake client
 * created during a test, mirroring how a real DynamoDB table is one shared
 * server regardless of how many clients connect to it.
 */
import {describe, it, expect, beforeEach} from 'vitest';
import {NewDynamoStorage, DynamoClientDeps} from './dynamo';
import {TokenSet} from 'openid-client';

type Item = Record<string, unknown>;

let store: Map<string, Item>;

function keyOf(key: {pk: string; sk?: string}): string {
  return `${key.pk}|${key.sk ?? ''}`;
}

class FakePutCommand {
  constructor(public input: {TableName: string; Item: Item}) {}
}

class FakeGetCommand {
  constructor(
    public input: {TableName: string; Key: {pk: string; sk?: string}},
  ) {}
}

function fakeDeps(): DynamoClientDeps {
  return {
    PutCommand: FakePutCommand,
    GetCommand: FakeGetCommand,
    client: {
      async send(command: unknown) {
        if (command instanceof FakePutCommand) {
          store.set(keyOf(command.input.Item as {pk: string; sk?: string}), {
            ...command.input.Item,
          });
          return {};
        }
        if (command instanceof FakeGetCommand) {
          return {Item: store.get(keyOf(command.input.Key))};
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
});

describe('NewDynamoStorage: session storage', () => {
  it('round-trips a session through set() and get()', async () => {
    const {ss} = NewDynamoStorage({tableName: TABLE}, fakeDeps());
    const tokenSet = new TokenSet({access_token: 'abc'});

    await ss.set('session:1', tokenSet, 300);
    expect(await ss.get('session:1')).toEqual({access_token: 'abc'});
  });

  it('returns null for a session that was never set', async () => {
    const {ss} = NewDynamoStorage({tableName: TABLE}, fakeDeps());
    expect(await ss.get('session:missing')).toBeNull();
  });

  it('namespaces keys with keyPrefix, isolating same-name keys', async () => {
    const deps = fakeDeps();
    const a = NewDynamoStorage({tableName: TABLE, keyPrefix: 'a-'}, deps);
    const b = NewDynamoStorage({tableName: TABLE, keyPrefix: 'b-'}, deps);

    await a.ss.set('session:1', new TokenSet({access_token: 'a-token'}), 300);
    await b.ss.set('session:1', new TokenSet({access_token: 'b-token'}), 300);

    expect(await a.ss.get('session:1')).toEqual({access_token: 'a-token'});
    expect(await b.ss.get('session:1')).toEqual({access_token: 'b-token'});
  });
});

describe('NewDynamoStorage: token storage', () => {
  it('round-trips a token through set() and get()', async () => {
    const {ts} = NewDynamoStorage({tableName: TABLE}, fakeDeps());

    await ts.set('login:1', 'npm-token-value', 300);
    expect(await ts.get('login:1', 1)).toBe('npm-token-value');
  });

  it('returns null for a token that was never set', async () => {
    const {ts} = NewDynamoStorage({tableName: TABLE}, fakeDeps());
    expect(await ts.get('login:missing', 0.1)).toBeNull();
  });
});

describe('NewDynamoStorage: sort key', () => {
  it('omits sk entirely when sortKeyValue is not configured', async () => {
    const {ss} = NewDynamoStorage({tableName: TABLE}, fakeDeps());
    await ss.set('session:1', new TokenSet({}), 300);

    const stored = store.get('SESSION#session:1|');
    expect(stored).toBeDefined();
    expect(stored).not.toHaveProperty('sk');
  });

  it('writes the configured sk on every item when sortKeyValue is set', async () => {
    const {ss} = NewDynamoStorage(
      {tableName: TABLE, sortKeyValue: 'OIDC'},
      fakeDeps(),
    );
    await ss.set('session:1', new TokenSet({}), 300);

    const stored = store.get('SESSION#session:1|OIDC');
    expect(stored?.sk).toBe('OIDC');
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
      value: 'stale-value',
      expireTime: Math.floor(Date.now() / 1000) - 10,
    });

    expect(await ts.get('login:1', 0.1)).toBeNull();
  });
});

describe('NewDynamoStorage: close()', () => {
  it('closes both session and token storage without throwing', async () => {
    const {ss, ts} = NewDynamoStorage({tableName: TABLE}, fakeDeps());
    await expect(ss.close()).resolves.toBeUndefined();
    await expect(ts.close()).resolves.toBeUndefined();
  });
});
