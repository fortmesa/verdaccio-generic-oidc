/**
 * Runs against a real temp directory on disk rather than mocking `fs` --
 * cheap, fast, and exercises the real on-disk file format (this backend has
 * no external service to fake in the first place).
 */
import {describe, it, expect, beforeEach, afterEach, vi} from 'vitest';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import {Logger} from '@verdaccio/types';
import {TokenSet} from 'openid-client';
import {NewFileStorage} from './fs';

function makeLogger(): Logger {
  return {
    child: vi.fn(),
    debug: vi.fn(),
    error: vi.fn(),
    http: vi.fn(),
    trace: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
  };
}

let tmpDir: string;

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'oidc-fs-test-'));
});

afterEach(async () => {
  await fs.rm(tmpDir, {recursive: true, force: true});
});

describe('NewFileStorage: session storage', () => {
  it('round-trips a session through set() and get()', async () => {
    const {ss} = NewFileStorage(makeLogger(), tmpDir, tmpDir);
    const tokenSet = new TokenSet({access_token: 'abc'});

    await ss.set('session:1', tokenSet, 300);
    expect(await ss.get('session:1')).toEqual({access_token: 'abc'});
  });

  it('returns null for a session that was never set', async () => {
    const {ss} = NewFileStorage(makeLogger(), tmpDir, tmpDir);
    expect(await ss.get('session:missing')).toBeNull();
  });

  it('returns null for a session past its expiry, without deleting it eagerly', async () => {
    const {ss} = NewFileStorage(makeLogger(), tmpDir, tmpDir);
    await ss.set('session:1', new TokenSet({access_token: 'abc'}), -10);

    expect(await ss.get('session:1')).toBeNull();
    const files = await fs.readdir(tmpDir);
    expect(files.some(f => f.endsWith('.session'))).toBe(true);
  });

  it('base64-encodes the key into the filename, tolerating arbitrary characters', async () => {
    const {ss} = NewFileStorage(makeLogger(), tmpDir, tmpDir);
    await ss.set('session:weird/key:with:colons', new TokenSet({}), 300);

    const files = await fs.readdir(tmpDir);
    expect(files).toHaveLength(1);
    expect(files[0]).not.toContain('/');
  });

  it('uses base64url, not plain base64, so a key that would produce a "/" under plain base64 never does', async () => {
    // Buffer.from('session:?abc').toString('base64') is
    // 'c2Vzc2lvbjo/YWJj' -- a real, plain-base64 '/' in the encoded output,
    // not a contrived one. FileTokenStorage's key is a caller-supplied,
    // fully attacker-controlled Basic-Auth password, so this isn't a
    // hypothetical input.
    const {ss} = NewFileStorage(makeLogger(), tmpDir, tmpDir);
    await ss.set('session:?abc', new TokenSet({}), 300);

    const files = await fs.readdir(tmpDir);
    expect(files).toHaveLength(1);
    expect(files[0]).not.toContain('/');
    expect(await ss.get('session:?abc')).toEqual({});
  });
});

describe('NewFileStorage: token storage', () => {
  it('round-trips a token through set() and get()', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir, tmpDir);

    await ts.set('login:1', 'npm-token-value', 300);
    expect(await ts.get('login:1', 1)).toBe('npm-token-value');
  });

  it('returns null after the poll window elapses for a key that never appears', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir, tmpDir);
    expect(await ts.get('login:missing', 0.2)).toBeNull();
  });

  it('returns null for a token past its expiry', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir, tmpDir);
    await ts.set('login:1', 'stale-token', -10);
    expect(await ts.get('login:1', 0.2)).toBeNull();
  });

  it('polls and picks up a value written shortly after get() starts', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir, tmpDir);

    setTimeout(() => {
      ts.set('login:1', 'delayed-token', 300);
    }, 50);

    expect(await ts.get('login:1', 2)).toBe('delayed-token');
  });
});

describe('NewFileStorage: shared session/token directory', () => {
  it('keeps sessions and tokens under the same key from colliding', async () => {
    const {ss, ts} = NewFileStorage(makeLogger(), tmpDir, tmpDir);

    await ss.set(
      'shared-key',
      new TokenSet({access_token: 'session-value'}),
      300,
    );
    await ts.set('shared-key', 'token-value', 300);

    expect(await ss.get('shared-key')).toEqual({access_token: 'session-value'});
    expect(await ts.get('shared-key', 1)).toBe('token-value');
  });
});

describe('NewFileStorage: close()', () => {
  it('closes both session and token storage without throwing', async () => {
    const {ss, ts} = NewFileStorage(makeLogger(), tmpDir, tmpDir);
    await expect(ss.close()).resolves.toBeUndefined();
    await expect(ts.close()).resolves.toBeUndefined();
  });
});
