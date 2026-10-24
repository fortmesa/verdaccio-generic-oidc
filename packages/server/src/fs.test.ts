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
  } as unknown as Logger;
}

let tmpDir: string;

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'oidc-fs-test-'));
});

afterEach(async () => {
  await fs.rm(tmpDir, {recursive: true, force: true});
});

describe('NewFileStorage: token storage', () => {
  it('round-trips a token through set() and consume()', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir);

    await ts.set('login:1', 'npm-token-value', 300);
    expect(await ts.consume('login:1', 1)).toBe('npm-token-value');
  });

  it('hands a value out once: a second consume() finds nothing', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir);

    await ts.set('login:1', 'npm-token-value', 300);
    expect(await ts.consume('login:1', 1)).toBe('npm-token-value');
    expect(await ts.consume('login:1', 0.2)).toBeNull();
  });

  it('gives the value to exactly one of several concurrent consumers', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir);

    await ts.set('login:1', 'npm-token-value', 300);
    const results = await Promise.all(
      Array.from({length: 8}, () => ts.consume('login:1', 0.2)),
    );
    expect(results.filter(r => r === 'npm-token-value')).toHaveLength(1);
    expect(results.filter(r => r === null)).toHaveLength(7);
  });

  it('returns null after the poll window elapses for a key that never appears', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir);
    expect(await ts.consume('login:missing', 0.2)).toBeNull();
  });

  it('polls and picks up a value written shortly after consume() starts', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir);

    const pending = ts.consume('login:1', 2);
    await new Promise(r => setTimeout(r, 150));
    await ts.set('login:1', 'late-token', 300);

    expect(await pending).toBe('late-token');
  });

  it('returns null for a token past its expiry', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir);
    await ts.set('login:1', 'old-token', -1);
    expect(await ts.consume('login:1', 0.2)).toBeNull();
  });

  it('treats a file with no readable expiry as expired, not as never expiring', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir);
    const fName = path.join(
      tmpDir,
      Buffer.from('login:1').toString('base64url') + '.token',
    );
    await fs.writeFile(fName, 'not-a-number\nnpm-token-value');
    expect(await ts.consume('login:1', 0.2)).toBeNull();
    await fs.writeFile(fName, '');
    expect(await ts.consume('login:1', 0.2)).toBeNull();
  });

  it('writes files readable only by their owner and leaves no temp file behind', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir);
    await ts.set('login:1', 'npm-token-value', 300);

    const files = await fs.readdir(tmpDir);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/\.token$/);
    const {mode} = await fs.stat(path.join(tmpDir, files[0]));
    expect(mode & 0o077).toBe(0);
  });

  it('uses base64url, not plain base64, so a key that would produce a "/" under plain base64 never does', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir);
    // Plain base64 of this key is 'bG9naW46w7/Dv8O/', slashes included.
    const key = 'login:' + String.fromCharCode(0xff).repeat(3);
    expect(Buffer.from(key).toString('base64')).toContain('/');

    await ts.set(key, 'value', 300);
    const files = await fs.readdir(tmpDir);
    expect(files).toHaveLength(1);
    expect(files[0]).not.toContain('/');
    expect(await ts.consume(key, 1)).toBe('value');
  });
});

describe('NewFileStorage: close()', () => {
  it('closes without throwing', async () => {
    const {ts} = NewFileStorage(makeLogger(), tmpDir);
    await expect(ts.close()).resolves.toBeUndefined();
  });
});
