import * as path from 'path';
import * as fs from 'fs/promises';
import {randomBytes} from 'crypto';
import {ITokenStorage} from './types';
import {Logger} from '@verdaccio/types';

const TOKEN_FILE_EXT = '.token';
const GC_TIMEOUT = 60 * 1_000;
const POLL_INTERVAL_MS = 100;

export function NewFileStorage(
  logger: Logger,
  tokenStoragePath: string,
): {ts: ITokenStorage} {
  let stopped = false;
  const timer = setTimeout(function run() {
    gc(logger, tokenStoragePath).finally(() => {
      if (!stopped) setTimeout(run, GC_TIMEOUT).unref?.();
    });
  }, GC_TIMEOUT);
  timer.unref?.();

  return {
    ts: new FileTokenStorage(tokenStoragePath, () => {
      stopped = true;
      clearTimeout(timer);
      return Promise.resolve();
    }),
  };
}

// base64url, not plain base64: the key is partly caller-controlled (a login
// request id from a URL) and becomes a filename. Plain base64's alphabet
// includes '/', which would land the file in an unintended subdirectory;
// base64url ('-'/'_' in place of '+'/'/', no padding) has no character a
// filesystem path treats specially.
function btoa(s: string): string {
  return Buffer.from(s).toString('base64url');
}

async function gc(logger: Logger, dir: string): Promise<void> {
  try {
    for (const f of await fs.readdir(dir, {encoding: 'utf-8'})) {
      if (path.extname(f) !== TOKEN_FILE_EXT) continue;
      const ff = path.join(dir, f);
      const entry = await readFileEx(ff).catch(() => null);
      if (entry != null && isExpired(entry.expires_in)) {
        await fs.rm(ff, {force: true, maxRetries: 3, retryDelay: 10});
      }
    }
  } catch (err) {
    logger.warn({err}, 'file storage gc error: @{!err.message}\n@{err.stack}');
  }
}

// A file whose first line isn't a number counts as expired. Treating it as
// valid would never expire it, since every comparison with NaN is false.
function isExpired(expiresIn: number): boolean {
  return !Number.isFinite(expiresIn) || Date.now() > expiresIn;
}

async function readFileEx(
  fName: string,
): Promise<{expires_in: number; objRaw: string}> {
  const fData = await fs.readFile(fName, {encoding: 'utf-8'});
  const sIdx = fData.indexOf('\n');
  if (sIdx < 0) return {expires_in: NaN, objRaw: ''};
  return {
    expires_in: Number(fData.slice(0, sIdx)),
    objRaw: fData.slice(sIdx + 1),
  };
}

class FileTokenStorage implements ITokenStorage {
  constructor(
    private path: string,
    private fnClose: () => Promise<void>,
  ) {}

  public close(): Promise<void> {
    return this.fnClose();
  }

  private fileName(key: string): string {
    return path.join(this.path, btoa(key) + TOKEN_FILE_EXT);
  }

  public async set(
    key: string,
    value: string,
    expires_sec: number,
  ): Promise<void> {
    // Written to a private temp file and renamed into place, so a reader
    // only ever sees no file or the whole file, and only this user can
    // read it.
    const target = this.fileName(key);
    const temp = `${target}.${randomBytes(6).toString('hex')}.tmp`;
    await fs.writeFile(temp, `${Date.now() + 1000 * expires_sec}\n${value}`, {
      encoding: 'utf-8',
      mode: 0o600,
    });
    try {
      await fs.rename(temp, target);
    } catch (err) {
      await fs.rm(temp, {force: true});
      throw err;
    }
  }

  // rename() is atomic, so of several callers racing for the same file
  // exactly one moves it and gets to read it; the rest see ENOENT.
  private async tryConsume(key: string): Promise<string | null> {
    const target = this.fileName(key);
    const claimed = `${target}.${randomBytes(6).toString('hex')}.claimed`;
    try {
      await fs.rename(target, claimed);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw err;
    }
    try {
      const {expires_in, objRaw} = await readFileEx(claimed);
      return isExpired(expires_in) ? null : objRaw;
    } finally {
      await fs.rm(claimed, {force: true});
    }
  }

  public async consume(
    key: string,
    timeoutSec: number,
  ): Promise<string | null> {
    const deadline = Date.now() + timeoutSec * 1000;
    for (;;) {
      const value = await this.tryConsume(key);
      if (value != null) return value;
      const remaining = deadline - Date.now();
      if (remaining <= 0) return null;
      await new Promise(resolve =>
        setTimeout(resolve, Math.min(POLL_INTERVAL_MS, remaining)),
      );
    }
  }
}
