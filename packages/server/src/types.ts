export interface ITokenStorage {
  close(): Promise<void>;
  set(key: string, value: string, expires_sec: number): Promise<void>;
  /**
   * Waits up to timeoutSec seconds for the key to appear, then removes it and
   * returns its value, or returns null if it never appeared. Removal and read
   * are one step, so of any number of concurrent callers at most one gets
   * the value.
   */
  consume(key: string, timeoutSec: number): Promise<string | null>;
}
