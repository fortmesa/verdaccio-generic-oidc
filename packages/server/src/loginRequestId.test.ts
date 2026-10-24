import {describe, it, expect, vi, beforeEach, afterEach} from 'vitest';
import {
  signLoginRequestId,
  verifyAndConsumeLoginRequestId,
  checkAndConsumeMintBudget,
  createSourceBudget,
  loginRequestSecret,
  MAX_AGE_SEC,
  MAX_USES,
  MINT_WINDOW_SEC,
  MAX_MINTS_PER_WINDOW,
} from './loginRequestId';

const SECRET = 'test-secret';

describe('signLoginRequestId / verifyAndConsumeLoginRequestId', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('accepts an id signed with the matching secret, and reports its kind', () => {
    const cli = signLoginRequestId(SECRET, 'cli');
    const web = signLoginRequestId(SECRET, 'web');
    expect(verifyAndConsumeLoginRequestId(cli, SECRET)?.kind).toBe('cli');
    expect(verifyAndConsumeLoginRequestId(web, SECRET)?.kind).toBe('web');
  });

  it('rejects an id signed with a different secret', () => {
    const id = signLoginRequestId(SECRET, 'cli');
    expect(verifyAndConsumeLoginRequestId(id, 'wrong-secret')).toBeNull();
  });

  it('rejects a completely forged id with no signature structure at all', () => {
    expect(
      verifyAndConsumeLoginRequestId('just-a-random-looking-string', SECRET),
    ).toBeNull();
  });

  it('rejects a forged id with a made-up timestamp and signature', () => {
    expect(
      verifyAndConsumeLoginRequestId(
        'AAAAAAAAAAAAAAAAAAAAAA.1700000000.cli.deadbeefdeadbeefdeadbeefdeadbeef',
        SECRET,
      ),
    ).toBeNull();
  });

  it('rejects a tampered nonce paired with a previously-valid timestamp+signature', () => {
    const id = signLoginRequestId(SECRET, 'cli');
    const tampered = 'BBBBBBBBBBBBBBBBBBBBBB' + id.slice(id.indexOf('.'));
    expect(verifyAndConsumeLoginRequestId(tampered, SECRET)).toBeNull();
  });

  it('rejects an id whose kind was changed after signing', () => {
    const id = signLoginRequestId(SECRET, 'web');
    expect(
      verifyAndConsumeLoginRequestId(id.replace('.web.', '.cli.'), SECRET),
    ).toBeNull();
  });

  it('rejects a non-numeric issuedAt segment', () => {
    const [nonce, , kind, mac] = signLoginRequestId(SECRET, 'cli').split('.');
    expect(
      verifyAndConsumeLoginRequestId(
        `${nonce}.not-a-number.${kind}.${mac}`,
        SECRET,
      ),
    ).toBeNull();
  });

  it('rejects re-spellings of a valid id, so none of them gets a fresh use budget', () => {
    const id = signLoginRequestId(SECRET, 'cli');
    const [nonce, issuedAt, kind, mac] = id.split('.');
    for (const variant of [
      `${nonce}.${issuedAt}.${kind}.${mac.toUpperCase()}`,
      `${id}z`,
      `${id}zz`,
      `${nonce}.0${issuedAt}.${kind}.${mac}`,
      `${id}.extra`,
    ]) {
      expect(verifyAndConsumeLoginRequestId(variant, SECRET)).toBeNull();
    }
  });

  it('rejects an empty string', () => {
    expect(verifyAndConsumeLoginRequestId('', SECRET)).toBeNull();
  });

  it('produces distinct ids on repeated calls', () => {
    const id1 = signLoginRequestId(SECRET, 'cli');
    const id2 = signLoginRequestId(SECRET, 'cli');
    expect(id1).not.toEqual(id2);
  });

  it('allows a whole interactive login: MAX_AGE_SEC is ten minutes', () => {
    expect(MAX_AGE_SEC).toBe(10 * 60);
  });

  it('rejects an id once it exceeds MAX_AGE_SEC', () => {
    const id = signLoginRequestId(SECRET, 'cli');
    vi.advanceTimersByTime((MAX_AGE_SEC + 1) * 1000);
    expect(verifyAndConsumeLoginRequestId(id, SECRET)).toBeNull();
  });

  it('accepts an id right up to MAX_AGE_SEC', () => {
    const id = signLoginRequestId(SECRET, 'cli');
    vi.advanceTimersByTime(MAX_AGE_SEC * 1000);
    expect(verifyAndConsumeLoginRequestId(id, SECRET)).not.toBeNull();
  });

  it('allows a valid id to be used up to MAX_USES times, then rejects it', () => {
    const id = signLoginRequestId(SECRET, 'cli');
    for (let i = 0; i < MAX_USES; i++) {
      expect(verifyAndConsumeLoginRequestId(id, SECRET)).not.toBeNull();
    }
    // budget exhausted -- a fully valid, unexpired id is now rejected
    expect(verifyAndConsumeLoginRequestId(id, SECRET)).toBeNull();
  });

  it('tracks use counts independently per id', () => {
    const idA = signLoginRequestId(SECRET, 'cli');
    const idB = signLoginRequestId(SECRET, 'cli');

    for (let i = 0; i < MAX_USES; i++) {
      verifyAndConsumeLoginRequestId(idA, SECRET);
    }
    expect(verifyAndConsumeLoginRequestId(idA, SECRET)).toBeNull();
    // idB's own budget is untouched by idA's exhaustion
    expect(verifyAndConsumeLoginRequestId(idB, SECRET)).not.toBeNull();
  });
});

describe('loginRequestSecret', () => {
  it('is stable for one id and purpose, and differs across purposes, ids and secrets', () => {
    const id = signLoginRequestId(SECRET, 'cli');
    const other = signLoginRequestId(SECRET, 'cli');
    const pkce = loginRequestSecret(SECRET, 'pkce', id);

    expect(loginRequestSecret(SECRET, 'pkce', id)).toBe(pkce);
    expect(loginRequestSecret(SECRET, 'nonce', id)).not.toBe(pkce);
    expect(loginRequestSecret(SECRET, 'browser', id)).not.toBe(pkce);
    expect(loginRequestSecret(SECRET, 'pkce', other)).not.toBe(pkce);
    expect(loginRequestSecret('other-secret', 'pkce', id)).not.toBe(pkce);
  });

  it('is a valid PKCE code verifier: 43 characters of the unreserved alphabet', () => {
    const verifier = loginRequestSecret(
      SECRET,
      'pkce',
      signLoginRequestId(SECRET, 'cli'),
    );
    expect(verifier).toMatch(/^[A-Za-z0-9._~-]{43,128}$/);
  });
});

describe('checkAndConsumeMintBudget', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('allows up to MAX_MINTS_PER_WINDOW mints from one source, then rejects', () => {
    const source = `source-a-${Math.random()}`;
    for (let i = 0; i < MAX_MINTS_PER_WINDOW; i++) {
      expect(checkAndConsumeMintBudget(source)).toBe(true);
    }
    expect(checkAndConsumeMintBudget(source)).toBe(false);
  });

  it('tracks mint budgets independently per source', () => {
    const sourceA = `source-a-${Math.random()}`;
    const sourceB = `source-b-${Math.random()}`;

    for (let i = 0; i < MAX_MINTS_PER_WINDOW; i++) {
      checkAndConsumeMintBudget(sourceA);
    }
    expect(checkAndConsumeMintBudget(sourceA)).toBe(false);
    // sourceB's own budget is untouched by sourceA's exhaustion
    expect(checkAndConsumeMintBudget(sourceB)).toBe(true);
  });

  it('resets the budget once the window elapses', () => {
    const source = `source-a-${Math.random()}`;
    for (let i = 0; i < MAX_MINTS_PER_WINDOW; i++) {
      checkAndConsumeMintBudget(source);
    }
    expect(checkAndConsumeMintBudget(source)).toBe(false);

    vi.advanceTimersByTime((MINT_WINDOW_SEC + 1) * 1000);

    expect(checkAndConsumeMintBudget(source)).toBe(true);
  });
});

describe('createSourceBudget', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('counts per source within its own window', () => {
    const budget = createSourceBudget(2, 60);
    expect(budget.take('a')).toBe(true);
    expect(budget.take('a')).toBe(true);
    expect(budget.take('a')).toBe(false);
    expect(budget.take('b')).toBe(true);
    vi.advanceTimersByTime(61 * 1000);
    expect(budget.take('a')).toBe(true);
  });
});
