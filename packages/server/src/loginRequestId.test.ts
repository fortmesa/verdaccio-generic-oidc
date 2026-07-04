import {describe, it, expect, vi, beforeEach, afterEach} from 'vitest';
import {
  signLoginRequestId,
  verifyAndConsumeLoginRequestId,
  checkAndConsumeMintBudget,
  MAX_AGE_SEC,
  MAX_USES,
  MINT_WINDOW_SEC,
  MAX_MINTS_PER_WINDOW,
} from './loginRequestId';

const SECRET = 'test-secret';

describe('signLoginRequestId / verifyAndConsumeLoginRequestId', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('accepts an id signed with the matching secret', async () => {
    const id = await signLoginRequestId(SECRET);
    expect(verifyAndConsumeLoginRequestId(id, SECRET)).toBe(true);
  });

  it('rejects an id signed with a different secret', async () => {
    const id = await signLoginRequestId(SECRET);
    expect(verifyAndConsumeLoginRequestId(id, 'wrong-secret')).toBe(false);
  });

  it('rejects a completely forged id with no signature structure at all', () => {
    expect(
      verifyAndConsumeLoginRequestId('just-a-random-looking-string', SECRET),
    ).toBe(false);
  });

  it('rejects a forged id with a made-up timestamp and signature', () => {
    expect(
      verifyAndConsumeLoginRequestId(
        'somenonce.1700000000.deadbeefdeadbeefdeadbeefdeadbeef',
        SECRET,
      ),
    ).toBe(false);
  });

  it('rejects a tampered nonce paired with a previously-valid timestamp+signature', async () => {
    const id = await signLoginRequestId(SECRET);
    const firstDot = id.indexOf('.');
    const tampered = 'tampered-nonce' + id.slice(firstDot);
    expect(verifyAndConsumeLoginRequestId(tampered, SECRET)).toBe(false);
  });

  it('rejects a non-numeric issuedAt segment', async () => {
    const id = await signLoginRequestId(SECRET);
    const parts = id.split('.');
    const forged = `${parts[0]}.not-a-number.${parts[2]}`;
    expect(verifyAndConsumeLoginRequestId(forged, SECRET)).toBe(false);
  });

  it('rejects an empty string', () => {
    expect(verifyAndConsumeLoginRequestId('', SECRET)).toBe(false);
  });

  it('produces distinct ids on repeated calls', async () => {
    const id1 = await signLoginRequestId(SECRET);
    const id2 = await signLoginRequestId(SECRET);
    expect(id1).not.toEqual(id2);
  });

  it('rejects an id once it exceeds MAX_AGE_SEC', async () => {
    const id = await signLoginRequestId(SECRET);
    vi.advanceTimersByTime((MAX_AGE_SEC + 1) * 1000);
    expect(verifyAndConsumeLoginRequestId(id, SECRET)).toBe(false);
  });

  it('accepts an id right up to MAX_AGE_SEC', async () => {
    const id = await signLoginRequestId(SECRET);
    vi.advanceTimersByTime(MAX_AGE_SEC * 1000);
    expect(verifyAndConsumeLoginRequestId(id, SECRET)).toBe(true);
  });

  it('allows a valid id to be used up to MAX_USES times, then rejects it', async () => {
    const id = await signLoginRequestId(SECRET);
    for (let i = 0; i < MAX_USES; i++) {
      expect(verifyAndConsumeLoginRequestId(id, SECRET)).toBe(true);
    }
    // budget exhausted -- a fully valid, unexpired id is now rejected
    expect(verifyAndConsumeLoginRequestId(id, SECRET)).toBe(false);
  });

  it('tracks use counts independently per id', async () => {
    const idA = await signLoginRequestId(SECRET);
    const idB = await signLoginRequestId(SECRET);

    for (let i = 0; i < MAX_USES; i++) {
      verifyAndConsumeLoginRequestId(idA, SECRET);
    }
    expect(verifyAndConsumeLoginRequestId(idA, SECRET)).toBe(false);
    // idB's own budget is untouched by idA's exhaustion
    expect(verifyAndConsumeLoginRequestId(idB, SECRET)).toBe(true);
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
