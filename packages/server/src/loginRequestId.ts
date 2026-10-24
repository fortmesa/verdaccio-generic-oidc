import {createHmac, randomBytes, timingSafeEqual} from 'crypto';

// Truncated to 16 bytes/32 hex chars -- this is a forgery check, not a
// general-purpose MAC, so the full SHA-256 output length buys nothing extra
// here while keeping the combined id (used as both a URL path segment and
// the OAuth `state` parameter) needlessly long.
const HMAC_BYTES = 16;

// Total time a signed id remains acceptable at all, regardless of how many
// times it's used within that window. It covers the whole human login: the
// confirmation page, the IdP's own sign-in (password, 2FA, consent), the
// callback, and the CLI's last poll of doneUrl. What stops someone else
// collecting a token through an id they minted is the confirmation click at
// loginUrl and doneUrl handing the token out once (see index.ts), not the
// length of this window.
export const MAX_AGE_SEC = 10 * 60;

// A legitimate login flow touches storage a small, predictable number of
// times: the confirmation page and its POST at /-/oidc/login, one write at
// /-/oidc/callback, and a handful of /-/oidc/done polls. /-/oidc/done blocks
// server-side for up to 10s per call, so even a client re-polling the
// instant each call returns can't exceed MAX_AGE_SEC / 10s =~ 60 calls
// within the id's lifetime -- 100 leaves headroom above that theoretical
// max without being anywhere close to "unlimited". This is the actual
// point: a valid, unexpired id -- whether leaked or entirely self-issued
// via the always-open /-/v1/login -- cannot be replayed to hammer
// Redis/DynamoDB indefinitely. It runs out.
export const MAX_USES = 100;

// The use-budget above only bounds abuse of a *single* id -- it does
// nothing to stop an attacker from minting an unlimited number of fresh,
// fully legitimate ids in the first place, since /-/v1/login is (correctly)
// unauthenticated and touches no storage at all (random bytes + an HMAC,
// both cheap local CPU). Without also capping the mint rate, MAX_USES is
// not a real bound at all: N minted ids x MAX_USES each is still
// N x MAX_USES total backend hits, and N is uncapped. Sharing the same
// window as MAX_AGE_SEC keeps this to one mental model ("how much can
// happen in the lifetime of an id"): at most MAX_MINTS_PER_WINDOW ids per
// source, each worth at most MAX_USES, bounds the real worst case to
// MAX_MINTS_PER_WINDOW * MAX_USES backend-touching calls per source per
// window -- a small, fixed number instead of an unbounded one.
export const MINT_WINDOW_SEC = MAX_AGE_SEC;
export const MAX_MINTS_PER_WINDOW = 30;

const GC_INTERVAL_MS = 60_000;

function computeMac(payload: string, secret: string): string {
  return createHmac('sha256', secret)
    .update(payload)
    .digest('hex')
    .slice(0, HMAC_BYTES * 2);
}

// What started the login: 'cli' is npm/yarn's web login (/-/v1/login),
// which picks its token up from doneUrl; 'web' is a person signing in to
// the web UI (/-/oidc/start), which never needs one stored for pickup.
export type LoginRequestKind = 'cli' | 'web';

export interface LoginRequest {
  kind: LoginRequestKind;
  issuedAt: number;
}

// nonce: 16 random bytes, base64url. mac: HMAC_BYTES of lowercase hex.
// Anything else is rejected before the MAC is checked, so one id can't be
// re-spelled (upper-case hex, trailing junk Buffer.from(hex) would ignore)
// into many ids that each get a fresh use budget.
const LOGIN_REQUEST_ID_PATTERN =
  /^([A-Za-z0-9_-]{22})\.(\d{1,12})\.(cli|web)\.([0-9a-f]{32})$/;

/**
 * A value only this registry can compute for one login request id, for the
 * given purpose: the PKCE code verifier, the OIDC nonce, and the cookie that
 * ties the callback to the browser that started the login. Deriving them
 * from the id with the instance secret means none of them has to be stored
 * between /-/oidc/login and /-/oidc/callback. The id itself travels in URLs
 * and the `state` parameter; these never do, apart from the nonce, which
 * the IdP echoes back inside the signed ID token.
 */
export function loginRequestSecret(
  secret: string,
  purpose: 'pkce' | 'nonce' | 'browser',
  id: string,
): string {
  return createHmac('sha256', secret)
    .update(`${purpose}:${id}`)
    .digest('base64url');
}

type BudgetEntry = {count: number; issuedAt: number};

// Deliberately not backed by Redis/DynamoDB, since the whole point of this
// module is bounding abuse *without* adding a new backend round-trip to
// routes that exist specifically to reject abuse before touching the
// backend. A determined attacker could spread requests across replicas to
// get the budget per replica rather than in total; that's an accepted
// trade-off for a local, zero-round-trip check layered in front of the
// real storage calls.
//
// Entries are only ever relevant for `maxAgeSec` after they're created --
// anything past that has already failed (or will fail) its own age check
// regardless of count, so it's safe to prune on a fixed schedule rather
// than tracking per-entry expiry separately.
function startBudgetGc(map: Map<string, BudgetEntry>, maxAgeSec: number): void {
  const timer = setInterval(() => {
    const nowSec = Math.floor(Date.now() / 1000);
    for (const [key, entry] of map) {
      if (nowSec - entry.issuedAt > maxAgeSec) map.delete(key);
    }
  }, GC_INTERVAL_MS);
  timer.unref?.();
}

// Keyed by the id's nonce.
const useCounts = new Map<string, BudgetEntry>();
startBudgetGc(useCounts, MAX_AGE_SEC);

/**
 * A per-source counter over fixed windows: take(source) returns false once
 * that source has used `max` within the current `windowSec` window. Used for
 * the mint budget below and for token-exchange attempts in index.ts.
 *
 * Sources are whatever the caller passes, in practice req.ip, which
 * reflects whatever trust-proxy configuration Verdaccio's own Express app
 * has (or hasn't) been given -- this plugin doesn't set that itself, it only
 * adds routes to Verdaccio's existing app. If you're running behind a
 * reverse proxy, verify req.ip actually resolves to real client addresses
 * for your deployment, not the proxy's own address -- otherwise every user
 * behind that proxy shares one budget.
 */
export function createSourceBudget(
  max: number,
  windowSec: number,
): {take(source: string): boolean} {
  const counts = new Map<string, BudgetEntry>();
  startBudgetGc(counts, windowSec);
  return {
    take(source: string): boolean {
      const nowSec = Math.floor(Date.now() / 1000);
      const entry = counts.get(source);
      if (entry == null || nowSec - entry.issuedAt > windowSec) {
        counts.set(source, {count: 1, issuedAt: nowSec});
        return true;
      }
      if (entry.count >= max) return false;
      entry.count += 1;
      return true;
    },
  };
}

const mintBudget = createSourceBudget(MAX_MINTS_PER_WINDOW, MINT_WINDOW_SEC);

/**
 * Call before signLoginRequestId() with a per-source key (req.ip). Returns
 * false once that source has minted MAX_MINTS_PER_WINDOW ids within the
 * current window -- the caller should reject the request (429) without
 * minting anything, rather than handing out an id that just adds to an
 * already-large pile.
 */
export function checkAndConsumeMintBudget(source: string): boolean {
  return mintBudget.take(source);
}

/**
 * /-/oidc/login, /-/oidc/callback, and /-/oidc/done are all necessarily
 * unauthenticated (that's the point of a login flow) and, without this,
 * took their session/token storage key straight from attacker-controlled
 * input (a URL path segment or the OAuth `state` query param) -- letting
 * anyone force a real Redis/DynamoDB round-trip (or, for Redis's blocking
 * XREAD, hold a pooled connection for up to 10s) per garbage request, with
 * no way to tell it apart from a real login.
 *
 * Signing the id at issuance -- and verifying both the signature and a
 * bounded age/use-count budget before ever touching storage -- closes
 * this. Forging a valid signature requires knowing `secret` (the same
 * Verdaccio instance secret already used to sign npm/web JWTs, so this
 * works correctly across replicas without any new shared state).
 *
 * Signature validity alone isn't enough, though: /-/v1/login is (correctly)
 * unauthenticated and free to call, so an attacker can always mint any
 * number of fully legitimate signed ids. The per-id age/use-count budget
 * only bounds abuse of *one* id -- an attacker who can mint unlimited ids
 * isn't limited by it at all (N ids x MAX_USES each is still unbounded as
 * N grows). checkAndConsumeMintBudget() below closes that: it caps how
 * many ids a single source can mint per window, so the two bounds
 * together (mints per source, uses per id) turn "unbounded" into a small,
 * fixed MAX_MINTS_PER_WINDOW * MAX_USES per source per window.
 */
export function signLoginRequestId(
  secret: string,
  kind: LoginRequestKind,
): string {
  const nonce = randomBytes(16).toString('base64url');
  const issuedAt = Math.floor(Date.now() / 1000);
  const payload = `${nonce}.${issuedAt}.${kind}`;
  return `${payload}.${computeMac(payload, secret)}`;
}

/**
 * Returns the id's kind and issue time when its signature checks out, it is
 * younger than MAX_AGE_SEC and it has use budget left (counting this use),
 * or null otherwise.
 */
export function verifyAndConsumeLoginRequestId(
  id: string,
  secret: string,
): LoginRequest | null {
  const match = LOGIN_REQUEST_ID_PATTERN.exec(id);
  if (!match) return null;
  const [, nonce, issuedAtRaw, kind, mac] = match;

  const payload = `${nonce}.${issuedAtRaw}.${kind}`;
  const provided = Buffer.from(mac, 'hex');
  const expected = Buffer.from(computeMac(payload, secret), 'hex');
  if (
    provided.length !== expected.length ||
    !timingSafeEqual(provided, expected)
  ) {
    return null;
  }

  const issuedAt = Number(issuedAtRaw);
  const ageSec = Math.floor(Date.now() / 1000) - issuedAt;
  if (ageSec < 0 || ageSec > MAX_AGE_SEC) return null;

  const entry = useCounts.get(nonce) ?? {count: 0, issuedAt};
  if (entry.count >= MAX_USES) return null;
  entry.count += 1;
  useCounts.set(nonce, entry);

  return {kind: kind as LoginRequestKind, issuedAt};
}
