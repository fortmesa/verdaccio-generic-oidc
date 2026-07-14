import {createHmac, timingSafeEqual} from 'crypto';
import {nanoid} from 'nanoid/async';

// Truncated to 16 bytes/32 hex chars -- this is a forgery check, not a
// general-purpose MAC, so the full SHA-256 output length buys nothing extra
// here while keeping the combined id (used as both a URL path segment and
// the OAuth `state` parameter) needlessly long.
const HMAC_BYTES = 16;

// Total time a signed id remains acceptable at all, regardless of how many
// times it's used within that window. Deliberately short: this is also the
// realistic window for the device-code-phishing-style risk described in
// docs/web-login-protocol.md (an attacker mints an id, hands loginUrl to a
// victim, then polls doneUrl themselves) -- npm/Yarn's own client protocol
// gives no way to close that off outright (see that doc), so keeping this
// window tight is the one thing this project can still do to shrink the
// realistic attack window, short of breaking real login usability. 90s
// is the floor a real human needs to open the browser, authenticate with
// the IdP, and land back on the callback page.
export const MAX_AGE_SEC = 90;

// A legitimate login flow touches storage a small, predictable number of
// times: one write at /-/oidc/login, one read (plus a possible PKCE lookup)
// at /-/oidc/callback, and a handful of /-/oidc/done polls. /-/oidc/done blocks
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
// unauthenticated and touches no storage at all (just nanoid() + an HMAC,
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

const useCounts = new Map<string, BudgetEntry>();
startBudgetGc(useCounts, MAX_AGE_SEC);

// Keyed by source (in practice, req.ip).
const mintCounts = new Map<string, BudgetEntry>();
startBudgetGc(mintCounts, MINT_WINDOW_SEC);

/**
 * Call before signLoginRequestId() with a per-source key (req.ip). Returns
 * false once that source has minted MAX_MINTS_PER_WINDOW ids within the
 * current window -- the caller should reject the request (429) without
 * minting anything, rather than handing out an id that just adds to an
 * already-large pile.
 *
 * req.ip reflects whatever trust-proxy configuration Verdaccio's own
 * Express app has (or hasn't) been given -- this plugin doesn't set that
 * itself, it only adds routes to Verdaccio's existing app. If you're
 * running behind a reverse proxy, verify req.ip actually resolves to real
 * client addresses for your deployment, not the proxy's own address --
 * otherwise every user behind that proxy shares one mint budget.
 */
export function checkAndConsumeMintBudget(source: string): boolean {
  const nowSec = Math.floor(Date.now() / 1000);
  const entry = mintCounts.get(source);

  if (entry == null || nowSec - entry.issuedAt > MINT_WINDOW_SEC) {
    mintCounts.set(source, {count: 1, issuedAt: nowSec});
    return true;
  }

  if (entry.count >= MAX_MINTS_PER_WINDOW) return false;
  entry.count += 1;
  return true;
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
export async function signLoginRequestId(secret: string): Promise<string> {
  const nonce = await nanoid();
  const issuedAt = Math.floor(Date.now() / 1000);
  const payload = `${nonce}.${issuedAt}`;
  return `${payload}.${computeMac(payload, secret)}`;
}

export function verifyAndConsumeLoginRequestId(
  id: string,
  secret: string,
): boolean {
  const parts = id.split('.');
  if (parts.length !== 3) return false;
  const [nonce, issuedAtRaw, mac] = parts;

  const issuedAt = Number(issuedAtRaw);
  if (!Number.isInteger(issuedAt)) return false;

  const payload = `${nonce}.${issuedAtRaw}`;
  const provided = Buffer.from(mac, 'hex');
  const expected = Buffer.from(computeMac(payload, secret), 'hex');
  if (
    provided.length !== expected.length ||
    !timingSafeEqual(provided, expected)
  ) {
    return false;
  }

  const ageSec = Math.floor(Date.now() / 1000) - issuedAt;
  if (ageSec < 0 || ageSec > MAX_AGE_SEC) return false;

  const entry = useCounts.get(id) ?? {count: 0, issuedAt};
  if (entry.count >= MAX_USES) return false;
  entry.count += 1;
  useCounts.set(id, entry);

  return true;
}
