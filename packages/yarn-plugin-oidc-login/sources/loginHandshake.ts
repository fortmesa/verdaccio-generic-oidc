import {Configuration, httpUtils, nodeUtils} from '@yarnpkg/core';

/**
 * Drives the standard npm web-login handshake
 * (verdaccio-generic-oidc's server implements it):
 *
 *   POST /-/v1/login          -> {loginUrl, doneUrl}
 *   open loginUrl in a browser (the person confirms, then signs in with the
 *   real OIDC provider there)
 *   poll doneUrl               -> 202 while pending, 200 {token} once done
 *
 * This is the same protocol `npm login --auth-type=web` and
 * `yarn npm login --web-login` speak; we reimplement it (rather than shell
 * out to either) because we need to trigger it automatically from inside a
 * network-request hook, not as a standalone manually-invoked command.
 */

const POLL_TIMEOUT_MS = 5 * 60 * 1000;
const DEFAULT_POLL_INTERVAL_MS = 2000;

// Keyed by registry: dedupes concurrent callers (a cold `yarn install` fires
// many requests in parallel) so only one handshake -- and one browser tab --
// happens at a time, regardless of how many requests are waiting on it. This
// only covers callers racing while a handshake is still pending -- it's
// deleted once the handshake settles, so on its own it does NOT stop a
// second, later call from starting a brand new handshake.
const inFlight = new Map<string, Promise<string | undefined>>();

// The actual fix for repeat logins within one process: persistToken() below
// only writes to $HOME/.yarnrc.yml for *future* processes (see its own
// comment) -- this process's own Configuration object, and the header Yarn
// resolves from it, are never refreshed mid-run. index.ts checks this cache
// before the saved token and before starting a new handshake.
const tokenCache = new Map<string, string>();

// Registries whose POST /-/v1/login answered 404 (no web login there). Not
// asked again for the rest of this process.
const unsupported = new Set<string>();

// URLs this module itself is requesting right now. index.ts's 401 handling
// skips them, so a 401 from the login endpoint can't start another login
// that waits on the one already running.
const handshakeTargets = new Set<string>();

export function isHandshakeRequest(target: string | URL): boolean {
  return handshakeTargets.has(new URL(target).href);
}

export function cachedToken(registry: string): string | undefined {
  return tokenCache.get(registry);
}

function isInteractive(): boolean {
  return Boolean(process.stdout.isTTY) && !process.env.CI;
}

function warn(message: string): void {
  // eslint-disable-next-line no-console
  console.error(`oidc-login: ${message}`);
}

async function handshakeRequest(
  target: string,
  method: httpUtils.Method,
  configuration: Configuration,
): Promise<httpUtils.Response> {
  const href = new URL(target).href;
  handshakeTargets.add(href);
  try {
    return await httpUtils.request(href, null, {
      configuration,
      jsonResponse: true,
      method,
    });
  } finally {
    handshakeTargets.delete(href);
  }
}

function statusOf(err: unknown): number | undefined {
  const e = err as {
    response?: {statusCode?: number};
    originalError?: {response?: {statusCode?: number}};
  };
  return e?.response?.statusCode ?? e?.originalError?.response?.statusCode;
}

// loginUrl is opened with the system's URL handler, so it must be a web
// page; doneUrl returns the token, so it must not drop to plain http when
// the registry itself is https.
function validLoginUrls(
  registry: string,
  loginUrl: unknown,
  doneUrl: unknown,
): {loginUrl: string; doneUrl: string} | undefined {
  if (typeof loginUrl !== 'string' || typeof doneUrl !== 'string') {
    return undefined;
  }
  let login: URL;
  let done: URL;
  try {
    login = new URL(loginUrl);
    done = new URL(doneUrl);
  } catch {
    return undefined;
  }
  const secure = new URL(registry).protocol === 'https:';
  const allowed = secure ? ['https:'] : ['https:', 'http:'];
  if (!allowed.includes(login.protocol) || !allowed.includes(done.protocol)) {
    return undefined;
  }
  return {loginUrl: login.href, doneUrl: done.href};
}

async function persistToken(registry: string, token: string): Promise<void> {
  await Configuration.updateHomeConfiguration({
    // Must stay a plain object, never a Map: Yarn's own YAML serializer
    // (stringifySyml) silently drops this entire key when the value is a
    // Map instance -- confirmed directly against the real serializer, not
    // just theorized -- so a Map here means the token silently never gets
    // written at all, while every sibling top-level key still saves fine.
    // current is likewise always a plain object here (or undefined), never
    // a real Map -- it comes straight from YAML parsing.
    npmRegistries: (current: unknown) => {
      const registries =
        current && typeof current === 'object'
          ? {...(current as Record<string, unknown>)}
          : {};
      const entry = (registries[registry] as Record<string, unknown>) ?? {};
      registries[registry] = {...entry, npmAuthToken: token};
      return registries;
    },
  });
}

async function runHandshake(
  configuration: Configuration,
  registry: string,
): Promise<string | undefined> {
  if (unsupported.has(registry)) return undefined;

  let loginResponse: httpUtils.Response;
  try {
    loginResponse = await handshakeRequest(
      `${registry}/-/v1/login`,
      httpUtils.Method.POST,
      configuration,
    );
  } catch (err) {
    const status = statusOf(err);
    if (status === 404) {
      // Not every registry implements this handshake -- let normal
      // (config-based) auth resolution proceed, and don't ask again.
      unsupported.add(registry);
    } else if (status === 429) {
      warn(`${registry} refused to start a login: too many login attempts`);
    } else {
      warn(`could not start a login at ${registry}: ${(err as Error).message}`);
    }
    return undefined;
  }

  const urls = validLoginUrls(
    registry,
    loginResponse.body?.loginUrl,
    loginResponse.body?.doneUrl,
  );
  if (!urls) {
    warn(`${registry} answered /-/v1/login without usable login URLs`);
    return undefined;
  }

  // Always print the URL rather than trusting openUrl()'s return value alone:
  // it only reports whether the `xdg-open`/`open` *process* spawned
  // successfully, not whether a browser actually displayed anything --
  // confirmed by testing in a headless sandbox where it reports success
  // while showing the user nothing at all. Attempting to open it is still
  // worthwhile as a convenience for the common case where it does work.
  // eslint-disable-next-line no-console
  console.log(
    `To finish logging in to ${registry}, open this URL:\n  ${urls.loginUrl}`,
  );
  await nodeUtils.openUrl?.(urls.loginUrl).catch(() => false);

  const deadline = Date.now() + POLL_TIMEOUT_MS;
  for (;;) {
    let doneResponse: httpUtils.Response;
    try {
      doneResponse = await handshakeRequest(
        urls.doneUrl,
        httpUtils.Method.GET,
        configuration,
      );
    } catch (err) {
      const status = statusOf(err);
      warn(
        status === 400
          ? `the login at ${registry} expired before it was finished`
          : `the login at ${registry} failed: ${(err as Error).message}`,
      );
      return undefined;
    }

    if (
      doneResponse.statusCode === 200 &&
      typeof doneResponse.body?.token === 'string'
    ) {
      return doneResponse.body.token;
    }

    if (Date.now() >= deadline) {
      warn(`gave up waiting for the login at ${registry} to finish`);
      return undefined;
    }

    const retryAfterHeader = doneResponse.headers['retry-after'];
    const retryAfterSec = Array.isArray(retryAfterHeader)
      ? Number(retryAfterHeader[0])
      : Number(retryAfterHeader);
    const waitMs =
      Number.isFinite(retryAfterSec) && retryAfterSec > 0
        ? retryAfterSec * 1000
        : DEFAULT_POLL_INTERVAL_MS;

    await new Promise(resolve =>
      setTimeout(resolve, Math.min(waitMs, deadline - Date.now())),
    );
  }
}

/**
 * Ensures at most one handshake runs per registry at a time; persists the
 * result to $HOME/.yarnrc.yml (never the project's) for future processes,
 * and returns it directly so the CURRENT request can use it immediately --
 * updateHomeConfiguration only affects processes started after it returns.
 */
function runDedupedHandshake(
  configuration: Configuration,
  registry: string,
): Promise<string | undefined> {
  const existing = inFlight.get(registry);
  if (existing) return existing;

  const promise = runHandshake(configuration, registry)
    .then(async token => {
      if (token) {
        tokenCache.set(registry, token);
        await persistToken(registry, token);
      }
      return token;
    })
    .finally(() => {
      inFlight.delete(registry);
    });

  inFlight.set(registry, promise);
  return promise;
}

/**
 * Used from getNpmAuthenticationHeader: no header configured at all yet.
 * Reuses an already-obtained token for the rest of this process's lifetime.
 */
export async function ensureLogin(
  configuration: Configuration,
  registry: string,
): Promise<string | undefined> {
  if (!isInteractive()) return undefined;

  const cached = tokenCache.get(registry);
  if (cached) return cached;

  return runDedupedHandshake(configuration, registry);
}

/**
 * Used from wrapNetworkRequest once the newest token was refused with a
 * 401: it's discarded before logging in again, unlike ensureLogin's normal
 * reuse-what-we-have path.
 */
export async function refreshLogin(
  configuration: Configuration,
  registry: string,
): Promise<string | undefined> {
  if (!isInteractive()) return undefined;

  tokenCache.delete(registry);
  return runDedupedHandshake(configuration, registry);
}
