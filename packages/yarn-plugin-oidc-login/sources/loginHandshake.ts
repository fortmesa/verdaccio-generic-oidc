import {Configuration, httpUtils, nodeUtils} from '@yarnpkg/core';

/**
 * Drives the standard npm web-login handshake
 * (verdaccio-generic-oidc's server implements it):
 *
 *   POST /-/v1/login          -> {loginUrl, doneUrl}
 *   open loginUrl in a browser (real OIDC provider consent happens there)
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
// happens at a time, regardless of how many requests are waiting on it.
const inFlight = new Map<string, Promise<string | undefined>>();

function isInteractive(): boolean {
  return Boolean(process.stdout.isTTY) && !process.env.CI;
}

async function persistToken(registry: string, token: string): Promise<void> {
  await Configuration.updateHomeConfiguration({
    npmRegistries: (current: unknown) => {
      const map = new Map(current instanceof Map ? current : []);
      const entry = (map.get(registry) as Record<string, unknown>) ?? {};
      map.set(registry, {...entry, npmAuthToken: token});
      return map;
    },
  });
}

async function runHandshake(
  configuration: Configuration,
  registry: string,
): Promise<string | undefined> {
  let loginResponse: httpUtils.Response;
  try {
    loginResponse = await httpUtils.request(
      new URL('/-/v1/login', registry),
      null,
      {configuration, jsonResponse: true, method: httpUtils.Method.POST},
    );
  } catch {
    // Not every registry implements this handshake -- degrade silently and
    // let normal (config-based) auth resolution proceed.
    return undefined;
  }

  const {loginUrl, doneUrl} = loginResponse.body ?? {};
  if (typeof loginUrl !== 'string' || typeof doneUrl !== 'string') {
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
    `To finish logging in to ${registry}, open this URL:\n  ${loginUrl}`,
  );
  await nodeUtils.openUrl?.(loginUrl).catch(() => false);

  const deadline = Date.now() + POLL_TIMEOUT_MS;
  for (;;) {
    let doneResponse: httpUtils.Response;
    try {
      doneResponse = await httpUtils.request(doneUrl, null, {
        configuration,
        jsonResponse: true,
      });
    } catch {
      return undefined;
    }

    if (
      doneResponse.statusCode === 200 &&
      typeof doneResponse.body?.token === 'string'
    ) {
      return doneResponse.body.token;
    }

    if (Date.now() >= deadline) return undefined;

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
export async function ensureLogin(
  configuration: Configuration,
  registry: string,
): Promise<string | undefined> {
  if (!isInteractive()) return undefined;

  const existing = inFlight.get(registry);
  if (existing) return existing;

  const promise = runHandshake(configuration, registry)
    .then(async token => {
      if (token) await persistToken(registry, token);
      return token;
    })
    .finally(() => {
      inFlight.delete(registry);
    });

  inFlight.set(registry, promise);
  return promise;
}
