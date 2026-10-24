import {
  Hooks as CoreHooks,
  Plugin,
  YarnVersion,
  httpUtils,
} from '@yarnpkg/core';
import type {Configuration, Ident, WrapNetworkRequestInfo} from '@yarnpkg/core';
import type {Hooks as NpmHooks} from '@yarnpkg/plugin-npm';
import {npmConfigUtils} from '@yarnpkg/plugin-npm';

import {
  cachedToken,
  ensureLogin,
  isHandshakeRequest,
  refreshLogin,
} from './loginHandshake';

function is401(candidate: unknown): boolean {
  const err = candidate as {
    statusCode?: number;
    response?: {statusCode?: number};
    originalError?: {response?: {statusCode?: number}};
  } | null;
  return (
    err?.statusCode === 401 ||
    err?.response?.statusCode === 401 ||
    err?.originalError?.response?.statusCode === 401
  );
}

// Every registry this configuration names, normalized the way Yarn's own
// npmConfigUtils does (no trailing slash).
function configuredRegistries(configuration: Configuration): string[] {
  const registries = new Set<string>();
  const add = (value: unknown) => {
    if (typeof value === 'string' && value !== '') {
      registries.add(npmConfigUtils.normalizeRegistry(value));
    }
  };
  add(configuration.get('npmRegistryServer'));
  add(configuration.get('npmPublishRegistry'));
  for (const scope of (
    configuration.get('npmScopes') as Map<string, Map<string, unknown>>
  ).values()) {
    add(scope.get('npmRegistryServer'));
    add(scope.get('npmPublishRegistry'));
  }
  for (const registry of (
    configuration.get('npmRegistries') as Map<string, unknown>
  ).keys()) {
    if (/^https?:/.test(registry)) add(registry);
  }
  return [...registries];
}

// The configured registry a request goes to (the longest one its URL
// starts with), or undefined for a request to any other host.
function registryFor(
  target: string | URL,
  configuration: Configuration,
): string | undefined {
  const href = new URL(target).href;
  let match: string | undefined;
  for (const registry of configuredRegistries(configuration)) {
    if (
      (href === registry || href.startsWith(`${registry}/`)) &&
      (match == null || registry.length > match.length)
    ) {
      match = registry;
    }
  }
  return match;
}

function hasConfiguredCredential(
  registry: string,
  configuration: Configuration,
  ident: Ident | undefined,
): boolean {
  const auth = npmConfigUtils.getAuthConfiguration(registry, {
    configuration,
    ident,
  });
  return Boolean(auth.get('npmAuthToken') || auth.get('npmAuthIdent'));
}

function bearerToken(headers: WrapNetworkRequestInfo['headers']) {
  const header = headers?.authorization;
  return header?.startsWith('Bearer ') ? header.slice(7) : undefined;
}

// A token for the request that just got a 401. If another request already
// logged in again since this one was sent, that token is used and no new
// login starts; only a refusal of the newest token logs in again.
async function freshToken(
  extra: WrapNetworkRequestInfo,
  registry: string,
): Promise<string | undefined> {
  const cached = cachedToken(registry);
  if (cached != null && cached !== bearerToken(extra.headers)) return cached;
  return refreshLogin(extra.configuration, registry);
}

// Yarn 4 hands this hook the same options object its request reads its
// headers from when it runs; Yarn 3 builds the request from its own copy.
const EXECUTOR_READS_EXTRA = Number(YarnVersion?.split('.')[0]) >= 4;

// Header objects of requests retryWith() sent itself, which the hook below
// passes straight through.
const retryHeaders = new WeakSet<object>();

// Sends the request again with the new token, so that a second 401 is
// returned instead of starting yet another login. On Yarn 4 it re-runs the
// same executor, which includes any wrapper the caller added (the npm
// metadata cache's 304 handling, for one) that a fresh httpUtils.request()
// would leave out. Yarn 3 has no such wrappers, so the request is sent anew.
function retryWith(
  executor: () => Promise<httpUtils.Response>,
  extra: WrapNetworkRequestInfo,
  token: string,
): Promise<httpUtils.Response> {
  const headers = {...extra.headers, authorization: `Bearer ${token}`};
  if (EXECUTOR_READS_EXTRA) {
    extra.headers = headers;
    return executor();
  }
  retryHeaders.add(headers);
  return httpUtils.request(extra.target, extra.body, {...extra, headers});
}

const plugin: Plugin<CoreHooks & NpmHooks> = {
  hooks: {
    // Fires before Yarn's own npmAuthToken/npmAuthIdent config lookup (that
    // lookup is what would otherwise throw "No authentication configured
    // for request"), which is exactly why currentHeader is *always*
    // undefined here -- Yarn's own reduceHook call starts this hook chain
    // with `void 0`, and Yarn's own npmAuthToken check only runs *after*
    // this hook returns. So currentHeader can only ever reflect an earlier
    // plugin's own hook output, never a real, already-saved config value.
    async getNpmAuthenticationHeader(
      currentHeader,
      registry,
      {configuration, ident},
    ) {
      if (currentHeader) return currentHeader;
      // A token this process logged in for comes first: Yarn's in-memory
      // configuration still holds whatever was saved before, which may be
      // the token the registry just refused.
      const cached = cachedToken(registry);
      if (cached) return `Bearer ${cached}`;
      // A configured token or ident is Yarn's own to send.
      if (hasConfiguredCredential(registry, configuration, ident)) {
        return currentHeader;
      }
      const token = await ensureLogin(configuration, registry);
      return token ? `Bearer ${token}` : currentHeader;
    },

    // Handles the other case: a token WAS sent but the registry rejects it
    // as stale/expired with a 401. Only for configured registries, and never
    // for this plugin's own login requests.
    async wrapNetworkRequest(executor, extra) {
      const registry = registryFor(extra.target, extra.configuration);
      if (
        registry == null ||
        isHandshakeRequest(extra.target) ||
        (extra.headers != null && retryHeaders.has(extra.headers))
      ) {
        return executor;
      }
      return async () => {
        let rejected: httpUtils.Response;
        try {
          rejected = await executor();
          if (rejected.statusCode !== 401) return rejected;
        } catch (err) {
          if (!is401(err)) throw err;
          const token = await freshToken(extra, registry);
          if (!token) throw err;
          return retryWith(executor, extra, token);
        }
        const token = await freshToken(extra, registry);
        if (!token) return rejected;
        return retryWith(executor, extra, token);
      };
    },
  },
};

export default plugin;
