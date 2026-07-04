import {Hooks as CoreHooks, Plugin, httpUtils} from '@yarnpkg/core';
import type {Configuration, WrapNetworkRequestInfo} from '@yarnpkg/core';
import type {Hooks as NpmHooks} from '@yarnpkg/plugin-npm';
import {npmConfigUtils} from '@yarnpkg/plugin-npm';

import {ensureLogin, refreshLogin} from './loginHandshake';

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

function registryOrigin(target: string | URL): string {
  return new URL(target).origin;
}

function existingNpmAuthToken(
  registry: string,
  configuration: Configuration,
): string | undefined {
  const token = npmConfigUtils
    .getAuthConfiguration(registry, {configuration})
    .get('npmAuthToken');
  return typeof token === 'string' ? token : undefined;
}

async function retryWithFreshToken(
  extra: WrapNetworkRequestInfo,
  onFailure: () => httpUtils.Response,
): Promise<httpUtils.Response> {
  // refreshLogin, not ensureLogin: the cached token (if any) is the one that
  // was just rejected with a 401, so it must be discarded, not reused.
  const token = await refreshLogin(
    extra.configuration,
    registryOrigin(extra.target),
  );
  if (!token) return onFailure();

  return httpUtils.request(extra.target, extra.body, {
    ...extra,
    headers: {...extra.headers, authorization: `Bearer ${token}`},
  });
}

const plugin: Plugin<CoreHooks & NpmHooks> = {
  hooks: {
    // Fires before Yarn's own npmAuthToken/npmAuthIdent config lookup (that
    // lookup is what would otherwise throw "No authentication configured
    // for request"), which is exactly why currentHeader is *always*
    // undefined here -- Yarn's own reduceHook call starts this hook chain
    // with `void 0`, and Yarn's own npmAuthToken check only runs *after*
    // this hook returns. So currentHeader can only ever reflect an earlier
    // plugin's own hook output, never a real, already-saved config value --
    // checking it alone made this hook re-run the login handshake on every
    // single process, even with a valid token already persisted. The actual
    // saved token has to be read directly, the same way Yarn's own
    // subsequent check does.
    async getNpmAuthenticationHeader(currentHeader, registry, {configuration}) {
      if (currentHeader) return currentHeader;
      const saved = existingNpmAuthToken(registry, configuration);
      if (saved) return `Bearer ${saved}`;
      const token = await ensureLogin(configuration, registry);
      return token ? `Bearer ${token}` : currentHeader;
    },

    // Handles the other case: a token WAS configured (so the hook above
    // deferred to it) but the server rejects it as stale/expired with a 401.
    async wrapNetworkRequest(executor, extra) {
      return async () => {
        try {
          const response = await executor();
          if (response.statusCode !== 401) return response;
          return retryWithFreshToken(extra, () => response);
        } catch (err) {
          if (!is401(err)) throw err;
          return retryWithFreshToken(extra, () => {
            throw err;
          });
        }
      };
    },
  },
};

export default plugin;
