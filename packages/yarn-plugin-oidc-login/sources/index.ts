import {Hooks as CoreHooks, Plugin, httpUtils} from '@yarnpkg/core';
import type {Hooks as NpmHooks} from '@yarnpkg/plugin-npm';
import type {WrapNetworkRequestInfo} from '@yarnpkg/core';

import {ensureLogin} from './loginHandshake';

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

async function retryWithFreshToken(
  extra: WrapNetworkRequestInfo,
  onFailure: () => httpUtils.Response,
): Promise<httpUtils.Response> {
  const token = await ensureLogin(
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
    // Fires before Yarn's own npmAuthToken/npmAuthIdent config lookup, and
    // before the "No authentication configured for request" throw that
    // lookup leads to when nothing is configured -- this is the only hook
    // that can intercept the "never logged in" case, since that throw
    // happens in the request's header-resolution step, before the
    // lower-level executor wrapNetworkRequest wraps is ever reached.
    async getNpmAuthenticationHeader(currentHeader, registry, {configuration}) {
      if (currentHeader) return currentHeader;
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
