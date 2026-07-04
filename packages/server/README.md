# @fortmesa/verdaccio-generic-oidc

Verdaccio authentication plugin for any standards-compliant OAuth2/OIDC provider
-- not tied to any one of them. When installed, `npm login --auth-type=web` /
`yarn npm login --web-login` (or Yarn users with
[the companion plugin](../yarn-plugin-oidc-login) installed, automatically on
any command) will open the browser to start the login flow.

Fork of
[verdaccio-openid-connect](https://github.com/deeplay-io/verdaccio-openid-connect)
by Dan Lytkin, MIT licensed. This fork adds:

- **Generalized groups/roles extraction**: `roles.claim` is now a dot-path (e.g.
  `resource_access.myclient.roles`), and handles flat arrays, comma strings,
  group-name-to-role-array maps, and group-name-to-object maps -- not just a
  single flat claim.
- **`roles.allowList`**: restricts which extracted groups actually reach
  Verdaccio, with the same semantics the older `verdaccio-bitbucket` plugin used
  (`"team1(admin|write),team2"`, or an equivalent native map) -- default-deny,
  empty list means unconditional, non-empty list means the user's role must
  intersect it.
- **An optional DynamoDB storage backend** (`dynamo.tableName`), alongside the
  existing Redis and filesystem ones -- none of the three are required
  dependencies unless you actually configure that backend.
- **`clientSecret` is now optional**: omit it and the plugin registers as a
  public client, using PKCE (S256) instead of a secret to protect the code
  exchange -- for providers that support a secret-less public web client
  (Keycloak, Auth0, Okta, Authentik; not Google).
- **In-memory session caching**: session lookups (which happen on every
  authenticated request, not just logins) are cached for a bounded window
  (`session.cacheTtl`, default 5 minutes) in front of whichever storage backend
  is configured, cutting recurring Redis/DynamoDB load.
- **Hardened, signed login request ids**: `/-/oidc/login`, `/-/oidc/callback`,
  and `/-/oidc/done` are necessarily unauthenticated, so upstream took its
  storage key straight from attacker-controlled input. This fork signs and
  rate-limits every login request id (HMAC + a use/age budget) so a forged or
  replayed id is rejected before ever touching storage -- and separately
  rate-limits `/-/v1/login` itself (the endpoint that issues those ids), so the
  per-id budget can't be defeated by simply minting an unlimited number of
  legitimate ones.

Compatible with Verdaccio 4.x, 5.x and 6.x (matches upstream; this fork adds
features, it doesn't narrow compatibility).

## Installation

    npm i -g @fortmesa/verdaccio-generic-oidc

In your Verdaccio config, the `auth:` (and `middlewares:`) key must be the
literal package name -- Verdaccio resolves a scoped plugin package name
verbatim, with no prefix mangling:

```yaml
auth:
  '@fortmesa/verdaccio-generic-oidc':
    # ...
```

## Configuration

- [Configuration reference](../../docs/configuration.md) -- the generic
  mechanism, start here.
- Provider-specific setup: [Google Workspace](../../docs/google-workspace.md),
  [Keycloak](../../docs/keycloak.md),
  [Azure Entra ID](../../docs/azure-entra-id.md)
- [Yarn integration](../../docs/yarn-integration.md)
- Full reference sample: [`config.yaml`](config.yaml) -- pre-wired to work as-is
  against this repo's Keycloak devcontainer (see below).

Note: your OpenID Connect client must be configured to allow
`${publicUrl}/-/oidc/callback` as a redirect URI.

## Letting a human log into the web UI directly

`POST /-/v1/login` (used above by `npm login --auth-type=web` /
`yarn npm login --web-login`) returns JSON, not something a person can click --
it exists for the CLI's own polling handshake, not for a browser. For a human
who wants to log into the registry's web UI itself, without running any CLI
command first, this plugin also exposes:

- **`GET /-/oidc/start`** -- a plain, unauthenticated link. Mints the same
  signed, rate-limited login request the CLI flow uses and redirects straight
  into it, so a person can just navigate to `${publicUrl}/-/oidc/start`
  (bookmark it, link to it from an internal wiki/portal, or see below) and land
  back on the web UI already authenticated. The callback page tries
  `window.close()` first (for the CLI's script-opened popup case) and falls back
  to redirecting to `/` a moment later if the tab is still open -- i.e. it works
  whether this was opened by a CLI or navigated to directly.

Verdaccio's stock web UI theme has no OIDC awareness at all -- there is no "Sign
in with Google" button anywhere in it, and adding one for real would mean
forking `@verdaccio/ui-theme` itself. The cheaper option, using a config key
Verdaccio's own web renderer already supports (`web.scriptsBodyAfter` -- an
array of raw HTML/`<script>` strings injected verbatim into the served page, no
plugin or theme changes needed), is to drop a visible link onto the _stock_
login page pointing at `/-/oidc/start`:

```yaml
web:
  scriptsBodyAfter:
    - |
      <script>
        document.addEventListener('DOMContentLoaded', () => {
          const a = document.createElement('a');
          a.href = '/-/oidc/start';
          a.textContent = 'Sign in with Google';
          a.style.cssText = 'position: fixed; bottom: 16px; right: 16px; padding: 8px 16px; background: #4285F4; color: #fff; border-radius: 4px; text-decoration: none; font-size: 14px; z-index: 9999;';
          document.body.appendChild(a);
        });
      </script>
```

## Baking a storage backend into your own Docker image

`ioredis`, `generic-pool`, `@aws-sdk/client-dynamodb`, and
`@aws-sdk/lib-dynamodb` are optional peerDependencies, not regular dependencies
-- a plain install of this package will **not** pull them in, by design, so
filesystem-only users don't get Redis or the AWS SDK forced on them. Neither
Yarn nor npm auto-installs an optional peerDependency for the package that
declares it (only for a _consumer_ that installs it explicitly), so building an
image that wants all three backends baked in unconditionally takes an explicit
step -- and Yarn specifically refuses to `add` a package that's already a
peerDependency without special handling. See the worked, tested example and full
explanation in [`Dockerfile`](Dockerfile) -- copy that pattern rather than
reinventing it.

## Local development / testing

```bash
docker compose up
./keycloak/bootstrap-test-user.sh
```

Brings up Verdaccio + Redis + a pre-provisioned Keycloak realm
(`keycloak/realm-export.json`) with a test user (`alice` / `alicepw`) holding
both a realm role and a client role, matching `config.yaml`'s defaults.

## Tests

```bash
yarn workspace @fortmesa/verdaccio-generic-oidc test
```

Requires Node `^20.19.0 || >=22.12.0` (see the repo root's `.nvmrc`) -- vitest's
Rolldown-based bundler calls a `util.styleText()` form only available from those
versions on, and crashes at startup on anything older.

Every module has direct unit test coverage:

- `src/groups.ts` -- every claim shape and filter outcome.
- `src/loginRequestId.ts` -- signature forgery, age limits, use/mint budgets.
- `src/cachedSession.ts` -- hit/miss/expiry/write-through behavior.
- `src/fs.ts`, `src/redis.ts`, `src/dynamo.ts` -- the three storage backends,
  each against a real (filesystem) or hand-rolled fake (Redis, DynamoDB) backing
  store, covering round-trips, expiry, and `keyPrefix` isolation.
- `src/index.ts` -- the plugin itself, driven end-to-end through a real local
  HTTP server acting as a fake OIDC issuer (real RS256-signed ID tokens, real
  JWKS, real discovery): the full login handshake for both confidential and PKCE
  clients, the token-exchange endpoint, session authentication, and rejection of
  forged login request ids.
