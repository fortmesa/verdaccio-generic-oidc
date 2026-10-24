# verdaccio-generic-oidc

A generic OAuth2/OIDC authentication plugin for Verdaccio -- works against any
standards-compliant provider (Google, Keycloak, Azure Entra ID, Okta, Auth0,
Cognito, Authentik, ...), not any one of them specifically. Forked from
[verdaccio-openid-connect](https://github.com/deeplay-io/verdaccio-openid-connect)
by Dan Lytkin (deeplay-io), MIT licensed.

This fork adds:

- Generalized groups/roles extraction and allow-list filtering, for claim shapes
  beyond a flat array (see `packages/server`).
- An optional DynamoDB session/token storage backend, alongside the existing
  Redis and filesystem backends (see `packages/server`).
- A companion Yarn Berry plugin that automatically drives this server's standard
  npm web-login handshake when a `yarn install` would otherwise fail due to a
  missing or expired token (see `packages/yarn-plugin-oidc-login`).

## Packages

- [`packages/server`](packages/server) -- published as
  [`@fortmesa/verdaccio-generic-oidc`](https://www.npmjs.com/package/@fortmesa/verdaccio-generic-oidc).
- [`packages/yarn-plugin-oidc-login`](packages/yarn-plugin-oidc-login) -- not
  published to npm; distributed as a built `.cjs` via `yarn plugin import`.
  **Supports Yarn 3.x and 4.x only** -- see
  [Yarn version support](docs/yarn-integration.md#yarn-version-support).

## Development

This is a Yarn 4 workspace (`packageManager` pins the exact version via Corepack
-- run `corepack enable` once if `yarn --version` doesn't already resolve to
it). From the repo root:

```bash
yarn install
yarn workspace @fortmesa/verdaccio-generic-oidc test
yarn workspace @fortmesa/verdaccio-generic-oidc build
yarn workspace @fortmesa/yarn-plugin-oidc-login build
```

`packages/server` is published standalone to npm and consumed with whatever tool
a user's project already uses (npm, yarn, pnpm) -- the workspace setup here only
affects how _this repo_ is developed, not how the published package is
installed.

The root `devDependencies` (`ioredis`, `@aws-sdk/*`) exist purely so a fresh
`yarn install` here gives local `tsc`/vitest something to resolve types against
-- `packages/server` declares these as _optional peerDependencies_ (real
consumers opt in to whichever storage backend they use), which neither Yarn nor
npm auto-installs for the package that declares them. This root is private and
never published, so there's no consumer-facing consequence to it also listing
them as devDependencies.

## Documentation

- [Configuration reference](docs/configuration.md) -- the generic mechanism:
  claim shapes, groups/roles extraction and filtering, how it feeds Verdaccio's
  `packages:` access control, storage backends. Start here.
- Provider-specific setup (only what actually differs per provider):
  [Google Workspace](docs/google-workspace.md), [Keycloak](docs/keycloak.md),
  [Azure Entra ID](docs/azure-entra-id.md)
- [Yarn integration](docs/yarn-integration.md)
- [Why `/-/v1/login` polls `doneUrl`](docs/web-login-protocol.md) -- why this
  can't be a "real" PKCE/device-grant CLI flow like `aws sso login`'s, and whose
  design choice (not this project's) that actually is.
