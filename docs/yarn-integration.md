# Yarn (Berry) integration

`packages/yarn-plugin-oidc-login` is a small Yarn Berry plugin: when
`yarn install` (or any other command touching the registry) has no token
configured, or gets a 401 because a previously-good token expired, it
automatically drives this server's login handshake instead of just failing.
Everything below is verified against a real Keycloak + verdaccio devcontainer,
not just written from the design.

## Installing the plugin

The plugin isn't published to npm -- it's distributed as a single built `.cjs`,
the standard way for Yarn Berry plugins:

```bash
yarn plugin import https://github.com/fortmesa/verdaccio-generic-oidc/releases/download/vX.Y.Z/plugin-oidc-login.cjs
```

This does everything for you -- no manual file copying or YAML editing: Yarn
reads the file, writes it to `.yarn/plugins/@yarnpkg/plugin-oidc-login.cjs` (the
name it lands under is normalized by Yarn's own build tooling, not
`@fortmesa/...` -- that's expected), and registers it in the project's
`.yarnrc.yml` under `plugins:` with a checksum.

## Required `.yarnrc.yml` shape

```yaml
npmRegistryServer: 'https://npm.example.com'
npmRegistries:
  'https://npm.example.com':
    npmAlwaysAuth: true
```

**Do not** set `npmAuthIdent` or `npmAuthToken` to a literal value or an
`${ENV_VAR}` reference for this registry in the _project_ `.yarnrc.yml`. Two
reasons, both confirmed directly rather than assumed:

1. This plugin supplies the token per-request via the
   `getNpmAuthenticationHeader` hook -- no static config is needed for it to
   work at all.
2. If the project config references an environment variable that happens to be
   unset (e.g. a fresh `docker exec` shell that never had it exported), Yarn
   throws `Environment variable not found` and refuses to run _any_ command,
   regardless of what a valid token elsewhere might supply. Static config
   referencing an env var and this plugin are not a safe combination in the same
   `.yarnrc.yml` entry.

## Where the token actually lives

The plugin never writes to the project's `.yarnrc.yml`. It calls Yarn's own
`Configuration.updateHomeConfiguration()` -- the same mechanism `yarn npm login`
itself uses -- which writes to `$HOME/.yarnrc.yml`. If you're running Yarn
inside a container, that keeps the token off anything bind-mounted from a
git-tracked host directory, and it persists across `docker exec` invocations
into the same container since it's a real file, not a shell-scoped environment
variable.

## What actually happens on a cold install

Confirmed via server request logs during real testing, not assumed:

1. `getNpmAuthenticationHeader` fires before Yarn's own token lookup.
2. It `POST`s `/-/v1/login` to the registry, gets back `{loginUrl, doneUrl}`.
3. It prints the login URL to the terminal and attempts to open it in a browser.
   Print it either way -- this repo found in real testing that Yarn's `openUrl`
   helper reports success as long as the `open`/`xdg-open` process spawned, not
   whether a browser actually displayed anything, so it's not reliable as the
   sole signal.
4. It polls `doneUrl` (honoring `Retry-After`) until you finish the OIDC
   provider's login page, then returns the token for the current request _and_
   persists it to `$HOME/.yarnrc.yml` for future ones.
5. Concurrent requests (a cold `yarn install` fires many in parallel) share a
   single in-flight handshake rather than each opening their own browser tab.

If a token was already configured but the registry rejects it as expired with a
401, `wrapNetworkRequest` catches that specifically and redoes the same
handshake before retrying the request once.

## Manual login

You don't need to wait for an install to trigger it -- this also works,
confirmed against the same server:

```bash
yarn npm login --web-login
```

This is Yarn's own built-in command speaking the exact same `/-/v1/login` ->
`doneUrl` protocol the plugin drives automatically. Useful if you'd rather log
in ahead of time.

## CI

The plugin deliberately does nothing when it detects a non-interactive
environment (`CI` env var set, or no TTY) -- confirmed live: with `CI=1`, zero
extra requests reach the server at all, and the install fails immediately with
the original "Invalid authentication" error rather than hanging waiting for a
browser that will never open.

CI needs a token provisioned some other way -- there's no automatic, headless
path here, by design:

- Mint a token once (`yarn npm login --web-login` from a real terminal, or the
  `PUT /-/user/org.couchdb.user::userId` token-exchange endpoint if your CI
  already produces its own OIDC token, e.g. from GitHub Actions' or Bitbucket
  Pipelines' own OIDC support), and
- store it as a pipeline secret, written into `$HOME/.yarnrc.yml`
  (`yarn config set 'npmRegistries["<registry>"].npmAuthToken' "$TOKEN" --home`)
  as a setup step before `yarn install` runs.

## Troubleshooting

- **Install hangs with no output**: you're probably in a non-interactive shell
  that Yarn doesn't recognize as having a TTY (some CI runners, some
  containerized shells) but without `CI` set. Set `CI=1` explicitly to get a
  fast, clear failure instead, then provision a token per the CI section above.
- **Nothing happens, install just fails**: check whether the registry actually
  implements `POST /-/v1/login` in the shape this plugin expects -- it silently
  no-ops against any registry that doesn't, by design, so a misconfigured
  `npmRegistryServer` pointing somewhere else will look like "the plugin isn't
  doing anything" rather than an obvious error.
- **Force a fresh login**: remove the relevant entry from `npmRegistries` in
  `$HOME/.yarnrc.yml` and re-run.
