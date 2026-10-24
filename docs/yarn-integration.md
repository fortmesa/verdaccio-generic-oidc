# Yarn (Berry) integration

`packages/yarn-plugin-oidc-login` is a small Yarn Berry plugin: a
quality-of-life improvement over Yarn's normal behavior, not a different login
mechanism. Without it, `yarn install` (or any other command touching the
registry) with no token configured, or a 401 because a previously-good token
expired, just fails with an auth error -- you then have to separately run a
login command and rerun whatever you were doing. With the plugin installed, it
detects that same condition inline and automatically drives this server's login
handshake itself, then lets the original command continue -- collapsing "fail,
log in separately, rerun" into one step. Everything below is verified against a
real Keycloak + verdaccio devcontainer, not just written from the design.

## Yarn version support

**Only Yarn 3.x and 4.x are supported.** The plugin depends on two Yarn Berry
hooks -- `getNpmAuthenticationHeader` (supplies the auth header before a request
goes out) and `wrapNetworkRequest` (retries a stale-token 401 with a
freshly-obtained one) -- and neither exists in Yarn 2.x. Confirmed directly
against each version's own bundled `yarn.js`: zero matches for either hook name
in yarn 2.4.3, versus one match each in 3.8.7 and two/one in 4.17.0.
`yarn plugin import` still succeeds on 2.x with no error -- a silent no-op, not
a loud failure -- so don't rely on an import-time error to catch a 2.x project;
both hooks simply never fire. Yarn Classic (1.x) isn't Yarn Berry at all and was
never a candidate.

See `packages/yarn-plugin-oidc-login/test/cli-real.js`
(`yarn workspace @fortmesa/yarn-plugin-oidc-login test:cli-real`) for the real,
corepack-driven test against both supported versions -- separate from the rest
of this monorepo's fast/offline test suite since it activates real Yarn releases
and spins up a real local HTTP server.

## Command coverage: more than just install/add

Both hooks fire for every `yarn npm` subcommand that actually touches the
registry, not just package installation -- confirmed directly with a
debug-instrumented copy of this plugin (temporary `console.error` calls inside
both hooks, not inferred from error text alone) run against real Yarn
3.8.7/4.17.0 for: `add`/`install` (the original motivating case), `npm audit`,
`npm info`, `npm publish`, `npm tag add`/`list`, and `npm stage list`.
`npm logout` makes no network call at all -- it's a purely local config-file
edit, nothing for either hook to intercept.

This isn't a coincidence needing per-command support: `@yarnpkg/plugin-npm`
funnels every one of these operations through the same shared HTTP/auth-header
pipeline `getNpmAuthenticationHeader` and `wrapNetworkRequest` are wired into,
rather than reimplementing auth per subcommand. That's _why_ one pair of hooks
is enough to cover the whole `yarn npm` surface, not just the install path this
plugin was originally built for.

`test/cli-real.js` encodes four of these as permanent regression checks against
both supported Yarn versions -- `add`, `npm whoami` (a read), `npm publish` (a
write), and `npm audit` (a bulk query) -- chosen to be representative of the
shared pipeline above rather than exhaustively re-testing every subcommand that
goes through the exact same code path. If a future Yarn release ever splits one
of these onto a different code path (unlikely, but this is exactly the kind of
internal-architecture assumption that a version bump could quietly break), one
of those four checks should catch it.

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

See [Why `/-/v1/login` polls `doneUrl`](web-login-protocol.md) for why step 4
below is a polling handshake at all, rather than Yarn doing a PKCE/device-grant
exchange itself the way `aws sso login` does -- that's npm's own client-side
protocol design, not something this plugin or the server it talks to chose.

Confirmed via server request logs during real testing, not assumed:

1. `getNpmAuthenticationHeader` fires before Yarn's own token lookup.
2. It `POST`s `/-/v1/login` to the registry, gets back `{loginUrl, doneUrl}`.
3. It prints the login URL to the terminal and attempts to open it in a browser.
   Print it either way -- this repo found in real testing that Yarn's `openUrl`
   helper reports success as long as the `open`/`xdg-open` process spawned, not
   whether a browser actually displayed anything, so it's not reliable as the
   sole signal. The page asks you to confirm before it goes to the OIDC
   provider.
4. It polls `doneUrl` (honoring `Retry-After`) until you finish the OIDC
   provider's login page, then returns the token for the current request _and_
   persists it to `$HOME/.yarnrc.yml` for future ones. The server allows 10
   minutes from step 2 to the last poll.
5. Concurrent requests (a cold `yarn install` fires many in parallel) share a
   single in-flight handshake rather than each opening their own browser tab.

If a token was already configured but the registry rejects it as expired with a
401, `wrapNetworkRequest` catches that specifically, redoes the same handshake,
and sends the request again once with the new token. Every later request in the
same command uses the new token, so one install logs in once, not once per wave
of requests.

The plugin only acts for registries the configuration names
(`npmRegistryServer`, `npmPublishRegistry`, `npmScopes.*`, `npmRegistries`); a
401 from any other host is left alone. A registry with its own `npmAuthToken` or
`npmAuthIdent` configured gets that credential from Yarn as usual, and the
plugin only steps in if the registry refuses it. `loginUrl` must be an http(s)
URL, and neither URL may be plain http when the registry is https. When a login
can't finish (the server refused to start one, the 10 minutes ran out, or the
URLs it returned were refused), the plugin prints why.

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
  implements `POST /-/v1/login` in the shape this plugin expects. A registry
  that answers it with 404 is taken to have no web login, without a message, and
  isn't asked again in that command, so a misconfigured `npmRegistryServer`
  pointing somewhere else will look like "the plugin isn't doing anything"
  rather than an obvious error.
- **Force a fresh login**: remove the relevant entry from `npmRegistries` in
  `$HOME/.yarnrc.yml` and re-run.
