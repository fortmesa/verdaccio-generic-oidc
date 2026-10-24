# Configuration reference

This plugin is a generic OAuth2/OIDC client -- it works against any standards-
compliant provider (Google, Keycloak, Azure Entra ID, Okta, Auth0, AWS Cognito,
Authentik, ...). Nothing here is specific to any one of them; the
provider-specific docs ([Google Workspace](google-workspace.md),
[Keycloak](keycloak.md), [Azure Entra ID](azure-entra-id.md)) only cover the
handful of things that actually differ between providers -- creating a
client/app registration, and each provider's own claim names and quirks.
Everything below applies identically regardless of which one you point this at.

## Core config

```yaml
auth:
  '@fortmesa/verdaccio-generic-oidc':
    publicUrl: https://npm.example.com
    issuer: https://your-provider.example.com/...
    clientId: '...'
    clientSecret: '...'
    scope: 'openid profile email'
    usernameClaim: preferred_username # which ID token claim becomes the npm username

    # optional: claims an ID token must carry, see "Restricting who can log in"
    # requiredClaims:
    #   hd: example.com
    #   email_verified: true

    # exactly one of these three storage backends:
    redis:
      url: redis
    # filesystem:
    #   tokenPath: /var/lib/verdaccio/oidc-tokens
    # dynamo:
    #   tableName: my-table
```

One more top-level option not shown above: `accessTokenAuth` (boolean, default
`false`). Set it to `true` to disable the interactive `/-/v1/login` (npm/yarn
web-login) flow entirely, leaving only the token-exchange endpoint
(`PUT /-/user/org.couchdb.user::userId`, for exchanging an already-obtained
access token for an npm token) available.

The token-exchange endpoint only handles a password that is a JWT whose `iss` is
this plugin's issuer, and only while the issuer's discovery document lists
`urn:ietf:params:oauth:grant-type:token-exchange` in `grant_types_supported`.
Any other password, an htpasswd one included, goes on to Verdaccio's own
`npm login` route and its `userRateLimit`, and is never sent to the IdP.
Exchange attempts are limited per client address with the same `userRateLimit`
numbers (Verdaccio's default is 1000 per 15 minutes). Google lists no
token-exchange grant, so against Google this endpoint always defers to
Verdaccio.

`issuer` must point at a real OIDC discovery document
(`<issuer>/.well-known/openid-configuration`) -- this plugin uses
standards-based discovery, not a hand-configured set of endpoints, so anything
that publishes that document works without any provider-specific code.

## Client authentication: secret vs PKCE

`clientSecret` is optional. If it's set, the plugin authenticates as a
traditional confidential client (`client_secret_basic`). If it's left out
entirely, the plugin instead registers as a public client and uses PKCE (RFC
7636, `S256`) to protect the authorization code exchange. The `code_verifier` is
an HMAC of the login request id under the Verdaccio instance `secret`, so the
plugin can recompute it at the callback without storing it, and it never leaves
the server. That makes this as secure as a client secret for this plugin's use
case: the entire OAuth exchange, including the callback, happens server-side,
never in a browser.

Either way, every authorization request also carries a `nonce` derived the same
way, and the callback requires the ID token to echo it and requires an
authorization `code` (an ID token sent on its own is refused).

Whether you _can_ drop the secret depends on whether your provider lets you
register a public web client at all:

- **Keycloak, Auth0, Okta, Authentik**: yes -- toggle the client to "public"
  (Keycloak: turn off "Client authentication"; also worth explicitly requiring
  PKCE on the client, e.g. Keycloak's Advanced tab -> "Proof Key for Code
  Exchange Code Challenge Method" -> `S256`, so a misconfigured client can't
  silently fall back to no protection at all).
- **Google**: no -- Google accepts PKCE parameters on a "Web application"
  client, but that doesn't let you drop the secret the way it does on the
  providers above; a client_secret is required on every token exchange for this
  client type regardless. Only Google's Desktop/Android/iOS client types skip
  it, and none of those are usable here. See
  [google-workspace.md](google-workspace.md).
- **Azure Entra ID**: depends on the app registration's platform type -- see
  [azure-entra-id.md](azure-entra-id.md).

If you omit `clientSecret` against a provider that still requires one, you'll
see an authentication failure at the token endpoint (e.g. `invalid_client`)
rather than this plugin failing to start -- it can't know in advance whether a
given issuer accepts a secret-less client.

## Groups/roles: the part every provider does differently

This is the part that varies most between providers, and the part most worth
understanding generically before reading any provider-specific doc.

### The mechanism

1. `roles.claim` is a **dot-path** into the ID token's claims -- not just a
   top-level key. `roles`, `realm_access.roles`, and
   `resource_access.myapp.roles` are all valid.
2. Whatever that path resolves to gets normalized into a list of group names,
   handling every shape a real provider might produce:
   - a comma-separated string (`"team1,team2"`)
   - a flat array (`["team1", "team2"]`)
   - a map of name to a role array (`{team1: ["admin","write"], team2: []}`)
   - a map of name to an object holding a role array under some key, default
     `roles` (`{team1: {roles: ["admin"]}}`) -- override the key with
     `roles.mapKey` if your provider's claim uses a different one.
   - a map of name to `true` (`{team1: true}`)

   In a map, a key whose value is anything else (`false`, `null`, a number, a
   string, an object without the role key) is not a group.

3. Optionally, `roles.allowList` restricts which of those extracted names
   actually become groups:

   ```yaml
   roles:
     allowList:
       team1:
         [admin, write] # only include "team1" if the user's role for it
         # is admin or write
       team2: [] # include "team2" unconditionally if present
   # anything not listed here is dropped -- default-deny
   ```

   Also accepts a single string, for cases where injecting it via an environment
   variable is more convenient than a YAML block:
   `roles.allowList: "team1(admin|write),team2"`.

   Leave `roles.allowList` out entirely and every extracted name passes through
   unfiltered -- this is fully backward compatible with using just `roles.claim`
   on its own.

### How this feeds Verdaccio's `packages:` access control

This is the actual point of the whole mechanism, and it's worth being explicit
about since it's not automatic in any deeper sense than "these are plain strings
that get compared": every group name that comes out of the process above becomes
an entry in the authenticated user's group list, and Verdaccio's own `packages:`
config matches `access`/`publish` values against that list by exact string
equality. There's no additional plumbing -- the group name Verdaccio sees is the
extraction result, full stop.

```yaml
# say roles.claim + roles.allowList above extracted "team1" for this user
packages:
  '@myorg/*':
    access: team1
    publish: team1
  '**':
    access: $authenticated
    publish: $authenticated
```

A user whose token yields `team1` gets `access`/`publish` on `@myorg/*`; a user
who doesn't, falls through to whatever the next matching rule allows (here,
`$authenticated` on everything else, per Verdaccio's own first-match rules). You
can list as many group names as you extract, across as many `packages:` entries
as you need -- this plugin's job ends at producing the group list, standard
Verdaccio access control takes it from there.

## Restricting who can log in

By default every account your IdP authenticates for this client can log in. With
Verdaccio's usual `access: $authenticated`, that's read access to every package.
`requiredClaims` lists claims an ID token must carry before the plugin issues a
token:

```yaml
requiredClaims:
  hd: example.com # one allowed value
  email_verified: true
  groups: [npm-readers, npm-publishers] # any one of these
  realm_access.roles: npm # dot-paths work, as for roles.claim
```

Each key is a dot-path into the ID token's claims, and each value is the allowed
value or a list of allowed values. A claim passes when it equals one allowed
value, or, when the claim is an array, when any element does. Values compare
exactly: `true` and `"true"` are different, so list both for a provider that
sends the string. A login that fails any entry gets a 403 and no token, at the
callback and at the token-exchange endpoint alike. The plugin refuses to start
if an entry's value isn't a string, number, boolean, or non-empty list of them.

Which claims to require depends on the provider. For Google Workspace,
`hd: <your domain>` and `email_verified: true` keep out every account outside
the domain even when the OAuth consent screen is External. See
[google-workspace.md](google-workspace.md).

### What each provider actually gives you here

This varies a lot, which is why it's worth reading the specific provider doc
rather than assuming they're interchangeable:

- **Keycloak**: real roles, two independent flavors (realm-wide and per-client),
  off by default in the ID token until you flip a mapper setting. See
  [keycloak.md](keycloak.md).
- **Azure Entra ID**: real roles via "App roles" (the recommended approach, a
  flat `roles` claim) or raw group object IDs via the `groups` claim (has a
  200-group "overage" caveat). See [azure-entra-id.md](azure-entra-id.md).
- **Google**: no real groups claim at all. The best available signal is the `hd`
  (hosted domain) claim, usable as a coarse "is this account on our Workspace
  domain" check, not per-team/per-role authorization. See
  [google-workspace.md](google-workspace.md).
- **Okta / Auth0 / Cognito / Authentik / others**: not documented here yet, but
  the mechanism is the same -- check what claim your provider emits (often
  configurable, e.g. as a custom claim / scope mapping in the provider's own
  admin console) and point `roles.claim` at it.

## Storage backends

Exactly one of these three is required (the plugin throws at startup if none are
configured); which one you pick doesn't depend on your OIDC provider at all,
only on your deployment's own infrastructure:

| Backend    | Config                                                                                                              | Notes                                                                                           |
| ---------- | ------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Filesystem | `filesystem.tokenPath`                                                                                              | Zero extra dependencies. Doesn't work across multiple replicas (each has its own filesystem).   |
| Redis      | `redis.url` (+ optionally `redis.keyPrefix`)                                                                        | Works across replicas. Requires `ioredis` installed (`peerDependencies`, not bundled).          |
| DynamoDB   | `dynamo.tableName` (+ optionally `dynamo.region`, `dynamo.keyPrefix`, `dynamo.sortKeyValue`, `dynamo.ttlAttribute`) | Works across replicas. Requires `@aws-sdk/client-dynamodb` + `@aws-sdk/lib-dynamodb` installed. |

### What gets stored

Only one thing: the npm token a finished `npm login`/`yarn npm login` is waiting
for. The callback writes it, and the first `/-/oidc/done` poll that finds it
removes it as it reads it (Redis `MULTI GET DEL`, a DynamoDB conditional
`DeleteItem`, a filesystem `rename`), so it's handed out once. It expires when
the login request does, at most 10 minutes. Requests authenticated with a token
never touch storage; the token's signature and expiry are what's checked.

DynamoDB needs `GetItem`, `PutItem` and `DeleteItem` on the table. Redis needs
no connection pool: every command is non-blocking, and a waiting `/-/oidc/done`
polls. Filesystem token files are written mode `0600` and renamed into place.

`filesystem.sessionPath` and `session.cacheTtl` are no longer read; the plugin
logs a warning when either is set. Earlier versions kept the IdP's token set per
login and accepted the login's session id as a password. Nothing uses that now,
and a session id was readable from inside any token issued for it.

## Login flow hardening

`/-/oidc/login`, `/-/oidc/callback`, and `/-/oidc/done` are all necessarily
unauthenticated -- that's the nature of a login flow -- which means their
`loginRequestId` (a URL path segment / the OAuth `state` parameter) is
attacker-controlled input by construction. Without any protection, that id is
used directly as a Redis/DynamoDB key, letting anyone force a real backend
round-trip (and, for `/-/oidc/done`, up to 10 seconds of polling) per garbage
request.

The plugin closes this by signing every `loginRequestId` it issues (HMAC, keyed
by the same instance `secret` already used to sign npm/web JWTs) and verifying
the signature -- plus a 10-minute age limit and a 100-use budget per id --
before any of those three routes touch storage. An id has exactly one spelling
(lowercase hex MAC, no trailing characters), so it can't be re-spelled into many
ids with a fresh budget each.

Anyone can mint an id and send its `loginUrl` to someone else, so the flow also
checks who is on the other end:

- `loginUrl` shows a confirmation page and goes to the IdP only when the person
  clicks Continue. The form carries a value that must match a `SameSite=Strict`
  cookie the page set, so a page on another site can't submit it. The page sends
  `frame-ancestors 'none'` and `X-Frame-Options: DENY`, so it can't be framed.
- The callback only accepts the browser that started the login: going to the IdP
  sets a cookie holding an HMAC of the login request id, which the callback
  checks. A callback URL handed to someone else's browser is refused.
- `/-/oidc/done` hands the token out once.
- `/-/v1/login`, `loginUrl`, `/-/oidc/callback` and `/-/oidc/done` drop the
  `Access-Control-Allow-Origin: *` header Verdaccio adds to every response, so a
  web page can't run the flow from inside a visitor's browser.

`GET /-/oidc/start` (a person signing in to the web UI) skips the confirmation
page, since the person is already in the browser that gets the token, and stores
nothing for `/-/oidc/done`.

That budget only bounds abuse of a _single_ id, though. It does nothing against
an attacker who mints many ids: `/-/v1/login` (the endpoint that issues them) is
necessarily open to anyone and doesn't itself touch storage -- just random bytes
and an HMAC computation, both cheap local CPU -- so nothing stops minting an
unlimited number of fully legitimate, validly signed ids and cashing in the full
100-use budget against each one. N ids x 100 uses is still unbounded as N grows.
So `/-/v1/login` also enforces its own budget: at most 30 mints per source per
10-minute window, tracked in memory and keyed by `req.ip`. `GET /-/oidc/start`
(see [README.md](../packages/server/README.md), "Letting a human log into the
web UI directly" -- the other place a `loginRequestId` gets minted) shares this
same budget rather than getting its own, since both are just two entry points
into the identical mint operation. Together, the two bounds turn "unbounded"
into a small, fixed worst case (30 x 100 = 3000 backend-touching calls per
source per window) instead of an open-ended one.

`req.ip` reflects whatever trust-proxy configuration Verdaccio's own Express app
has (or hasn't) been given -- this plugin only adds routes to Verdaccio's
existing app, it doesn't configure that itself. If you run Verdaccio behind a
reverse proxy, verify `req.ip` actually resolves to real client addresses for
your deployment rather than the proxy's own address; otherwise every user behind
that proxy shares one mint budget. For request-volume abuse more broadly (not
just this one endpoint), rate limiting at the reverse proxy / load balancer in
front of Verdaccio (nginx `limit_req`, an ALB/WAF rule, Cloudflare, etc.) is
generally the better tool than anything this plugin could add internally -- it
has unambiguous IP visibility and dedicated tooling for exactly this problem.

None of the thresholds above are configurable -- this is internal hardening with
generous, fixed values sized around real login-flow behavior (a slow,
multi-minute human login, a client aggressively re-polling `/-/oidc/done`, a
handful of retried attempts from one person or one shared/NAT'd IP), not a
tunable surface.

## Yarn client integration

See [yarn-integration.md](yarn-integration.md) for the companion Yarn Berry
plugin that automatically drives the login flow instead of `yarn install` just
failing when no token is configured.
