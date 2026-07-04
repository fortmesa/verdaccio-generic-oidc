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

    # exactly one of these three storage backends:
    redis:
      url: redis
    # filesystem:
    #   sessionPath: /tmp
    #   tokenPath: /tmp
    # dynamo:
    #   tableName: my-table
```

One more top-level option not shown above: `accessTokenAuth` (boolean, default
`false`). Set it to `true` to disable the interactive `/-/v1/login` (npm/yarn
web-login) flow entirely, leaving only the token-exchange endpoint
(`PUT /-/user/org.couchdb.user::userId`, for exchanging an already-obtained
access token for an npm session) available.

`issuer` must point at a real OIDC discovery document
(`<issuer>/.well-known/openid-configuration`) -- this plugin uses
standards-based discovery, not a hand-configured set of endpoints, so anything
that publishes that document works without any provider-specific code.

## Client authentication: secret vs PKCE

`clientSecret` is optional. If it's set, the plugin authenticates as a
traditional confidential client (`client_secret_basic`). If it's left out
entirely, the plugin instead registers as a public client and uses PKCE (RFC
7636, `S256`) to protect the authorization code exchange -- the `code_verifier`
is generated and held server-side (keyed by the login request, in whichever
storage backend you've configured) and never leaves the server, so this is just
as secure as a client secret for this plugin's use case: the entire OAuth
exchange, including the callback, happens server-side, never in a browser.

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
| Filesystem | `filesystem.sessionPath` + `filesystem.tokenPath`                                                                   | Zero extra dependencies. Doesn't work across multiple replicas (each has its own filesystem).   |
| Redis      | `redis.url` (+ optionally `redis.keyPrefix`)                                                                        | Works across replicas. Requires `ioredis` installed (`peerDependencies`, not bundled).          |
| DynamoDB   | `dynamo.tableName` (+ optionally `dynamo.region`, `dynamo.keyPrefix`, `dynamo.sortKeyValue`, `dynamo.ttlAttribute`) | Works across replicas. Requires `@aws-sdk/client-dynamodb` + `@aws-sdk/lib-dynamodb` installed. |

### Session caching

`authenticate()` calls the session backend on _every_ authenticated npm/yarn
request (package fetches, publishes, `whoami` -- not just logins), so regardless
of which backend above you pick, that's a real, recurring Redis/DynamoDB
round-trip per request. The plugin wraps whichever backend is selected with a
bounded-staleness in-memory cache: `session.cacheTtl` (default 5 minutes / 300)
controls how long a session lookup is trusted locally before re-checking the
real backend. Set it to `0` to disable caching entirely. Each replica keeps its
own independent cache, so this trades up to `session.cacheTtl` of staleness
across replicas for a large reduction in backend load -- fine as long as nothing
needs to revoke a session sooner than its own natural expiry, which nothing in
this plugin does today.

## Login flow hardening

`/-/oidc/login`, `/-/oidc/callback`, and `/-/oidc/done` are all necessarily
unauthenticated -- that's the nature of a login flow -- which means their
`loginRequestId` (a URL path segment / the OAuth `state` parameter) is
attacker-controlled input by construction. Without any protection, that id is
used directly as a Redis/DynamoDB key, letting anyone force a real backend
round-trip (or, for Redis's blocking read, hold a pooled connection for up to 10
seconds) per garbage request.

The plugin closes this by signing every `loginRequestId` it issues (HMAC, keyed
by the same instance `secret` already used to sign npm/web JWTs) and verifying
the signature -- plus a 10-minute age limit and a 100-use budget per id --
before any of those three routes touch storage.

That budget only bounds abuse of a _single_ id, though. It does nothing against
an attacker who mints many ids: `/-/v1/login` (the endpoint that issues them) is
necessarily open to anyone and doesn't itself touch storage -- just `nanoid()` +
an HMAC computation, both cheap local CPU -- so nothing stops minting an
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
