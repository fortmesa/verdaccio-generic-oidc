# Keycloak

For the generic mechanism (claim shapes, `roles.allowList`, how groups feed
Verdaccio's `packages:` access control, storage backends), see
[configuration.md](configuration.md) -- this doc only covers what's actually
specific to Keycloak. The exact realm here is checked in and tested live in
[`packages/server/keycloak/realm-export.json`](../packages/server/keycloak/realm-export.json),
brought up via `docker compose up` in `packages/server/` -- a working reference
if you want to compare against something real.

## 1. Create a client

In your realm: **Clients -> Create client**.

- Client type: `OpenID Connect`
- Client ID: this becomes the literal key in the
  `resource_access.<clientId>.roles` claim shape below and, by extension, the
  literal group name this plugin extracts -- so name it for what it's used for
  (e.g. `oauthClientIdName` in this doc's examples is a deliberately
  self-documenting placeholder, not a value you should type verbatim; pick your
  own real client ID and use it consistently everywhere below).
- Client authentication: **On** (confidential client) -- or **Off** for a public
  client, if you'd rather skip provisioning a secret and use PKCE instead (see
  [configuration.md](configuration.md), "Client authentication"). If you go the
  public-client route, also set **Advanced -> Proof Key for Code Exchange Code
  Challenge Method** to `S256`, so the client can't silently fall back to no
  protection at all.
- Valid redirect URIs: `<publicUrl>/-/oidc/callback`

If you left client authentication **On**, copy the client secret from the
**Credentials** tab and set it as `clientSecret`; otherwise omit `clientSecret`
entirely from your config.

## 2. The Keycloak-specific gotcha: role claims default to the access token, not the ID token

This cost real debugging time while building this fork, and it's specific to
Keycloak's default mapper configuration -- worth being explicit about.
Keycloak's built-in "realm roles" and "client roles" protocol mappers ship with
**"Add to ID token" turned off by default**. This plugin only ever reads ID
token claims, never the access token -- so with a fresh, default Keycloak
client, `roles.claim` will look like it's silently not working: the claim just
won't be there.

Fix, per mapper (there are two -- do both):

**Client scopes -> `roles` -> Mappers -> `realm roles`** and **Client scopes ->
`roles` -> Mappers -> `client roles`**:

- Open each mapper
- Toggle **Add to ID token** to **On**
- Save

Confirm it worked by decoding an `id_token` (e.g. via jwt.io) after logging in
-- you should see `realm_access.roles` and `resource_access.<clientId>.roles`
populated.

## 3. Keycloak's two role shapes

Keycloak gives you two independent claim shapes once the mappers above are
enabled -- see [configuration.md](configuration.md) for what `roles.claim`/
`roles.mapKey`/`roles.allowList` actually do with them:

- **Realm roles** (`realm_access.roles`) -- a flat array, assigned realm-wide.
- **Client roles** (`resource_access.<clientId>.roles`) -- a map of client ID to
  an object holding a `roles` array, letting you scope permissions per-client
  rather than realm-wide.

```yaml
# realm-wide roles
roles:
  claim: realm_access.roles

# OR per-client roles
roles:
  claim: resource_access
  allowList:
    oauthClientIdName: [admin, write]
```

## 4. Full example

```yaml
auth:
  '@fortmesa/verdaccio-generic-oidc':
    publicUrl: https://npm.example.com
    issuer: https://keycloak.example.com/realms/myrealm
    clientId: oauthClientIdName
    clientSecret: '...'
    scope: 'openid profile email'
    usernameClaim: preferred_username

    roles:
      claim: resource_access
      allowList:
        oauthClientIdName: [admin, write]

    dynamo:
      tableName: verdaccio-locks
      sortKeyValue: 'OIDC'

packages:
  '@myorg/*':
    access: $authenticated
    publish: oauthClientIdName
  '**':
    access: $authenticated
    publish: $authenticated
```

The example above uses a confidential client (`clientSecret` set). To use a
public client with PKCE instead, drop `clientSecret` and flip the two Keycloak
client settings from step 1 (client authentication off, PKCE method `S256`) --
both flows have been tested against this exact realm.

## Local testing

```bash
cd packages/server
docker compose up
./keycloak/bootstrap-test-user.sh
```

Logs in as `alice` / `alicepw`, holding the `npm-publish` realm role and the
`admin` client role on the `oauthClientIdName` client -- enough to exercise both
claim shapes above without configuring anything by hand. By default the realm's
`oauthClientIdName` client is confidential (matches the example above); to try
the PKCE path, flip it to public in the Keycloak admin console (or via the admin
REST API) and remove `clientSecret` from `config.yaml`.
