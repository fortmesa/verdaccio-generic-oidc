# Azure Entra ID (formerly Azure AD)

For the generic mechanism (claim shapes, `roles.allowList`, how groups feed
Verdaccio's `packages:` access control, storage backends), see
[configuration.md](configuration.md) -- this doc only covers what's actually
specific to Entra ID. Unlike the Google and Keycloak docs, this one hasn't been
exercised against a live tenant while building this fork -- the shapes below
match Microsoft's own documented behavior, but verify against a real token
(decode it at jwt.io) before relying on it, the same way the Keycloak doc's "Add
to ID token" gotcha was only found by actually looking at a real token.

## 1. App registration

**Entra ID -> App registrations -> New registration.**

- Redirect URI: platform **Web**, value `<publicUrl>/-/oidc/callback`.
- After creation, note the **Application (client) ID** and **Directory (tenant)
  ID**.
- **Certificates & secrets -> New client secret** -- copy the secret **value**
  immediately; it's only shown once. Unlike Google or Keycloak client secrets,
  this one has an **expiration date** you choose at creation (max often 24
  months) -- put a rotation reminder somewhere, this will silently break login
  otherwise.

A redirect URI registered under the **Web** platform (as above) is treated by
Entra ID as a confidential client and expects a secret. Skipping `clientSecret`
for PKCE-only auth (see [configuration.md](configuration.md)) likely requires
registering the redirect URI under a different platform type instead (e.g.
"Mobile and desktop applications" / "Single-page application", with "Allow
public client flows" enabled) -- unverified here, same caveat as the rest of
this doc: confirm against a real tenant before relying on it.

## 2. Issuer

For a single tenant (the normal case for a private registry -- you don't want
every Microsoft account on earth to be able to log in):

```yaml
issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
```

## 3. Roles: two options, pick App roles unless you have a reason not to

Entra ID gives you two independent ways to get authorization data into the
token, and they're not equivalent -- read both before choosing.

### Option A (recommended): App roles

**In the app registration -> App roles -> Create app role.** Set a display name
and a **Value** (e.g. `Admin`, `Publisher`) -- the _value_ is what ends up in
the token, not the display name. Allowed member types can be Users, Groups, or
both.

Then assign it: **Entra ID -> Enterprise applications -> (this app) -> Users and
groups -> Add user/group**, picking the app role to assign.

The token then carries a flat array at the top level:

```json
{"roles": ["Admin", "Publisher"]}
```

```yaml
roles:
  claim: roles
  allowList:
    Admin: []
    Publisher: []
```

This is Microsoft's own recommended pattern for authorization decisions
specifically because it sidesteps both problems Option B has below -- values are
meaningful strings you chose, not opaque IDs, and there's no group-count limit
to worry about.

### Option B: the `groups` claim

**App registration -> Token configuration -> Add groups claim.** Choose
**"Groups assigned to the application"** rather than "All groups" or "Security
groups" -- this avoids the overage problem below by only ever including groups
you've explicitly assigned to this specific app (**Enterprise applications ->
(this app) -> Users and groups**, same place as app role assignment).

Two real caveats, not just theoretical ones:

- **Values are opaque object IDs**, not group names
  (`"groups": ["8b8d33..." ]`), unless you do extra work (a Microsoft Graph
  lookup) to resolve them to display names. `roles.allowList` entries end up
  referencing GUIDs, which is stable but not something you can eyeball in a
  config file.
- **Overage**: if a user belongs to more than 200 groups (for this token type),
  Entra ID omits the `groups` claim entirely and replaces it with a
  `_claim_names`/`_claim_sources` indirection pointing at a Graph API call this
  plugin does not make. For anyone in a lot of groups, the claim may simply not
  be there. "Groups assigned to the application" (rather than all of a user's
  groups) makes this far less likely to bite, but it's not eliminated if the
  assigned set itself is large.

```yaml
roles:
  claim: groups
  allowList:
    '8b8d3300-0000-0000-0000-000000000000': [] # the actual object ID of your group
```

## 4. Username

Unlike Google, Entra ID's v2.0 token generally does populate
`preferred_username` -- the plugin's own default -- usually as the user's UPN or
email. You likely don't need to override `usernameClaim` at all, though
guest/B2B accounts are worth spot-checking since their claims can differ from
native tenant members.

## 5. Full example

```yaml
auth:
  '@fortmesa/verdaccio-generic-oidc':
    publicUrl: https://npm.example.com
    issuer: https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0
    clientId: '...'
    clientSecret: '...'
    scope: 'openid profile email'

    roles:
      claim: roles
      allowList:
        Admin: []
        Publisher: []

    redis:
      url: redis

packages:
  '@myorg/*':
    access: $authenticated
    publish: Publisher
  '**':
    access: $authenticated
    publish: $authenticated
```
