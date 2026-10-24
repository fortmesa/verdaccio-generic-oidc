# Google Workspace

For the generic mechanism (claim shapes, `roles.allowList`, how groups feed
Verdaccio's `packages:` access control, storage backends), see
[configuration.md](configuration.md) -- this doc only covers what's actually
specific to Google.

## 1. Create OAuth credentials

In [Google Cloud Console](https://console.cloud.google.com/apis/credentials):

1. Configure the **OAuth consent screen** (Internal, if you only want your
   Workspace domain to be able to log in at all -- see the domain- restriction
   note below).
2. **Create Credentials -> OAuth client ID**, application type **Web
   application**.
3. Add an authorized redirect URI: `<publicUrl>/-/oidc/callback`.
4. Copy the generated Client ID and Client Secret.

Google does accept PKCE parameters on a **Web application** client (it's not
rejected), but PKCE doesn't let you drop the secret the way it does on
Keycloak/Auth0/Okta/Authentik: Google requires `client_secret` on every token
exchange for this client type regardless. Per a Google identity team member,
"Google's Identity Platform ... does not support public applications under the
'Web Application' profile. Flows always require a client_secret." So for this
plugin's purposes (see [configuration.md](configuration.md), "Client
authentication"), `clientSecret` is effectively not optional for Google --
omitting it will fail at the token endpoint, not at plugin startup.

## 2. Google-specific config

```yaml
auth:
  '@fortmesa/verdaccio-generic-oidc':
    publicUrl: https://npm.example.com
    issuer: https://accounts.google.com
    clientId: 'your-client-id.apps.googleusercontent.com'
    clientSecret: '...'
    scope: 'openid email profile'
    # Google's ID token has no `preferred_username` claim (the plugin's
    # default) -- use `email` instead, or usernameClaim resolution will
    # throw "Missing username claim 'preferred_username'" on every login.
    usernameClaim: email
    # Only verified accounts on your Workspace domain get a token, whatever
    # the OAuth consent screen allows. See "Restricting who can log in" in
    # configuration.md.
    requiredClaims:
      hd: example.com
      email_verified: true

    filesystem:
      tokenPath: /var/lib/verdaccio/oidc-tokens
```

## 3. Google-specific limitation: there is no real "groups" claim

Worth being upfront about, since it's a real gap rather than a configuration
detail -- unlike Keycloak or Entra ID, Google's ID token does not include
Workspace/Cloud Identity group membership at all. Getting real group membership
requires a separate call to the
[Admin SDK Directory API](https://developers.google.com/admin-sdk/directory/reference/rest/v1/groups/list)
using a service account with domain-wide delegation -- a materially bigger
integration than reading a claim off the token, and out of scope for this plugin
as it stands today.

### What you get instead: domain restriction via `hd`

Workspace (not personal `@gmail.com`) accounts carry an `hd` claim -- the
"hosted domain" the account belongs to. Per the generic mechanism in
[configuration.md](configuration.md), you can turn this into a single coarse
group:

```yaml
usernameClaim: email
roles:
  claim: hd
```

A user authenticating with `alice@example.com` (a Workspace account on the
`example.com` domain) extracts a single group literally named `example.com`,
usable directly in `packages:`:

```yaml
packages:
  '**':
    access: example.com
    publish: example.com
```

This restricts access to your Workspace domain -- it is not per-user or per-team
authorization, just "is this a real account on our domain." Personal Google
accounts have no `hd` claim at all, so they extract no groups and fail this
check by default. They can still log in and get `$authenticated`, though, unless
`requiredClaims` (in the config above) turns them away at login. For real
group-based access control with Google, layer the Admin SDK integration
mentioned above on top of (not instead of) this plugin.
