# Why `/-/v1/login` polls `doneUrl`, and why "real" CLI-side PKCE isn't

# available through `npm login`/`yarn npm login`

This document explains a question that comes up when reading
`POST /-/v1/login`'s implementation (`packages/server/src/index.ts`): why does
finishing a login require the CLI to poll a `doneUrl`, instead of the CLI doing
a standard OAuth PKCE exchange directly against the identity provider? Short
answer: npm invented its own, non-standard login protocol for
`npm login`/`npm publish` rather than adopting either of the two
already-standardized patterns the rest of the industry uses for CLI OAuth, and
this project has to speak whatever protocol the real `npm`/Yarn clients actually
implement -- that's not a choice available to a Verdaccio plugin.

## What `/-/v1/login` actually is

`POST /-/v1/login` -> `{loginUrl, doneUrl}` -> open `loginUrl` in a browser ->
poll `doneUrl` until it returns a token. This is npm's own invention, not a
general OAuth mechanism the CLI participates in. Confirmed directly against the
real, installed client source
(`@yarnpkg/plugin-npm-cli/lib/commands/npm/login.js`): the CLI's
`webLoginInit`/`loginViaWeb`/`webLoginCheck` functions unconditionally expect
exactly this `{loginUrl, doneUrl}` shape back from the POST, and unconditionally
enter a poll loop afterward (202 = keep waiting, honoring `Retry-After`; 200 =
done, extract `body.token`). There is no code path in the real client that
accepts a token directly from the initial POST. This is npm/Yarn's own
client-side behavior -- not a Verdaccio-side or plugin-side decision, and not
something this project can change by altering its own server implementation.

The actual OAuth exchange -- the one that _does_ use PKCE -- happens entirely
between this **server** and the real identity provider (Google, Keycloak, Azure
Entra ID, ...), via `/-/oidc/login/:loginRequestId` (the redirect into the IdP)
and `/-/oidc/callback` (the code exchange back). The npm/Yarn **CLI itself never
touches PKCE, never sees an authorization code, and never talks to the IdP at
all** -- it only ever speaks npm's own POST-then-poll protocol to this server.
"PKCE" in this codebase protects the _registry's_ own public-client OAuth
exchange with the IdP; it isn't, and structurally can't be, something the end
user's CLI process participates in through this entry point.

## Why polling exists at all

`POST /-/v1/login` has to return _before_ the actual login happens -- a human
still has to click through a real login page at the IdP, which is inherently
asynchronous and can take an arbitrary amount of time. That browser interaction
lands on a _different_ HTTP request (`/-/oidc/callback`) than the one the CLI is
holding open, so the server needs some way to correlate "the CLI's still-pending
request" with "the browser eventually finishing" -- `loginRequestId`, embedded
in both `loginUrl` and `doneUrl`, is that correlation key, and polling `doneUrl`
is how the CLI finds out the correlation resolved. Holding the _original_ POST
open instead (a long-poll) doesn't remove this problem, it just moves where the
waiting happens, and is worse in practice (proxy/load-balancer timeouts, one
held request-handler per pending login) -- and still wouldn't match what the
real client code above does with the response regardless.

## The rest of the industry solved this differently, years earlier

By the time npm added web-based login, there were already two well-established,
standardized ways to do CLI-driven OAuth without inventing a bespoke polling
protocol:

- **OAuth 2.0 Device Authorization Grant (RFC 8628)**: the CLI requests a
  `device_code`/`user_code` from the IdP's own standard device-authorization
  endpoint, shows the user a code and a verification URL, and polls the **IdP's
  own token endpoint** directly (interval and expiry dictated by the standard
  itself, not invented per-server) until the user finishes. Still polling, but
  against a standard endpoint on the identity provider itself, not a bespoke
  endpoint on a third-party relay. This is what `aws sso login` uses, and what
  GitHub CLI/Docker CLI use for their own browser-based logins.
- **OAuth for Native Apps + PKCE with a local loopback listener (RFC 8252)**:
  the CLI spins up its own HTTP listener on `127.0.0.1:<random-port>`, builds
  the authorization URL with that as the `redirect_uri` and its own PKCE
  `code_challenge`, opens it in the browser, and receives the callback
  _directly_ on its own local server the instant the human finishes -- no
  polling anywhere, the callback itself is the completion signal.
  `gcloud auth login` uses this pattern.

**Timeline, confirmed directly:**

|                                   | Date                                                                                                                                                            | Mechanism                                        |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| AWS CLI v2 SSO (`aws sso login`)  | preview [Nov 2019](https://aws.amazon.com/blogs/developer/aws-cli-v2-now-supports-aws-single-sign-on/), GA Feb 2020                                             | OAuth Device Authorization Grant (RFC 8628)      |
| npm web-login (`--auth-type=web`) | opt-in in npm 8.15.0, [Jul 2022](https://github.blog/changelog/2022-09-19-web-based-authentication-now-works-for-all-npm-commands/); default in npm 9, Oct 2022 | npm's own bespoke POST + poll `doneUrl` protocol |

npm's design shipped roughly **2.5-3 years after** AWS's CLI SSO went GA using a
standardized grant type -- by which point both RFC 8628 (device grant) and RFC
8252 (native-app PKCE) were already established, production-proven patterns
elsewhere in the industry. npm adopted neither; it designed its own protocol
instead, and that protocol -- not this project's own architecture -- is what
makes `doneUrl` polling mandatory for anything going through
`npm login`/`yarn npm login --web-login`.

## What this means in practice for this project

- **This project cannot unilaterally add "real" CLI-side PKCE (or a proper
  device grant) to `npm login`/`yarn npm login`.** Doing so would require
  changing npm-cli's and Yarn Berry's own client-side source code, which are
  upstream projects this plugin has no control over. As long as the entry point
  is the standard `npm login`/`yarn npm login --web-login` commands as they
  actually exist today, `/-/v1/login` + `doneUrl` polling is the only protocol
  available to implement against.
- **A project-owned companion tool is not bound by that constraint.** A separate
  CLI (the same idea `npx verdaccio-openid` already represents -- see the
  comment in `packages/server/src/index.ts` on the classic
  `PUT /-/user/org.couchdb.user::userId` handler) could implement RFC 8252 or
  RFC 8628 properly, since it isn't required to speak npm's own invented
  protocol at all. That would give a genuinely better experience than either
  today's polling-based `npm login --auth-type=web` or the
  paste-a-token-manually fallback -- but it's a separate tool with its own login
  UX, not an enhancement to the existing `/-/v1/login` route.
