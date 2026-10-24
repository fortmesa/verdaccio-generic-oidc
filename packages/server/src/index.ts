import type {pluginUtils} from '@verdaccio/core';
import type {
  Config,
  JWTSignOptions,
  Logger,
  RemoteUser,
} from '@verdaccio/types';
import {Issuer, Client, TokenSet, generators} from 'openid-client';
import * as bodyParser from 'body-parser';
import type {Express, NextFunction, Request, Response} from 'express';
import * as jwt from 'jsonwebtoken';
import {randomBytes, timingSafeEqual} from 'crypto';
import {setTimeout as sleep} from 'timers/promises';
import {URL} from 'url';

import {ITokenStorage} from './types';
import type {
  NewRedisStorage as NewRedisStorageType,
  RedisStorageConfig,
} from './redis';
import {NewFileStorage} from './fs';
import type {
  NewDynamoStorage as NewDynamoStorageType,
  DynamoStorageConfig,
} from './dynamo';
import {extractGroups, getByPath, RolesAllowList} from './groups';
import {
  signLoginRequestId,
  verifyAndConsumeLoginRequestId,
  checkAndConsumeMintBudget,
  createSourceBudget,
  loginRequestSecret,
  MAX_AGE_SEC,
} from './loginRequestId';

type ClaimValue = string | number | boolean;

type PluginOptions = pluginUtils.PluginOptions;
type AuthCallback = pluginUtils.AuthCallback;
// What Verdaccio passes as `auth`: its Auth instance, whose config (and the
// instance secret in it) the IBasicAuth type leaves out.
type VerdaccioAuth = pluginUtils.IBasicAuth & {config: Config};

type OidcPluginConfig = {
  publicUrl: string;
  issuer: string;
  clientId: string;
  // When unset, the client is treated as public and authenticates with PKCE
  // (RFC 7636) instead of a client secret. Not every provider supports a
  // secret-less "public" web client -- see docs/configuration.md.
  clientSecret?: string;
  scope: string;
  usernameClaim?: string;
  roles?: {
    claim?: string;
    mapKey?: string;
    allowList?: string | RolesAllowList;
  };
  // Claims an ID token must carry before a login is accepted: each key is a
  // dot-path into the claims, each value the allowed value or a list of
  // them. See docs/configuration.md, "Restricting who can log in".
  requiredClaims?: Record<string, ClaimValue | ClaimValue[]>;

  // Exactly one of these three is required -- see docs/configuration.md,
  // "Storage backends".
  redis?: RedisStorageConfig;
  // sessionPath is no longer read; only tokenPath is.
  filesystem?: {sessionPath?: string; tokenPath: string};
  dynamo?: DynamoStorageConfig;

  // No longer read: there is no session store to cache.
  session?: {cacheTtl?: number};

  accessTokenAuth?: boolean;

  oidcPluginInstance: OidcPlugin;
};

type Tokens = {
  npmToken: string;
  webToken: string;
};

// A generated token's key, as Verdaccio's own `npm token create` writes it
// into the JWT and its router reads it from req.remote_user.
type RemoteUserEx = RemoteUser & {token?: {key: string}};

const TOKEN_BEARER = 'Bearer';
const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';

// Verdaccio's own defaults for its rate-limited user routes
// (@verdaccio/config's defaultUserRateLimiting), used for token exchange
// attempts when the deployment sets no userRateLimit of its own.
const DEFAULT_USER_RATE_LIMIT = {windowMs: 15 * 60 * 1000, max: 1000};

// Neither Verdaccio's default `security` nor every deployment sets
// api.jwt.sign.expiresIn, and jsonwebtoken rejects an undefined one.
const DEFAULT_TOKEN_EXPIRES_IN = '7d';

// Tokens are minted on one replica and checked on another; this absorbs
// clock skew between them unless security.api.jwt.verify sets its own.
const DEFAULT_CLOCK_TOLERANCE_SEC = 30;

// Must match this package's name: Verdaccio's plugin loader resolves a scoped
// package name verbatim as the config key (no `verdaccio-` prefix mangling),
// and both the `auth:` and `middlewares:` sections need to agree on this key
// for the constructor's self-referencing instance-sharing trick below to work.
const PLUGIN_CONFIG_KEY = '@fortmesa/verdaccio-generic-oidc';

export default class OidcPlugin
  implements
    Pick<pluginUtils.Auth<OidcPluginConfig>, 'authenticate'>,
    Pick<
      pluginUtils.ExpressMiddleware<OidcPluginConfig, unknown, VerdaccioAuth>,
      'register_middlewares'
    >
{
  private readonly pluginName = PLUGIN_CONFIG_KEY;

  private config: OidcPluginConfig;
  private options: PluginOptions;
  private clientPromise!: Promise<Client>;
  // Set once discovery succeeds, so a route that must not wait on a
  // discovery still being retried (PUT /-/user) can check it directly.
  private client?: Client;
  private closed = false;
  private logger!: Logger;
  private ts!: ITokenStorage;
  private usePkce!: boolean;
  private requiredClaims!: Array<[string, ClaimValue[]]>;
  private exchangeBudget!: {take(source: string): boolean};
  // Captured from register_middlewares() below -- apiJWTmiddleware(helpers)
  // only receives the narrow {createAnonymousRemoteUser, createRemoteUser}
  // helpers, not this. Needed to delegate Basic-Auth-scheme requests (e.g.
  // htpasswd, or a static CI credential) to the *real*, multi-plugin auth
  // chain.
  private authChain?: VerdaccioAuth;

  constructor(config: OidcPluginConfig, appOptions: PluginOptions) {
    this.config = config;
    this.options = appOptions;
    // The middleware-role instance is constructed with the config section
    // set below, so the auth-role instance is right there in it.
    if (this.config.oidcPluginInstance != null) {
      return this.config.oidcPluginInstance;
    }

    this.options.config.middlewares = {
      ...appOptions.config.middlewares,
      [PLUGIN_CONFIG_KEY]: {oidcPluginInstance: this},
    };
    this.logger = appOptions.logger;

    this.logger.trace(
      {pluginName: this.pluginName},
      '@{pluginName} in jwt mode',
    );
    this.apiJWTmiddleware = this._apiJWTmiddleware;
    this.requiredClaims = normalizeRequiredClaims(this.config.requiredClaims);

    const userRateLimit = {
      ...DEFAULT_USER_RATE_LIMIT,
      ...(this.options.config as {userRateLimit?: object}).userRateLimit,
    } as {windowMs: number; max: number};
    this.exchangeBudget = createSourceBudget(
      userRateLimit.max,
      Math.ceil(userRateLimit.windowMs / 1000),
    );

    if (this.config.redis?.url) {
      // ioredis is an optional peer dependency -- only require() it when
      // actually selected, so filesystem/DynamoDB-only installs never need
      // it on disk.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const {NewRedisStorage} = require('./redis') as {
        NewRedisStorage: typeof NewRedisStorageType;
      };
      this.ts = NewRedisStorage(this.config.redis).ts;
    } else if (this.config.filesystem?.tokenPath) {
      this.ts = NewFileStorage(
        this.logger,
        this.config.filesystem.tokenPath,
      ).ts;
    } else if (this.config.dynamo?.tableName) {
      // @aws-sdk/* is an optional peer dependency -- same reasoning as above.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const {NewDynamoStorage} = require('./dynamo') as {
        NewDynamoStorage: typeof NewDynamoStorageType;
      };
      this.ts = NewDynamoStorage(this.config.dynamo).ts;
    } else {
      throw new Error(
        'invalid configuration: none of [redis.url], [filesystem.tokenPath], or [dynamo.tableName] is set',
      );
    }
    if (this.config.filesystem?.sessionPath != null) {
      this.logger.warn({}, 'filesystem.sessionPath is no longer used');
    }
    if (this.config.session != null) {
      this.logger.warn({}, 'session.cacheTtl is no longer used');
    }

    const clientSecret =
      process.env.OIDC_CLIENT_SECRET || this.config.clientSecret;
    this.usePkce = !clientSecret;

    this.clientPromise = this.discoverIssuer().then(issuer => {
      const client = new issuer.Client({
        client_id: process.env.OIDC_CLIENT_ID || this.config.clientId,
        // No secret configured -> public client, authenticated via PKCE
        // (see the /-/oidc/login and /-/oidc/callback handlers) instead.
        ...(clientSecret
          ? {client_secret: clientSecret}
          : {token_endpoint_auth_method: 'none'}),
        redirect_uris: [
          new URL('-/oidc/callback', this.config.publicUrl).toString(),
        ],
        response_types: ['code'],
      });
      this.client = client;
      return client;
    });
    // Rejects only after close(); every route that awaits it has its own
    // handler, so don't let it surface as an unhandled rejection.
    this.clientPromise.catch(() => undefined);
  }

  // Retries until it succeeds or close() is called, waiting 1s, 2s, 4s and
  // so on between attempts, capped at 30s.
  private async discoverIssuer(): Promise<Issuer> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await Issuer.discover(this.config.issuer);
      } catch (err) {
        if (this.closed) throw err;
        this.logger.warn(
          {err, attempt},
          'Failed to discover issuer, retrying [@{attempt}]: @{!err.message}\n@{err.stack}',
        );
        await sleep(Math.min(1000 * 2 ** (attempt - 1), 30_000), undefined, {
          ref: false,
        });
      }
    }
  }

  public close() {
    const plugin = this.getInstance();
    if (plugin.closed) {
      return;
    }

    plugin.closed = true;
    plugin.ts.close();
  }

  private getInstance(): OidcPlugin {
    if ('oidcPluginInstance' in this.config) {
      return this.config.oidcPluginInstance;
    } else if ('clientPromise' in this) {
      return this;
    } else {
      throw new Error(
        `Unable to find plugin instance. This = ${JSON.stringify(this)}`,
      );
    }
  }

  private getUsername(tokenSet: TokenSet): string {
    const plugin = this.getInstance();

    const {usernameClaim = 'preferred_username'} = plugin.config;
    const username = tokenSet.claims()[usernameClaim];

    if (typeof username !== 'string') {
      throw new Error(
        `Missing username claim '${usernameClaim}'. Available claims: ${JSON.stringify(
          Object.keys(tokenSet.claims()),
        )}`,
      );
    }
    return username;
  }

  private getRoles(tokenSet: TokenSet): string[] {
    const plugin = this.getInstance();
    return extractGroups(tokenSet.claims(), plugin.config, plugin.logger);
  }

  // The first requiredClaims entry the token doesn't satisfy, or null. A
  // claim satisfies an entry when it equals one allowed value, or, for an
  // array claim, when any element does. Values compare with ===, so `true`
  // and "true" are different.
  private unmetRequiredClaim(tokenSet: TokenSet): string | null {
    const plugin = this.getInstance();
    const claims = tokenSet.claims() as Record<string, unknown>;
    for (const [claimPath, allowed] of plugin.requiredClaims) {
      const actual = getByPath(claims, claimPath);
      const values = Array.isArray(actual) ? actual : [actual];
      if (!values.some(value => allowed.includes(value as ClaimValue))) {
        return claimPath;
      }
    }
    return null;
  }

  // Every login this plugin performs ends in a signed npm or web token that
  // apiJWTmiddleware() checks, so nothing it issues is a password. Declining
  // passes the credentials on to the next auth plugin in Verdaccio's chain
  // (htpasswd, for one), which is what checks a Basic credential or an
  // `npm login` password.
  public authenticate(
    _user: string,
    _password: string,
    cb: AuthCallback,
  ): void {
    cb(null, false);
  }

  public apiJWTmiddleware?: (helpers: any) => any;

  private _apiJWTmiddleware(helpers: any): any {
    const plugin = this.getInstance();

    return (
      req: Request & {remote_user: RemoteUserEx},
      res: Response,
      _next: NextFunction,
    ) => {
      // The Bearer path below is deliberately synchronous end-to-end: an
      // async gap there (even a same-tick microtask, e.g. a storage
      // lookup) corrupts Verdaccio's own nested web-UI router dispatch for
      // this request -- reproduced directly against real Verdaccio +
      // Express -- so it must never await anything before calling next().
      const next = function (err?: Error) {
        // swallow error, user remains unauthorized
        // set remoteUserError to indicate that user was attempting authentication

        if (err) {
          req.remote_user.error = err.message;
        }

        return _next();
      };

      if (req.remote_user?.name) {
        return next();
      }

      req.remote_user = helpers.createAnonymousRemoteUser();
      res.locals.remote_user = req.remote_user;

      const {authorization} = req.headers;
      if (!authorization) {
        // looks like this is anonymous query - pass req to verdaccio core
        return next();
      }

      const authorizationParts = authorization.split(' ', 2);
      if (authorizationParts.length !== 2) {
        // Never log the header itself: without a space it's the bare
        // credential.
        plugin.logger.warn({}, 'malformed authorization header');
        return next(new Error('malformed authorization header'));
      }

      if (authorizationParts[0] !== TOKEN_BEARER) {
        // Not one of our own bearer tokens -- e.g. htpasswd, or a static
        // Basic-Auth credential (a CI build's own ident). This plugin
        // replaces Verdaccio's own apiJWTmiddleware entirely (Verdaccio only
        // calls a plugin-provided one, never both), so without this, no
        // sibling auth plugin configured alongside this one -- htpasswd
        // included -- could ever authenticate anything: confirmed directly,
        // removing this plugin restored htpasswd's Basic-Auth login.
        // Delegating here is what makes every configured auth plugin
        // reachable, not just this one -- exactly the "htpasswd fallback"
        // the config already assumes.
        if (!plugin.authChain) {
          plugin.logger.error(
            {},
            'authChain not set -- register_middlewares() must run before apiJWTmiddleware() handles a request',
          );
          return next(new Error('authentication is not ready'));
        }
        const credentials = parseBasicCredentials(authorizationParts[1]);
        if (!credentials) {
          return next(new Error('malformed basic credentials'));
        }
        // The auth chain is async (htpasswd's bcrypt, for one), and
        // Verdaccio's access log has already started reading the request
        // with req.on('data'). Pausing, as Verdaccio's own middleware does,
        // keeps a request body from streaming past before any parser is
        // attached (verdaccio/verdaccio#1912).
        req.pause();
        plugin.authChain.authenticate(
          credentials.user,
          credentials.password,
          (err: Error | null, authenticatedUser: RemoteUserEx | false) => {
            req.resume();
            if (err) {
              return next(err);
            }
            if (authenticatedUser) {
              req.remote_user = credentials.tokenKey
                ? {...authenticatedUser, token: {key: credentials.tokenKey}}
                : authenticatedUser;
            }
            next();
          },
        );
        return;
      }

      const jwtRaw = authorizationParts[1];
      let jwtPayload: unknown = undefined;

      // signPayload() below never sets an `iss` claim on a token this plugin
      // itself issues -- only a foreign token (e.g. a CI provider's OIDC
      // token, meant for a completely different auth plugin like
      // verdaccio-oidc-auth) would have one. Decoding first (no signature
      // check, cannot throw -- jwt.decode() returns null on anything
      // malformed) and skipping straight past anything with an `iss` avoids
      // logging a guaranteed, expected verification failure as an @{error}
      // -- error-level logging exists to flag a real problem to resolve,
      // not routine traffic this plugin was never going to authenticate in
      // the first place. A real failure to verify one of *this plugin's
      // own* tokens (expired, tampered, wrong secret) still logs at error
      // below, since that case is actually worth investigating.
      const decoded = jwt.decode(jwtRaw) as {iss?: string} | null;
      if (decoded?.iss) {
        plugin.logger.debug(
          {iss: decoded.iss},
          'bearer token has issuer @{iss} -- not one of ours, skipping',
        );
        return next();
      }

      try {
        jwtPayload = jwt.verify(jwtRaw, plugin.options.config.secret, {
          clockTolerance: DEFAULT_CLOCK_TOLERANCE_SEC,
          ...plugin.options.config.security?.api?.jwt?.verify,
        });
      } catch (err) {
        plugin.logger.error(
          {err},
          'error while verifying jwt bearer token: @{!err.message}\n@{err.stack}',
        );
      }

      if (!jwtPayload) {
        return next(new Error('unable to verify jwt bearer token'));
      }

      const {name, real_groups, token} = jwtPayload as RemoteUser & {
        token?: {key?: unknown};
      };
      if (!name) {
        plugin.logger.error(
          {},
          'incoming jwt token does not contain [name] claim',
        );
        return next(new Error('jwt token does not contain name'));
      }
      if (!real_groups) {
        plugin.logger.error(
          {},
          'incoming jwt token does not contain [real_groups] claim',
        );
        return next(new Error('jwt token does not contain real_groups'));
      }

      // jwt.verify() above already confirms this exact payload was signed by
      // this registry and has not expired (its own `exp` claim), which is
      // what's trusted. A token from `npm token create` also carries
      // token.key: Verdaccio's router looks the token's read-only/CIDR
      // settings and revocation up under it, so it has to survive here as it
      // does in Verdaccio's own middleware.
      const remoteUser = helpers.createRemoteUser(name, real_groups);
      req.remote_user =
        typeof token?.key === 'string'
          ? {...remoteUser, token: {key: token.key}}
          : remoteUser;
      next();
    };
  }

  public register_middlewares(app: Express, auth: VerdaccioAuth): void {
    const plugin = this.getInstance();
    plugin.authChain = auth;
    const secret = auth.config.secret;

    // `npm login`/`yarn npm login` are hardcoded, client-side, to call this
    // URL, which is what lets an IdP access token obtained out-of-band (e.g.
    // via `npx verdaccio-openid`) work by pasting it into `npm login`'s
    // password prompt. Only such a token is handled here: one this plugin's
    // own issuer signed, sent while that issuer advertises RFC 8693 token
    // exchange. Anything else, an htpasswd password included, goes on to
    // Verdaccio's own route (rate-limited, and backed by the auth chain)
    // without ever being sent to the IdP.
    app.put(
      '/-/user/org.couchdb.user::userId',
      bodyParser.json(),
      (req, res, next) => {
        Promise.resolve()
          .then(async () => {
            const client = plugin.client;
            const subjectToken = req.body?.password;
            const userName = req.body?.name;
            if (
              client == null ||
              typeof subjectToken !== 'string' ||
              typeof userName !== 'string' ||
              !supportsTokenExchange(client) ||
              !isIssuedBy(subjectToken, client.issuer.metadata.issuer)
            ) {
              next();
              return;
            }
            // Express's route-string type parser infers this route's param
            // key as the literal ":userId" (it doesn't fully replicate the
            // real runtime parser, path-to-regexp, for a param immediately
            // preceded by a literal colon) -- but the actual req.params key
            // at runtime is the plain "userId", verified directly against
            // this exact route pattern. Trust the runtime, not the type.
            if (userName !== (req.params as Record<string, string>).userId) {
              this.unauthorized(res, 'User ID in URL and body do not match.');
              return;
            }
            if (!plugin.exchangeBudget.take(req.ip ?? 'unknown')) {
              res.status(429);
              res
                .set('Content-Type', 'text/plain')
                .end('too many login attempts, try again later');
              return;
            }

            let tokenSet: TokenSet;
            try {
              // client_id/client_secret (or lack thereof) are already
              // applied per the Client's own configured
              // token_endpoint_auth_method -- repeating them here would put
              // a literal client_secret: undefined in the request body for
              // a PKCE/public client.
              tokenSet = await client.grant({
                grant_type: TOKEN_EXCHANGE_GRANT,
                requested_token_type:
                  'urn:ietf:params:oauth:token-type:refresh_token',
                subject_token: subjectToken,
                subject_token_type:
                  'urn:ietf:params:oauth:token-type:access_token',
                scope: plugin.config.scope,
              });
            } catch (err) {
              plugin.logger.info(
                {err},
                'PUT /-/user: the identity provider rejected the token exchange (@{!err.message})',
              );
              this.unauthorized(
                res,
                'The identity provider rejected this access token.',
              );
              return;
            }

            const tokenUsername = this.getUsername(tokenSet);
            if (userName !== tokenUsername) {
              this.unauthorized(
                res,
                'Access token is not issued for the user trying to log in.',
              );
              return;
            }
            if (this.rejectUnmetRequiredClaim(res, tokenSet)) return;

            const {npmToken} = await this.createTokens(tokenSet, auth);
            res.status(201);
            res
              .set('Content-Type', 'application/json')
              .end(JSON.stringify({token: npmToken}));
          })
          .catch(next);
      },
    );

    if (plugin.config.accessTokenAuth !== true) {
      app.post('/-/v1/login', noCors, (req, res, next) => {
        Promise.resolve()
          .then(() => {
            if (!this.takeMintBudget(req, res, '/-/v1/login')) return;

            const loginRequestId = signLoginRequestId(secret, 'cli');
            res.set('Content-Type', 'application/json').end(
              JSON.stringify({
                loginUrl: new URL(
                  `-/oidc/login/${loginRequestId}`,
                  plugin.config.publicUrl,
                ),
                doneUrl: new URL(
                  `-/oidc/done/${loginRequestId}`,
                  plugin.config.publicUrl,
                ),
              }),
            );
          })
          .catch(next);
      });

      // A plain, GET-able entry point for a human to navigate to directly --
      // e.g. a "Sign in with <provider>" link on the normal web UI (see
      // web.scriptsBodyAfter in this repo's deployment docs) -- as opposed to
      // /-/v1/login above, which exists for the npm/yarn CLI's web-login
      // handshake (JSON response, polled doneUrl) and isn't link-able from a
      // browser. The person is already in the browser that will receive the
      // token, so this goes straight to the IdP with no confirmation page.
      app.get('/-/oidc/start', noCors, (req, res, next) => {
        Promise.resolve()
          .then(async () => {
            if (!this.takeMintBudget(req, res, '/-/oidc/start')) return;
            await this.redirectToIdp(
              res,
              signLoginRequestId(secret, 'web'),
              secret,
            );
          })
          .catch(next);
      });
    }

    // loginUrl for npm/yarn's web login. Anyone can mint a login request id
    // and send its loginUrl to someone else, so this never goes straight to
    // the IdP: whoever opens it is asked to confirm, and the POST below only
    // proceeds when it comes from that same page in that same browser.
    app.get('/-/oidc/login/:loginRequestId', noCors, (req, res) => {
      const loginRequestId = req.params.loginRequestId;
      const request = verifyAndConsumeLoginRequestId(loginRequestId, secret);
      if (request?.kind !== 'cli') {
        this.rejectInvalidLoginRequestId(res);
        return;
      }

      const csrf = randomBytes(16).toString('base64url');
      setCookie(res, csrfCookieName(loginRequestId), csrf, {
        path: publicPath(plugin.config.publicUrl, '-/oidc/login'),
        sameSite: 'Strict',
        secure: isHttps(plugin.config.publicUrl),
      });
      sendHtml(
        res,
        200,
        confirmationPageHtml(new URL(plugin.config.publicUrl).host, csrf),
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
      );
    });

    app.post(
      '/-/oidc/login/:loginRequestId',
      noCors,
      bodyParser.urlencoded({extended: false}),
      (req, res, next) => {
        Promise.resolve()
          .then(async () => {
            const loginRequestId = req.params.loginRequestId;
            const cookieName = csrfCookieName(loginRequestId);
            // A SameSite=Strict cookie isn't sent with a POST another site
            // starts, so a page elsewhere can't submit this form for someone.
            if (!safeEqual(req.body?.csrf, readCookie(req, cookieName))) {
              sendText(
                res,
                403,
                'Open the sign-in link and confirm it in the same browser.',
              );
              return;
            }
            clearCookie(
              res,
              cookieName,
              publicPath(plugin.config.publicUrl, '-/oidc/login'),
            );

            const request = verifyAndConsumeLoginRequestId(
              loginRequestId,
              secret,
            );
            if (request?.kind !== 'cli') {
              this.rejectInvalidLoginRequestId(res);
              return;
            }
            await this.redirectToIdp(res, loginRequestId, secret);
          })
          .catch(next);
      },
    );

    app.get('/-/oidc/callback', noCors, (req, res, next) => {
      Promise.resolve()
        .then(async () => {
          const client = await plugin.clientPromise;
          const params = client.callbackParams(req);
          const loginRequestId = params.state;

          const request =
            typeof loginRequestId === 'string'
              ? verifyAndConsumeLoginRequestId(loginRequestId, secret)
              : null;
          if (request == null || typeof loginRequestId !== 'string') {
            this.rejectInvalidLoginRequestId(res);
            return;
          }

          // Set by redirectToIdp() in the browser that started this login.
          // Without it, a callback URL for someone else's login, handed to
          // this browser, would sign this browser in as them.
          const cookieName = browserCookieName(loginRequestId);
          if (
            !safeEqual(
              readCookie(req, cookieName),
              loginRequestSecret(secret, 'browser', loginRequestId),
            )
          ) {
            sendText(
              res,
              403,
              'Finish signing in in the browser that started it.',
            );
            return;
          }
          clearCookie(
            res,
            cookieName,
            publicPath(plugin.config.publicUrl, '-/oidc/callback'),
          );

          const tokenSet = await client.callback(
            new URL('-/oidc/callback', plugin.config.publicUrl).toString(),
            params,
            {
              state: loginRequestId,
              nonce: loginRequestSecret(secret, 'nonce', loginRequestId),
              response_type: 'code',
              ...(plugin.usePkce
                ? {
                    code_verifier: loginRequestSecret(
                      secret,
                      'pkce',
                      loginRequestId,
                    ),
                  }
                : {}),
            },
          );
          if (this.rejectUnmetRequiredClaim(res, tokenSet)) return;

          const {npmToken, webToken} = await this.createTokens(tokenSet, auth);

          // Only npm/yarn's web login polls doneUrl for a token.
          if (request.kind === 'cli') {
            const remainingSec =
              MAX_AGE_SEC - (Math.floor(Date.now() / 1000) - request.issuedAt);
            await plugin.ts.set(
              `login:${loginRequestId}`,
              npmToken,
              Math.max(1, remainingSec),
            );
          }
          sendHtml(
            res,
            200,
            callbackResponseHtml(this.getUsername(tokenSet), webToken),
            "frame-ancestors 'none'",
          );
        })
        .catch(next);
    });

    // Hands the token to the first poll that finds it, and only that one.
    app.get('/-/oidc/done/:loginRequestId', noCors, (req, res, next) => {
      Promise.resolve()
        .then(async () => {
          const request = verifyAndConsumeLoginRequestId(
            req.params.loginRequestId,
            secret,
          );
          if (request?.kind !== 'cli') {
            this.rejectInvalidLoginRequestId(res);
            return;
          }

          const token = await plugin.ts.consume(
            `login:${req.params.loginRequestId}`,
            10,
          );

          if (token == null) {
            res.status(202).end(JSON.stringify({}));
            return;
          }

          res
            .set('Content-Type', 'application/json')
            .end(JSON.stringify({token}));
        })
        .catch(next);
    });
  }

  private takeMintBudget(req: Request, res: Response, route: string): boolean {
    const plugin = this.getInstance();
    if (checkAndConsumeMintBudget(req.ip ?? 'unknown')) return true;
    plugin.logger.warn(
      {ip: req.ip, route},
      'rejected @{route}: mint budget exceeded for @{ip}',
    );
    sendText(res, 429, 'too many login attempts, try again later');
    return false;
  }

  // Sends the browser to the IdP for this login request, with the PKCE
  // challenge and nonce derived from its id, after setting the cookie the
  // callback checks.
  private async redirectToIdp(
    res: Response,
    loginRequestId: string,
    secret: string,
  ): Promise<void> {
    const plugin = this.getInstance();
    const client = await plugin.clientPromise;

    setCookie(
      res,
      browserCookieName(loginRequestId),
      loginRequestSecret(secret, 'browser', loginRequestId),
      {
        path: publicPath(plugin.config.publicUrl, '-/oidc/callback'),
        // Lax, not Strict: the callback arrives as a cross-site top-level
        // redirect from the IdP, which Lax cookies are sent with.
        sameSite: 'Lax',
        secure: isHttps(plugin.config.publicUrl),
      },
    );

    const authorizationUrl = client.authorizationUrl({
      scope: plugin.config.scope || 'openid email profile',
      state: loginRequestId,
      nonce: loginRequestSecret(secret, 'nonce', loginRequestId),
      redirect_uri: new URL(
        '-/oidc/callback',
        plugin.config.publicUrl,
      ).toString(),
      ...(plugin.usePkce
        ? {
            code_challenge: generators.codeChallenge(
              loginRequestSecret(secret, 'pkce', loginRequestId),
            ),
            code_challenge_method: 'S256',
          }
        : {}),
    });

    res.set('Referrer-Policy', 'no-referrer');
    res.redirect(authorizationUrl);
  }

  private rejectUnmetRequiredClaim(res: Response, tokenSet: TokenSet): boolean {
    const plugin = this.getInstance();
    const unmet = this.unmetRequiredClaim(tokenSet);
    if (unmet == null) return false;
    plugin.logger.warn(
      {claim: unmet},
      'rejected a login: the ID token does not satisfy requiredClaims.@{claim}',
    );
    sendText(res, 403, 'This account is not allowed to sign in here.');
    return true;
  }

  private unauthorized(res: Response, msg: string): void {
    const plugin = this.getInstance();
    plugin.logger.trace({msg}, 'Unauthorized access: @{msg}');
    sendText(res, 401, msg);
  }

  // Rejects a forged, expired, or exhausted-budget login request id --
  // before any of /-/oidc/login, /-/oidc/callback, or /-/oidc/done touch
  // token storage. See loginRequestId.ts for why this check exists.
  private rejectInvalidLoginRequestId(res: Response): void {
    const plugin = this.getInstance();
    plugin.logger.warn(
      {},
      'rejected login request id with invalid signature, expired, or over its use budget',
    );
    sendText(res, 400, 'invalid login request id');
  }

  private async createTokens(
    tokenSet: TokenSet,
    auth: VerdaccioAuth,
  ): Promise<Tokens> {
    const username = this.getUsername(tokenSet);
    const userroles = this.getRoles(tokenSet);
    const user = createRemoteUser(username, userroles);
    const security = this.options.config.security;

    const npmToken = await signPayload(user, auth.config.secret, {
      expiresIn:
        security?.api?.jwt?.sign?.expiresIn ?? DEFAULT_TOKEN_EXPIRES_IN,
    });
    const webToken = await signPayload(user, auth.config.secret, {
      expiresIn: security?.web?.sign?.expiresIn ?? DEFAULT_TOKEN_EXPIRES_IN,
    });

    return {npmToken, webToken};
  }
}

function normalizeRequiredClaims(
  input: OidcPluginConfig['requiredClaims'],
): Array<[string, ClaimValue[]]> {
  if (input == null) return [];
  if (typeof input !== 'object' || Array.isArray(input)) {
    throw new Error(
      'invalid configuration: requiredClaims must map claim names to allowed values',
    );
  }
  return Object.entries(input).map(([claim, value]) => {
    const allowed = Array.isArray(value) ? value : [value];
    if (
      claim === '' ||
      allowed.length === 0 ||
      !allowed.every(v => ['string', 'number', 'boolean'].includes(typeof v))
    ) {
      throw new Error(
        `invalid configuration: requiredClaims.${claim} must be a string, number or boolean, or a non-empty list of them`,
      );
    }
    return [claim, allowed];
  });
}

function supportsTokenExchange(client: Client): boolean {
  const grants = client.issuer.metadata.grant_types_supported;
  return Array.isArray(grants) && grants.includes(TOKEN_EXCHANGE_GRANT);
}

// True only for a JWT whose `iss` is this plugin's issuer. Signature and
// expiry are the IdP's to check during the exchange; this only keeps every
// other password away from the IdP.
function isIssuedBy(token: string, issuer: unknown): boolean {
  const payload = jwt.decode(token);
  return (
    typeof issuer === 'string' &&
    payload != null &&
    typeof payload === 'object' &&
    payload.iss === issuer
  );
}

// The same two forms Verdaccio's own parseBasicPayload accepts: JSON
// {user, password, tokenKey?}, or "user:password" split at the first colon.
function parseBasicCredentials(
  encoded: string,
): {user: string; password: string; tokenKey?: string} | null {
  const decoded = Buffer.from(encoded, 'base64').toString('utf8');
  if (decoded.startsWith('{')) {
    try {
      const parsed = JSON.parse(decoded);
      if (
        typeof parsed?.user === 'string' &&
        typeof parsed?.password === 'string'
      ) {
        return {
          user: parsed.user,
          password: parsed.password,
          ...(typeof parsed.tokenKey === 'string'
            ? {tokenKey: parsed.tokenKey}
            : {}),
        };
      }
    } catch {
      // not JSON after all; try user:password below
    }
  }
  const index = decoded.indexOf(':');
  if (index < 0) return null;
  return {user: decoded.slice(0, index), password: decoded.slice(index + 1)};
}

// Verdaccio's app answers every request with Access-Control-Allow-Origin: *.
// On the login routes that would let any web page start a login and read
// its result from inside a visitor's browser, so the header comes off.
function noCors(_req: Request, res: Response, next: NextFunction): void {
  res.removeHeader('Access-Control-Allow-Origin');
  next();
}

function isHttps(publicUrl: string): boolean {
  return new URL(publicUrl).protocol === 'https:';
}

// The path a browser sees for one of this plugin's routes, which includes
// any prefix publicUrl has (a registry served under /npm/, say).
function publicPath(publicUrl: string, route: string): string {
  return new URL(route, publicUrl).pathname;
}

// Named per login request (its nonce is the id's first segment), so two
// logins running in one browser don't overwrite each other's cookies.
function csrfCookieName(loginRequestId: string): string {
  return `oidc_csrf_${loginRequestId.split('.')[0]}`;
}

function browserCookieName(loginRequestId: string): string {
  return `oidc_login_${loginRequestId.split('.')[0]}`;
}

function setCookie(
  res: Response,
  name: string,
  value: string,
  {
    path,
    sameSite,
    secure,
  }: {path: string; sameSite: 'Strict' | 'Lax'; secure: boolean},
): void {
  res.append(
    'Set-Cookie',
    `${name}=${value}; Path=${path}; Max-Age=${MAX_AGE_SEC}; HttpOnly; SameSite=${sameSite}${secure ? '; Secure' : ''}`,
  );
}

function clearCookie(res: Response, name: string, path: string): void {
  res.append('Set-Cookie', `${name}=; Path=${path}; Max-Age=0; HttpOnly`);
}

function readCookie(req: Request, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0 && part.slice(0, eq).trim() === name) {
      return part.slice(eq + 1).trim();
    }
  }
  return undefined;
}

function safeEqual(a: unknown, b: unknown): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function sendText(res: Response, status: number, message: string): void {
  res.status(status);
  res.set('Content-Type', 'text/plain').end(message);
}

function sendHtml(
  res: Response,
  status: number,
  html: string,
  contentSecurityPolicy: string,
): void {
  res.status(status);
  res.set({
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Security-Policy': contentSecurityPolicy,
    'X-Frame-Options': 'DENY',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
  });
  res.end(html);
}

function createRemoteUser(name: string, pluginGroups: string[]): RemoteUser {
  // copy&paste from: verdaccio/src/lib/auth-utils.ts
  const isGroupValid: boolean = Array.isArray(pluginGroups);
  const groups = (isGroupValid ? pluginGroups : []).concat([
    '$all',
    'all',
    '$authenticated',
    '@all',
    '@authenticated',
  ]);

  return {
    name,
    groups,
    real_groups: pluginGroups,
  };
}

function signPayload(
  payload: RemoteUser,
  secretOrPrivateKey: string,
  options: JWTSignOptions,
): Promise<string> {
  // copy&paste from verdaccio/src/lib/crypto-utils.ts
  const opts: any = {
    notBefore: '1', // Make sure the time will not rollback :)
    ...options,
  };
  return new Promise(function (resolve, reject) {
    jwt.sign(payload, secretOrPrivateKey, opts, (error: any, token: any) =>
      error ? reject(error) : resolve(token),
    );
  });
}

const escapeHtml = (value: string) =>
  value.replace(
    /[&<>"']/g,
    c =>
      ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[
        c
      ] as string,
  );

// An empty form action posts back to this page's own URL.
const confirmationPageHtml = (host: string, csrf: string) => `
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Sign in to ${escapeHtml(host)}</title>
  </head>
  <body>
    <h1>Sign in to ${escapeHtml(host)}</h1>
    <p>
      npm or yarn on a computer asked to sign in to this registry as you.
      Continue only if you just ran a command that needed to sign in, such as
      <code>npm login</code> or <code>yarn npm login</code>. If you didn't,
      close this page.
    </p>
    <form method="POST" action="">
      <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
      <button type="submit">Continue</button>
    </form>
  </body>
</html>
`;

// JSON.stringify alone only guarantees valid *JS string* syntax -- it never
// escapes the "<" character, so a value containing a literal "</script>"
// (e.g. an IdP claim an attacker or the user themselves controls, like
// usernameClaim) closes the surrounding <script> element at the HTML
// parser's own layer before the JS engine ever gets to interpret the
// quotes JSON.stringify added, letting arbitrary markup/script after it
// execute as its own, separate <script> tag. Every "<" is rewritten to the
// six-character JS string escape sequence for it below -- still a
// perfectly valid part of the same JS string literal (the JS engine
// decodes it back to a literal "<" once parsed), but the raw HTML source
// never contains an actual "<" character there for the HTML parser's own
// `</script` scan to find.
const escapeForInlineScript = (value: string) =>
  JSON.stringify(value).replace(/</g, '\\u003c');

const callbackResponseHtml = (username: string, token: string) => `
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
    <script>
      localStorage.setItem('username', ${escapeForInlineScript(username)});
      localStorage.setItem('token', ${escapeForInlineScript(token)});
    </script>
    You are now authenticated in npm and on this website. You can close this
    tab, or <a href="/">continue to the site</a>.
    <script>
      // Browsers only let a page close itself via window.close() when that
      // exact window/tab was opened by a window.open() call from script --
      // an OS-level browser launch (a CLI's own "open this URL" helper, e.g.
      // yarn-plugin-oidc-login's use of it, same as a human navigating here
      // directly) doesn't count, and window.close() silently no-ops. Still
      // worth attempting since it costs nothing when it *does* apply, but
      // the visible fallback above must not assume which case this is --
      // an automatic redirect to the site is a false success signal for the
      // CLI/browser-launch case, not just an occasional no-op.
      window.close();
    </script>
  </body>
</html>
`;
