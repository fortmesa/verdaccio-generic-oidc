import {
  IBasicAuth,
  IPluginMiddleware,
  IPluginAuth,
  AuthCallback,
  PluginOptions,
  Logger,
  RemoteUser,
  JWTSignOptions,
} from '@verdaccio/types';
import {Issuer, Client, TokenSet, generators} from 'openid-client';
import asyncRetry = require('async-retry');
import * as express from 'express';
import {Express, Response} from 'express';
import {nanoid} from 'nanoid/async';
import ms = require('ms');
import * as jwt from 'jsonwebtoken';
import {URL} from 'url';

import {ISessionStorage, ITokenStorage} from './types';
import type {
  NewRedisStorage as NewRedisStorageType,
  RedisStorageConfig,
} from './redis';
import {NewFileStorage} from './fs';
import type {
  NewDynamoStorage as NewDynamoStorageType,
  DynamoStorageConfig,
} from './dynamo';
import {extractGroups, RolesAllowList} from './groups';
import {NewCachedSessionStorage} from './cachedSession';
import {
  signLoginRequestId,
  verifyAndConsumeLoginRequestId,
  checkAndConsumeMintBudget,
} from './loginRequestId';

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

  // Exactly one of these three is required -- see docs/configuration.md,
  // "Storage backends".
  redis?: RedisStorageConfig;
  filesystem?: {sessionPath: string; tokenPath: string};
  dynamo?: DynamoStorageConfig;

  session?: {
    // How long a session lookup is trusted from an in-memory cache before
    // re-checking the real storage backend, in seconds. Defaults to 5
    // minutes; set to 0 to disable caching entirely. See cachedSession.ts.
    cacheTtl?: number;
  };

  accessTokenAuth?: boolean;

  oidcPluginInstance: OidcPlugin;
};

type Tokens = {
  npmToken: string;
  webToken: string;
};

type RemoteUserEx = RemoteUser & {sid: string};

const TOKEN_BEARER = 'Bearer';

// Must match this package's name: Verdaccio's plugin loader resolves a scoped
// package name verbatim as the config key (no `verdaccio-` prefix mangling),
// and both the `auth:` and `middlewares:` sections need to agree on this key
// for the constructor's self-referencing instance-sharing trick below to work.
const PLUGIN_CONFIG_KEY = '@fortmesa/verdaccio-generic-oidc';

export default class OidcPlugin
  implements IPluginAuth<OidcPluginConfig>, IPluginMiddleware<OidcPluginConfig>
{
  private readonly pluginName = PLUGIN_CONFIG_KEY;

  private config: OidcPluginConfig;
  private options: PluginOptions<OidcPluginConfig>;
  private clientPromise!: Promise<Client>;
  private closed = false;
  private logger!: Logger;
  private ss!: ISessionStorage;
  private ts!: ITokenStorage;
  private sessionTtl!: number;
  private usePkce!: boolean;

  constructor(
    config: OidcPluginConfig,
    appOptions: PluginOptions<OidcPluginConfig>,
  ) {
    this.config = config;
    this.options = appOptions;
    if (this.config.oidcPluginInstance != null) {
      return this.options.config.oidcPluginInstance;
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
    const sessionExpiresIn =
      this.options.config.security?.api?.jwt?.sign?.expiresIn;
    const sessionTtl =
      sessionExpiresIn == null || sessionExpiresIn === 'never'
        ? '30d'
        : sessionExpiresIn;
    // ISessionStorage.set()'s expires_sec is, per its name, seconds -- but
    // ms() (needed for a human duration string like '30d') returns
    // milliseconds. A numeric expiresIn is already seconds by JWT's own
    // convention, so only the string branch needs converting. Getting this
    // wrong here previously meant sessions effectively never expired in
    // Redis/DynamoDB/filesystem (a 30d config value became ~82 years).
    this.sessionTtl = Number.isNaN(+sessionTtl)
      ? Math.floor(ms(sessionTtl) / 1000)
      : +sessionTtl;

    if (this.config.redis?.url) {
      // ioredis is an optional peer dependency -- only require() it when
      // actually selected, so filesystem/DynamoDB-only installs never need
      // it on disk.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const {NewRedisStorage} = require('./redis') as {
        NewRedisStorage: typeof NewRedisStorageType;
      };
      const rs = NewRedisStorage(this.config.redis);
      this.ss = rs.ss;
      this.ts = rs.ts;
    } else if (
      this.config.filesystem?.sessionPath &&
      this.config.filesystem?.tokenPath
    ) {
      const rs = NewFileStorage(
        this.logger,
        this.config.filesystem.sessionPath,
        this.config.filesystem.tokenPath,
      );
      this.ss = rs.ss;
      this.ts = rs.ts;
    } else if (this.config.dynamo?.tableName) {
      // @aws-sdk/* is an optional peer dependency -- same reasoning as above.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const {NewDynamoStorage} = require('./dynamo') as {
        NewDynamoStorage: typeof NewDynamoStorageType;
      };
      const rs = NewDynamoStorage(this.config.dynamo);
      this.ss = rs.ss;
      this.ts = rs.ts;
    } else {
      throw new Error(
        'invalid configuration: none of [redis.url], [filesystem.sessionPath, filesystem.tokenPath], or [dynamo.tableName] is set',
      );
    }

    // authenticate() calls ss.get() on every authenticated npm/yarn request,
    // not just logins -- wrapping whichever backend was selected above with
    // a bounded-staleness in-memory cache applies uniformly regardless of
    // which one is in use. session.cacheTtl: 0 opts out entirely.
    const sessionCacheTtlSec = this.config.session?.cacheTtl ?? 5 * 60;
    if (sessionCacheTtlSec > 0) {
      this.ss = NewCachedSessionStorage(this.ss, sessionCacheTtlSec);
    }

    const clientSecret =
      process.env.OIDC_CLIENT_SECRET || this.config.clientSecret;
    this.usePkce = !clientSecret;

    this.clientPromise = asyncRetry(() => Issuer.discover(this.config.issuer), {
      forever: true,
      maxTimeout: 30_000,
      onRetry: (err, attempt) => {
        this.logger.warn(
          {err, attempt},
          'Failed to discover issuer, retrying [@{attempt}]: @{!err.message}\n@{err.stack}',
        );
      },
    }).then(
      issuer =>
        new issuer.Client({
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
        }),
    );
  }

  public close() {
    const plugin = this.getInstance();
    if (plugin.closed) {
      return;
    }

    plugin.closed = true;
    plugin.ss.close();
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

  private async saveSession(
    sessionId: string,
    tokenSet: TokenSet,
  ): Promise<void> {
    const plugin = this.getInstance();
    return plugin.ss.set(`session:${sessionId}`, tokenSet, plugin.sessionTtl);
  }

  public authenticate(user: string, password: string, cb: AuthCallback): void {
    const plugin = this.getInstance();

    Promise.resolve()
      .then(async () => {
        const sessionId = password;
        const tokenSetObj: any | null = await plugin.ss.get(
          `session:${sessionId}`,
        );
        if (tokenSetObj == null) {
          cb(null, false);
          return;
        }

        let tokenSet = new TokenSet(tokenSetObj);
        const username = this.getUsername(tokenSet);

        if (username !== user) {
          plugin.logger.error(
            {user, username},
            'Rejecting auth because username @{user} does not match session username @{username}',
          );
          cb(null, false);
          return;
        }
        if (tokenSet.expired()) {
          plugin.logger.debug(
            {username},
            'Refreshing expired session for @{username}',
          );

          const client = await plugin.clientPromise;
          tokenSet = await client.refresh(tokenSet);
          await this.saveSession(sessionId, tokenSet);
        }

        plugin.logger.info({username}, 'Authenticated @{username}');

        const roles = this.getRoles(tokenSet);
        cb(null, [username, ...roles]);
      })
      .catch(err => {
        // cb(err, ...) aborts Verdaccio's entire auth plugin chain outright
        // (see @verdaccio/auth's authenticate()) -- it never falls through
        // to htpasswd, defeating the break-glass fallback this plugin is
        // deliberately configured ahead of. Falling through to the next
        // auth plugin is the expected, by-design outcome of this plugin
        // not authenticating the request, regardless of why.
        plugin.logger.debug(
          {err},
          'oidc: error while authenticating: @{!err.message}\n@{err.stack} -- falling through to any other configured auth plugin',
        );
        cb(null, false);
      });
  }

  public apiJWTmiddleware?: (helpers: any) => any;

  private _apiJWTmiddleware(helpers: any): any {
    const plugin = this.getInstance();

    return (
      req: express.Request & {remote_user: RemoteUserEx},
      _res: express.Response,
      _next: express.NextFunction,
    ) => {
      req.pause();

      const next = function (err?: Error) {
        req.resume(); // uncomment this to reject users with bad auth headers
        // return _next.apply(null, arguments)
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

      const {authorization} = req.headers;
      if (!authorization) {
        // looks like this is anonymous query - pass req to verdaccio core
        return next();
      }

      const authorizationParts = authorization.split(' ', 2);
      if (
        authorizationParts.length !== 2 ||
        authorizationParts[0] !== TOKEN_BEARER
      ) {
        plugin.logger.warn(
          {scheme: authorizationParts[0]},
          'unsupported authorization encoding or scheme @{scheme}',
        );
        return next(new Error('unsupported authorization encoding or scheme'));
      }

      const jwtRaw = authorizationParts[1];
      let jwtPayload = undefined;

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
        jwtPayload = jwt.verify(jwtRaw, plugin.options.config.secret);
      } catch (err) {
        plugin.logger.error(
          {err},
          'error while verifying jwt bearer token: @{!err.message}\n@{err.stack}',
        );
      }

      if (!jwtPayload) {
        return next(new Error('unable to verify jwt bearer token'));
      }

      const {sid, name, real_groups} = jwtPayload as RemoteUserEx;
      if (!sid) {
        plugin.logger.error(
          {},
          'incoming jwt token does not contain [sid] claim',
        );
        return next(new Error('jwt token does not contain sid'));
      }
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

      this.authenticate(name, sid, (err, groups) => {
        if (err) {
          plugin.logger.error(
            {err},
            'auth error: @{!err.message}\n@{err.stack}',
          );
          return next(err);
        }
        if (!groups) {
          plugin.logger.error(
            {sid},
            'unable to find session groups for incoming jwt token session @{sid}',
          );
          return next(
            new Error(
              'unable to find session groups for incoming jwt token session',
            ),
          );
        }

        const groupsWithoutUser: string[] = groups.slice(1);
        const rolesClaim = plugin.config.roles?.claim;
        if (rolesClaim) {
          if (!real_groups.every(v => groupsWithoutUser.includes(v))) {
            plugin.logger.error(
              {},
              'incoming token contains [real_groups] claim that is not a subset of the oidc server roles claim',
            );
            return next(
              new Error(
                'incoming token contains [real_groups] claim that is not a subset of the oidc server roles claim',
              ),
            );
          }
        }

        req.remote_user = helpers.createRemoteUser(name, groupsWithoutUser);
        next();
      });
    };
  }

  public register_middlewares(
    app: Express,
    auth: IBasicAuth<OidcPluginConfig>,
  ): void {
    const plugin = this.getInstance();
    app.put(
      '/-/user/org.couchdb.user::userId',
      express.json(),
      (req, res, next) => {
        Promise.resolve()
          .then(async () => {
            const subjectToken = req.body.password;
            if (!subjectToken) {
              this.unauthorized(res, 'Password attribute is missing.');
              return;
            }
            const userName = req.body.name;
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
            const client = await plugin.clientPromise;
            // client_id/client_secret (or lack thereof) are already applied
            // per the Client's own configured token_endpoint_auth_method --
            // repeating them here would put a literal client_secret:
            // undefined in the request body for a PKCE/public client.
            const tokenSet = await client.grant({
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              requested_token_type:
                'urn:ietf:params:oauth:token-type:refresh_token',
              subject_token: subjectToken,
              subject_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              scope: plugin.config.scope,
            });

            const tokenUsername = this.getUsername(tokenSet);
            if (userName !== tokenUsername) {
              this.unauthorized(
                res,
                'Access token is not issued for the user trying to log in.',
              );
              return;
            }

            const sessionId = await nanoid();
            const {npmToken} = await this.saveSessionAndCreateTokens(
              sessionId,
              tokenSet,
              auth,
            );
            const responseBody = JSON.stringify({token: npmToken});
            res.status(201);
            res.set('Content-Type', 'application/json').end(responseBody);
          })
          .catch(next);
      },
    );

    if (plugin.config.accessTokenAuth !== true) {
      app.post('/-/v1/login', express.json(), (req, res, next) => {
        Promise.resolve()
          .then(async () => {
            if (!checkAndConsumeMintBudget(req.ip ?? 'unknown')) {
              plugin.logger.warn(
                {ip: req.ip},
                'rejected /-/v1/login: mint budget exceeded for @{ip}',
              );
              res.status(429);
              res
                .set('Content-Type', 'text/plain')
                .end('too many login attempts, try again later');
              return;
            }

            const loginRequestId = await signLoginRequestId(auth.config.secret);

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
      // browser. Mints the same signed, rate-limited loginRequestId and skips
      // straight to the same /-/oidc/login/:id redirect used by that flow.
      app.get('/-/oidc/start', (req, res, next) => {
        Promise.resolve()
          .then(async () => {
            if (!checkAndConsumeMintBudget(req.ip ?? 'unknown')) {
              plugin.logger.warn(
                {ip: req.ip},
                'rejected /-/oidc/start: mint budget exceeded for @{ip}',
              );
              res.status(429);
              res
                .set('Content-Type', 'text/plain')
                .end('too many login attempts, try again later');
              return;
            }

            const loginRequestId = await signLoginRequestId(auth.config.secret);
            res.redirect(`/-/oidc/login/${loginRequestId}`);
          })
          .catch(next);
      });
    }

    app.get('/-/oidc/login/:loginRequestId', (req, res, next) => {
      Promise.resolve()
        .then(async () => {
          if (
            !verifyAndConsumeLoginRequestId(
              req.params.loginRequestId,
              auth.config.secret,
            )
          ) {
            this.rejectInvalidLoginRequestId(res);
            return;
          }

          const client = await plugin.clientPromise;

          let pkceParams = {};
          if (plugin.usePkce) {
            const codeVerifier = generators.codeVerifier();
            // Keyed by loginRequestId (== the `state` sent to the IdP) so
            // /-/oidc/callback below can look it up once the browser returns;
            // 5 minutes comfortably covers a user completing the IdP's own
            // login page, matching the TTL used for the post-login token
            // handoff further down in this file.
            await plugin.ts.set(
              `pkce:${req.params.loginRequestId}`,
              codeVerifier,
              5 * 60,
            );
            pkceParams = {
              code_challenge: generators.codeChallenge(codeVerifier),
              code_challenge_method: 'S256',
            };
          }

          const authorizationUrl = client.authorizationUrl({
            scope: plugin.config.scope || 'openid email profile',
            state: req.params.loginRequestId,
            redirect_uri: new URL(
              '-/oidc/callback',
              plugin.config.publicUrl,
            ).toString(),
            ...pkceParams,
          });

          res.redirect(authorizationUrl);
        })
        .catch(next);
    });

    app.get('/-/oidc/callback', (req, res, next) => {
      Promise.resolve()
        .then(async () => {
          const client = await plugin.clientPromise;
          const params = client.callbackParams(req);

          if (
            typeof params.state !== 'string' ||
            !verifyAndConsumeLoginRequestId(params.state, auth.config.secret)
          ) {
            this.rejectInvalidLoginRequestId(res);
            return;
          }

          // Short poll window as a safety margin for storage propagation
          // delay -- the verifier was already written before the IdP
          // redirect, so it should be there immediately.
          const codeVerifier = plugin.usePkce
            ? await plugin.ts.get(`pkce:${params.state}`, 5)
            : null;

          const tokenSet = await client.callback(
            new URL('-/oidc/callback', plugin.config.publicUrl).toString(),
            params,
            {
              state: params.state,
              ...(codeVerifier ? {code_verifier: codeVerifier} : {}),
            },
          );

          const loginRequestId = params.state;
          const sessionId = await nanoid();
          const {npmToken, webToken} = await this.saveSessionAndCreateTokens(
            sessionId,
            tokenSet,
            auth,
          );

          await plugin.ts.set(`login:${loginRequestId}`, npmToken, 5 * 60);
          res
            .set('Content-Type', 'text/html')
            .end(callbackResponseHtml(this.getUsername(tokenSet), webToken));
        })
        .catch(next);
    });

    app.get('/-/oidc/done/:loginRequestId', (req, res, next) => {
      Promise.resolve()
        .then(async () => {
          if (
            !verifyAndConsumeLoginRequestId(
              req.params.loginRequestId,
              auth.config.secret,
            )
          ) {
            this.rejectInvalidLoginRequestId(res);
            return;
          }

          const token = await plugin.ts.get(
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

  private unauthorized(res: Response, msg: string): void {
    const plugin = this.getInstance();
    plugin.logger.trace({msg}, 'Unauthorized access: @{msg}');
    res.status(401);
    res.set('Content-Type', 'text/plain').end(msg);
  }

  // Rejects a forged, expired, or exhausted-budget login request id --
  // before any of /-/oidc/login, /-/oidc/callback, or /-/oidc/done touch session/
  // token storage. See loginRequestId.ts for why this check exists.
  private rejectInvalidLoginRequestId(res: Response): void {
    const plugin = this.getInstance();
    plugin.logger.warn(
      {},
      'rejected login request id with invalid signature, expired, or over its use budget',
    );
    res.status(400);
    res.set('Content-Type', 'text/plain').end('invalid login request id');
  }

  private async saveSessionAndCreateTokens(
    sessionId: string,
    tokenSet: TokenSet,
    auth: IBasicAuth<OidcPluginConfig>,
  ): Promise<Tokens> {
    await this.saveSession(sessionId, tokenSet);
    const username = this.getUsername(tokenSet);
    const userroles = this.getRoles(tokenSet);

    const rUser = {
      ...createRemoteUser(username, userroles),
      sid: sessionId,
    };
    const npmToken = await signPayload(rUser, auth.config.secret, {
      expiresIn: this.options.config.security?.api?.jwt?.sign?.expiresIn,
    });
    const webToken = await signPayload(rUser, auth.config.secret, {
      // default expiration for web tokens is 7 days:
      // https://github.com/verdaccio/verdaccio/blob/64f0921477ef68fc96a2327c7a3c86a45f6d0255/packages/config/src/security.ts#L5-L11
      expiresIn: this.options.config.security?.web?.sign?.expiresIn ?? '7d',
    });

    return {npmToken, webToken};
  }
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
  payload: RemoteUserEx,
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

const callbackResponseHtml = (username: string, token: string) => `
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
    <script>
      localStorage.setItem('username', ${JSON.stringify(username)});
      localStorage.setItem('token', ${JSON.stringify(token)});
    </script>
    You are now authenticated in npm and on this website.
    <script>
      // A CLI (npm/yarn --web-login) opens this page as a fresh, script-opened
      // tab/popup, which window.close() is allowed to close; a human who
      // navigated here directly via /-/oidc/start in an existing tab is not
      // (browsers silently no-op close() there) -- redirect that case back to
      // the registry's own homepage instead, now authenticated via the
      // localStorage set above.
      window.close();
      setTimeout(function() { window.location.href = '/'; }, 300);
    </script>
  </body>
</html>
`;
