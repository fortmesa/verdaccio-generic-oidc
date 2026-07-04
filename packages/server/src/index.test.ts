/**
 * Exercises the plugin against a real local HTTP server acting as a fake
 * OIDC issuer (real RS256-signed ID tokens, real JWKS, real discovery) --
 * this plugin's own value is almost entirely in the OAuth/OIDC protocol
 * plumbing, so a hand-rolled fake at that level catches far more than
 * mocking `openid-client` itself would. Storage uses the real filesystem
 * backend (already covered in fs.test.ts) against a fresh temp directory --
 * cheap and real, no need to fake it here too.
 */
import {
  describe,
  it,
  expect,
  beforeAll,
  afterAll,
  beforeEach,
  vi,
} from 'vitest';
import * as http from 'http';
import type {AddressInfo} from 'net';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import * as os from 'os';
import * as path from 'path';
import * as fsp from 'fs/promises';
import express from 'express';
import type {IBasicAuth, Logger, PluginOptions} from '@verdaccio/types';
import OidcPlugin from './index';

// ---------------------------------------------------------------------
// Fake OIDC issuer: real HTTP server, real RS256-signed ID tokens, real
// JWKS -- accepts any authorization code/refresh token/subject token
// unconditionally (this is a test double, not a spec-compliant IdP), but
// gets the parts openid-client actually verifies (issuer, audience,
// signature, expiry) right for real.
// ---------------------------------------------------------------------

const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
const JWK_KID = 'test-key';
const JWKS = {
  keys: [
    {
      ...publicKey.export({format: 'jwk'}),
      kid: JWK_KID,
      use: 'sig',
      alg: 'RS256',
    },
  ],
};

interface FakeIssuer {
  url: string;
  clientId: string;
  state: {claims: Record<string, unknown>};
  close(): Promise<void>;
}

function signIdToken(
  issuerUrl: string,
  clientId: string,
  claims: Record<string, unknown>,
): string {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iss: issuerUrl,
      aud: clientId,
      sub: 'fake-subject',
      iat: now,
      exp: now + 3600,
      ...claims,
    },
    privateKey,
    {algorithm: 'RS256', keyid: JWK_KID},
  );
}

function startFakeIssuer(clientId: string): Promise<FakeIssuer> {
  const state = {
    claims: {preferred_username: 'alice'} as Record<string, unknown>,
  };
  let issuerUrl = '';

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');

    if (url.pathname === '/.well-known/openid-configuration') {
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          issuer: issuerUrl,
          authorization_endpoint: `${issuerUrl}/authorize`,
          token_endpoint: `${issuerUrl}/token`,
          jwks_uri: `${issuerUrl}/jwks`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          token_endpoint_auth_methods_supported: [
            'client_secret_basic',
            'none',
          ],
          code_challenge_methods_supported: ['S256'],
        }),
      );
      return;
    }

    if (url.pathname === '/jwks') {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(JWKS));
      return;
    }

    if (url.pathname === '/token' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => (body += chunk));
      req.on('end', () => {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            access_token: 'fake-access-token',
            refresh_token: 'fake-refresh-token',
            id_token: signIdToken(issuerUrl, clientId, state.claims),
            token_type: 'Bearer',
            expires_in: 3600,
          }),
        );
      });
      return;
    }

    res.statusCode = 404;
    res.end();
  });

  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => {
      const {port} = server.address() as AddressInfo;
      issuerUrl = `http://127.0.0.1:${port}`;
      resolve({
        url: issuerUrl,
        clientId,
        state,
        close: () => new Promise<void>(res => server.close(() => res())),
      });
    });
  });
}

// ---------------------------------------------------------------------
// Test scaffolding: a fake Verdaccio Logger/PluginOptions/IBasicAuth (only
// the fields this plugin's code actually reads), and a helper to build a
// fresh plugin instance wired to the fake issuer above plus a real,
// throwaway filesystem storage directory.
// ---------------------------------------------------------------------

const JWT_SECRET = 'test-jwt-secret';
const CLIENT_ID = 'test-client';

function makeLogger(): Logger {
  return {
    child: vi.fn(),
    debug: vi.fn(),
    error: vi.fn(),
    http: vi.fn(),
    trace: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
  };
}

function makeAuth(): IBasicAuth<any> {
  return {
    config: {secret: JWT_SECRET} as any,
    aesEncrypt: vi.fn(),
    authenticate: vi.fn(),
    changePassword: vi.fn(),
    allow_access: vi.fn(),
    add_user: vi.fn(),
  };
}

let issuer: FakeIssuer;
let tmpDir: string;

beforeAll(async () => {
  issuer = await startFakeIssuer(CLIENT_ID);
});

afterAll(async () => {
  await issuer.close();
});

beforeEach(async () => {
  tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'oidc-index-test-'));
  issuer.state.claims = {preferred_username: 'alice'};
});

function createPlugin(configOverrides: Record<string, unknown> = {}): {
  plugin: OidcPlugin;
  logger: Logger;
  config: Record<string, unknown>;
} {
  const logger = makeLogger();
  // publicUrl is a placeholder -- startServer() below rewrites it in place
  // once the test server's real port is known, and every actual use of it
  // (building the authorization/callback/login/done URLs) reads
  // plugin.config.publicUrl fresh at request time, not just once at
  // construction, so mutating it after the fact is safe.
  const config = {
    publicUrl: 'http://placeholder.invalid',
    issuer: issuer.url,
    clientId: CLIENT_ID,
    clientSecret: 'test-client-secret',
    scope: 'openid profile email',
    filesystem: {sessionPath: tmpDir, tokenPath: tmpDir},
    // Deliberately no `oidcPluginInstance` key at all (not even `undefined`)
    // -- OidcPlugin.getInstance() checks `'oidcPluginInstance' in this.config`,
    // a key-existence check, not a value check, so a present-but-undefined
    // key would still incorrectly short-circuit every method call.
    ...configOverrides,
  };
  const appOptions = {
    config: {
      secret: JWT_SECRET,
      security: {
        api: {jwt: {sign: {expiresIn: '30d'}}},
        web: {sign: {expiresIn: '7d'}},
      },
      middlewares: {},
    },
    logger,
  } as unknown as PluginOptions<any>;

  return {plugin: new OidcPlugin(config as any, appOptions), logger, config};
}

async function startServer(
  plugin: OidcPlugin,
  config: Record<string, unknown>,
  auth: IBasicAuth<any>,
): Promise<{baseUrl: string; close(): Promise<void>}> {
  const app = express();
  plugin.register_middlewares(app as any, auth);
  const server = http.createServer(app);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const {port} = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;
  config.publicUrl = baseUrl;
  return {
    baseUrl,
    close: () => new Promise<void>(resolve => server.close(() => resolve())),
  };
}

// Drives the full npm/yarn web-login handshake against a running plugin
// server: POST /-/v1/login, follow the redirect straight to /-/oidc/callback
// (skipping the real browser round-trip to the fake issuer's own
// /authorize, which openid-client never calls server-side anyway), then
// poll /-/oidc/done for the npm token.
async function performLogin(baseUrl: string): Promise<{
  npmToken: string;
  callbackHtml: string;
}> {
  const loginRes = await fetch(`${baseUrl}/-/v1/login`, {method: 'POST'});
  const {loginUrl, doneUrl} = await loginRes.json();

  const loginRedirect = await fetch(loginUrl, {redirect: 'manual'});
  expect(loginRedirect.status).toBe(302);
  const authorizeUrl = new URL(loginRedirect.headers.get('location')!);
  const state = authorizeUrl.searchParams.get('state')!;

  const callbackUrl = new URL(`${baseUrl}/-/oidc/callback`);
  callbackUrl.searchParams.set('state', state);
  callbackUrl.searchParams.set('code', 'fake-authorization-code');
  const callbackRes = await fetch(callbackUrl);
  expect(callbackRes.status).toBe(200);
  const callbackHtml = await callbackRes.text();

  let token: string | undefined;
  for (let i = 0; i < 20 && !token; i++) {
    const doneRes = await fetch(doneUrl);
    const body = await doneRes.json();
    token = body.token;
    if (!token) await new Promise(r => setTimeout(r, 50));
  }
  if (!token) throw new Error('login never completed');

  return {npmToken: token, callbackHtml};
}

describe('OidcPlugin: constructor', () => {
  it('throws when no storage backend is configured', () => {
    expect(() => createPlugin({filesystem: undefined})).toThrow(
      /invalid configuration/,
    );
  });
});

describe('OidcPlugin: full login flow (confidential client)', () => {
  it('logs in and issues a working npm token', async () => {
    const {plugin, config} = createPlugin();
    const server = await startServer(plugin, config, makeAuth());
    try {
      const {npmToken, callbackHtml} = await performLogin(server.baseUrl);

      const payload = jwt.verify(npmToken, JWT_SECRET) as Record<
        string,
        unknown
      >;
      expect(payload.name).toBe('alice');
      expect(payload.real_groups).toEqual([]);
      expect(callbackHtml).toContain('alice');
    } finally {
      await server.close();
      plugin.close();
    }
  });

  it('extracts roles into real_groups per the configured claim', async () => {
    issuer.state.claims = {
      preferred_username: 'alice',
      resource_access: {[CLIENT_ID]: {roles: ['admin']}},
    };
    const {plugin, config} = createPlugin({
      roles: {claim: 'resource_access', allowList: {[CLIENT_ID]: ['admin']}},
    });
    const server = await startServer(plugin, config, makeAuth());
    try {
      const {npmToken} = await performLogin(server.baseUrl);
      const payload = jwt.verify(npmToken, JWT_SECRET) as Record<
        string,
        unknown
      >;
      expect(payload.real_groups).toEqual([CLIENT_ID]);
    } finally {
      await server.close();
      plugin.close();
    }
  });
});

describe('OidcPlugin: full login flow (public/PKCE client)', () => {
  it('logs in without a client secret, using PKCE', async () => {
    const {plugin, config} = createPlugin({clientSecret: undefined});
    const server = await startServer(plugin, config, makeAuth());
    try {
      const loginRes = await fetch(`${server.baseUrl}/-/v1/login`, {
        method: 'POST',
      });
      const {loginUrl} = await loginRes.json();
      const redirect = await fetch(loginUrl, {redirect: 'manual'});
      const authorizeUrl = new URL(redirect.headers.get('location')!);

      expect(authorizeUrl.searchParams.get('code_challenge_method')).toBe(
        'S256',
      );
      expect(authorizeUrl.searchParams.get('code_challenge')).toBeTruthy();

      const {npmToken} = await performLogin(server.baseUrl);
      expect(jwt.verify(npmToken, JWT_SECRET)).toBeTruthy();
    } finally {
      await server.close();
      plugin.close();
    }
  });
});

describe('OidcPlugin: accessTokenAuth', () => {
  it('disables /-/v1/login when accessTokenAuth is true', async () => {
    const {plugin, config} = createPlugin({accessTokenAuth: true});
    const server = await startServer(plugin, config, makeAuth());
    try {
      const res = await fetch(`${server.baseUrl}/-/v1/login`, {
        method: 'POST',
      });
      expect(res.status).toBe(404);
    } finally {
      await server.close();
      plugin.close();
    }
  });

  it('disables /-/oidc/start when accessTokenAuth is true', async () => {
    const {plugin, config} = createPlugin({accessTokenAuth: true});
    const server = await startServer(plugin, config, makeAuth());
    try {
      const res = await fetch(`${server.baseUrl}/-/oidc/start`, {
        redirect: 'manual',
      });
      expect(res.status).toBe(404);
    } finally {
      await server.close();
      plugin.close();
    }
  });
});

describe('OidcPlugin: GET /-/oidc/start', () => {
  it('redirects straight into the login flow and completes it', async () => {
    const {plugin, config} = createPlugin();
    const server = await startServer(plugin, config, makeAuth());
    try {
      const startRes = await fetch(`${server.baseUrl}/-/oidc/start`, {
        redirect: 'manual',
      });
      expect(startRes.status).toBe(302);
      const loginPath = startRes.headers.get('location')!;
      expect(loginPath).toMatch(/^\/-\/oidc\/login\//);

      const loginRedirect = await fetch(`${server.baseUrl}${loginPath}`, {
        redirect: 'manual',
      });
      expect(loginRedirect.status).toBe(302);
      const authorizeUrl = new URL(loginRedirect.headers.get('location')!);
      const state = authorizeUrl.searchParams.get('state')!;

      const callbackUrl = new URL(`${server.baseUrl}/-/oidc/callback`);
      callbackUrl.searchParams.set('state', state);
      callbackUrl.searchParams.set('code', 'fake-authorization-code');
      const callbackRes = await fetch(callbackUrl);
      expect(callbackRes.status).toBe(200);
      const callbackHtml = await callbackRes.text();

      // Distinct from the CLI-triggered popup flow: still attempts
      // window.close() first (harmless no-op in a non-script-opened tab),
      // but falls back to redirecting home instead of leaving a dead end.
      expect(callbackHtml).toContain('alice');
      expect(callbackHtml).toContain('window.close()');
      expect(callbackHtml).toContain("window.location.href = '/'");
    } finally {
      await server.close();
      plugin.close();
    }
  });
});

describe('OidcPlugin: token-exchange endpoint (PUT /-/user/...)', () => {
  it('exchanges a subject token for an npm session', async () => {
    const {plugin, config} = createPlugin();
    const server = await startServer(plugin, config, makeAuth());
    try {
      const res = await fetch(
        `${server.baseUrl}/-/user/org.couchdb.user:alice`,
        {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({name: 'alice', password: 'some-access-token'}),
        },
      );
      expect(res.status).toBe(201);
      const {token} = await res.json();
      const payload = jwt.verify(token, JWT_SECRET) as Record<string, unknown>;
      expect(payload.name).toBe('alice');
    } finally {
      await server.close();
      plugin.close();
    }
  });

  it('rejects when the URL user and body user do not match', async () => {
    const {plugin, config} = createPlugin();
    const server = await startServer(plugin, config, makeAuth());
    try {
      const res = await fetch(
        `${server.baseUrl}/-/user/org.couchdb.user:alice`,
        {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({name: 'bob', password: 'some-access-token'}),
        },
      );
      expect(res.status).toBe(401);
    } finally {
      await server.close();
      plugin.close();
    }
  });

  it('rejects when the token belongs to a different user', async () => {
    issuer.state.claims = {preferred_username: 'someone-else'};
    const {plugin, config} = createPlugin();
    const server = await startServer(plugin, config, makeAuth());
    try {
      const res = await fetch(
        `${server.baseUrl}/-/user/org.couchdb.user:alice`,
        {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({name: 'alice', password: 'some-access-token'}),
        },
      );
      expect(res.status).toBe(401);
    } finally {
      await server.close();
      plugin.close();
    }
  });
});

describe('OidcPlugin: authenticate()', () => {
  it('authenticates a valid session and returns its groups', async () => {
    const {plugin, config} = createPlugin();
    const server = await startServer(plugin, config, makeAuth());
    try {
      const {npmToken} = await performLogin(server.baseUrl);
      const {sid} = jwt.verify(npmToken, JWT_SECRET) as {sid: string};

      const result = await new Promise<[unknown, unknown]>(resolve => {
        plugin.authenticate('alice', sid, (err, groups) =>
          resolve([err, groups]),
        );
      });
      expect(result[0]).toBeNull();
      expect(result[1]).toContain('alice');
    } finally {
      await server.close();
      plugin.close();
    }
  });

  it('rejects a session id that was never issued', async () => {
    const {plugin, config} = createPlugin();
    const result = await new Promise<[unknown, unknown]>(resolve => {
      plugin.authenticate('alice', 'not-a-real-session', (err, groups) =>
        resolve([err, groups]),
      );
    });
    expect(result[0]).toBeNull();
    expect(result[1]).toBe(false);
    plugin.close();
  });

  it('falls through to the next auth plugin (does not abort the chain) when session storage throws', async () => {
    const {plugin, logger} = createPlugin();
    (plugin as any).ss.get = () => {
      throw new Error('simulated DynamoDB failure');
    };

    const result = await new Promise<[unknown, unknown]>(resolve => {
      plugin.authenticate('alice', 'irrelevant-password', (err, groups) =>
        resolve([err, groups]),
      );
    });
    // err must be null -- @verdaccio/auth's real plugin chain aborts
    // entirely (never tries htpasswd) if err is truthy here, regardless of
    // what the second argument is.
    expect(result[0]).toBeNull();
    expect(result[1]).toBe(false);
    expect(logger.debug).toHaveBeenCalledWith(
      expect.objectContaining({err: expect.any(Error)}),
      expect.stringContaining('falling through'),
    );
    plugin.close();
  });

  it('rejects when the username does not match the session', async () => {
    const {plugin, config} = createPlugin();
    const server = await startServer(plugin, config, makeAuth());
    try {
      const {npmToken} = await performLogin(server.baseUrl);
      const {sid} = jwt.verify(npmToken, JWT_SECRET) as {sid: string};

      const result = await new Promise<[unknown, unknown]>(resolve => {
        plugin.authenticate('not-alice', sid, (err, groups) =>
          resolve([err, groups]),
        );
      });
      expect(result[1]).toBe(false);
    } finally {
      await server.close();
      plugin.close();
    }
  });
});

describe('OidcPlugin: invalid login request ids', () => {
  it('rejects a forged loginRequestId on /-/oidc/login', async () => {
    const {plugin, config} = createPlugin();
    const server = await startServer(plugin, config, makeAuth());
    try {
      const res = await fetch(`${server.baseUrl}/-/oidc/login/forged-id`);
      expect(res.status).toBe(400);
    } finally {
      await server.close();
      plugin.close();
    }
  });

  it('rejects a forged loginRequestId on /-/oidc/done', async () => {
    const {plugin, config} = createPlugin();
    const server = await startServer(plugin, config, makeAuth());
    try {
      const res = await fetch(`${server.baseUrl}/-/oidc/done/forged-id`);
      expect(res.status).toBe(400);
    } finally {
      await server.close();
      plugin.close();
    }
  });
});

describe('OidcPlugin: apiJWTmiddleware() bearer token handling', () => {
  function makeReq(headers: Record<string, string>) {
    return {headers, pause() {}, resume() {}} as any;
  }
  function makeHelpers() {
    return {
      createAnonymousRemoteUser: () => ({
        name: undefined,
        groups: [],
        real_groups: [],
      }),
    };
  }

  it('a bearer token with a foreign iss claim is skipped quietly, not logged as an error', () => {
    const {plugin, logger} = createPlugin();
    const handler = (plugin as any).apiJWTmiddleware(makeHelpers());
    const foreignToken = jwt.sign(
      {iss: 'https://token.actions.githubusercontent.com', sub: 'x'},
      'irrelevant-secret',
    );
    const req = makeReq({authorization: `Bearer ${foreignToken}`});
    let nextCalledWithError: Error | undefined | 'not-called' = 'not-called';
    handler(req, {}, (err?: Error) => {
      nextCalledWithError = err;
    });

    expect(nextCalledWithError).toBeUndefined();
    expect(logger.error).not.toHaveBeenCalled();
    expect(logger.debug).toHaveBeenCalledWith(
      expect.objectContaining({
        iss: 'https://token.actions.githubusercontent.com',
      }),
      expect.stringContaining('not one of ours'),
    );
  });

  it('a token with no iss claim that fails verification still logs at error (a real problem worth seeing)', () => {
    const {plugin, logger} = createPlugin();
    const handler = (plugin as any).apiJWTmiddleware(makeHelpers());
    // No `iss` claim, signed with the wrong secret -- this is the shape a
    // genuinely broken token (tampered, wrong secret after rotation) would
    // have, as opposed to a foreign token that was never meant for this
    // plugin at all.
    const noIssToken = jwt.sign({sub: 'x'}, 'wrong-secret');
    const req = makeReq({authorization: `Bearer ${noIssToken}`});
    // The next() wrapper always calls the real _next() with no arguments,
    // regardless of whether an internal error occurred (see its own
    // comments) -- the actual signal that verification failed is
    // req.remote_user.error, set inside the wrapper itself.
    handler(req, {}, () => {});

    expect((req.remote_user as {error?: string}).error).toBe(
      'unable to verify jwt bearer token',
    );
    expect(logger.error).toHaveBeenCalled();
  });

  it('a garbage (non-JWT) bearer token does not crash and still logs at error', () => {
    const {plugin, logger} = createPlugin();
    const handler = (plugin as any).apiJWTmiddleware(makeHelpers());
    const req = makeReq({authorization: 'Bearer garbage.not.a.jwt'});
    expect(() => {
      handler(req, {}, () => {});
    }).not.toThrow();

    expect((req.remote_user as {error?: string}).error).toBe(
      'unable to verify jwt bearer token',
    );
    expect(logger.error).toHaveBeenCalled();
  });
});
