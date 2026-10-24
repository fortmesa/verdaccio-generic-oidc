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
import type {Logger} from '@verdaccio/types';
import OidcPlugin from './index';

const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';

// ---------------------------------------------------------------------
// Fake OIDC issuer: real HTTP server, real RS256-signed ID tokens, real
// JWKS. It accepts any authorization code and any subject token (this is a
// test double, not a spec-compliant IdP), but gets the parts openid-client
// actually verifies (issuer, audience, signature, expiry, nonce) right for
// real, and checks a PKCE verifier against the challenge a test hands it.
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

interface IssuerState {
  claims: Record<string, unknown>;
  grantTypes: string[];
  // Echoed into the next ID token as its nonce claim, when echoNonce is set.
  nonce?: string;
  echoNonce: boolean;
  // When set, an authorization_code request must carry the matching verifier.
  codeChallenge?: string;
  tokenRequests: URLSearchParams[];
}

interface FakeIssuer {
  url: string;
  clientId: string;
  state: IssuerState;
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

function freshIssuerState(): IssuerState {
  return {
    claims: {preferred_username: 'alice'},
    grantTypes: ['authorization_code', TOKEN_EXCHANGE_GRANT],
    echoNonce: true,
    tokenRequests: [],
  };
}

function startFakeIssuer(clientId: string): Promise<FakeIssuer> {
  const holder: {state: IssuerState} = {state: freshIssuerState()};
  let issuerUrl = '';

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const state = holder.state;

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
          grant_types_supported: state.grantTypes,
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
        const params = new URLSearchParams(body);
        state.tokenRequests.push(params);
        res.setHeader('Content-Type', 'application/json');

        if (
          params.get('grant_type') === 'authorization_code' &&
          state.codeChallenge != null
        ) {
          const verifier = params.get('code_verifier') ?? '';
          const challenge = crypto
            .createHash('sha256')
            .update(verifier)
            .digest('base64url');
          if (challenge !== state.codeChallenge) {
            res.statusCode = 400;
            res.end(JSON.stringify({error: 'invalid_grant'}));
            return;
          }
        }

        res.end(
          JSON.stringify({
            access_token: randomSecret(),
            refresh_token: 'fake-refresh-token',
            id_token: signIdToken(issuerUrl, clientId, {
              ...state.claims,
              ...(state.echoNonce && state.nonce ? {nonce: state.nonce} : {}),
            }),
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
        get state() {
          return holder.state;
        },
        set state(value: IssuerState) {
          holder.state = value;
        },
        close: () => new Promise<void>(res => server.close(() => res())),
      });
    });
  });
}

// ---------------------------------------------------------------------
// Test scaffolding: a fake Verdaccio Logger/PluginOptions/auth (only the
// fields this plugin's code actually reads), and a helper to build a fresh
// plugin instance wired to the fake issuer above plus a real, throwaway
// filesystem storage directory.
// ---------------------------------------------------------------------

// Random per run, like every other secret these tests use.
const randomSecret = () => crypto.randomBytes(16).toString('hex');
const JWT_SECRET = randomSecret();
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
  } as unknown as Logger;
}

function makeAuth(overrides: Record<string, unknown> = {}): any {
  return {
    config: {secret: JWT_SECRET},
    authenticate: vi.fn(),
    changePassword: vi.fn(),
    allow_access: vi.fn(),
    add_user: vi.fn(),
    ...overrides,
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
  issuer.state = freshIssuerState();
});

const DEFAULT_SECURITY = {
  api: {jwt: {sign: {expiresIn: '30d'}}},
  web: {sign: {expiresIn: '7d'}},
};

function createPlugin(
  configOverrides: Record<string, unknown> = {},
  appConfigOverrides: Record<string, unknown> = {},
): {
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
    clientSecret: randomSecret(),
    scope: 'openid profile email',
    filesystem: {tokenPath: tmpDir},
    // Deliberately no `oidcPluginInstance` key at all (not even `undefined`)
    // -- OidcPlugin.getInstance() checks `'oidcPluginInstance' in this.config`,
    // a key-existence check, not a value check, so a present-but-undefined
    // key would still incorrectly short-circuit every method call.
    ...configOverrides,
  };
  const appOptions = {
    config: {
      secret: JWT_SECRET,
      security: DEFAULT_SECURITY,
      middlewares: {},
      ...appConfigOverrides,
    },
    logger,
  } as any;

  return {plugin: new OidcPlugin(config as any, appOptions), logger, config};
}

async function startServer(
  plugin: OidcPlugin,
  config: Record<string, unknown>,
  auth: any,
  {beforePlugin}: {beforePlugin?: express.RequestHandler} = {},
): Promise<{baseUrl: string; close(): Promise<void>}> {
  const app = express();
  app.disable('x-powered-by');
  if (beforePlugin) app.use(beforePlugin);
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

// Keeps what a browser would: the cookies the server set (paths aside --
// sending one to a route that doesn't read it changes nothing here).
class CookieJar {
  private cookies = new Map<string, string>();

  store(res: Response): void {
    for (const cookie of res.headers.getSetCookie()) {
      const [pair] = cookie.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (value === '' || /Max-Age=0/i.test(cookie)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }

  header(): string {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

// GETs loginUrl and POSTs the confirmation form back, the way a browser
// does when the person clicks Continue. Returns the IdP authorization URL
// it was sent to, with the fake issuer primed to echo its nonce and check
// its PKCE challenge.
async function confirmLogin(loginUrl: string, jar: CookieJar): Promise<URL> {
  const page = await fetch(loginUrl, {redirect: 'manual'});
  expect(page.status).toBe(200);
  jar.store(page);
  const csrf = /name="csrf" value="([^"]+)"/.exec(await page.text())?.[1];
  expect(csrf).toBeTruthy();

  const confirmed = await fetch(loginUrl, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Cookie: jar.header(),
    },
    body: new URLSearchParams({csrf: csrf!}).toString(),
  });
  expect(confirmed.status).toBe(302);
  jar.store(confirmed);
  return primeIssuer(new URL(confirmed.headers.get('location')!));
}

function primeIssuer(authorizeUrl: URL): URL {
  issuer.state.nonce = authorizeUrl.searchParams.get('nonce') ?? undefined;
  issuer.state.codeChallenge =
    authorizeUrl.searchParams.get('code_challenge') ?? undefined;
  return authorizeUrl;
}

function callbackUrl(baseUrl: string, state: string): URL {
  const url = new URL(`${baseUrl}/-/oidc/callback`);
  url.searchParams.set('state', state);
  url.searchParams.set('code', 'fake-authorization-code');
  return url;
}

// How many tokens are waiting in the filesystem store for doneUrl pickup.
// Checking storage directly is faster than a doneUrl poll that has to
// wait out its 10-second long-poll to say "nothing".
async function storedTokens(): Promise<number> {
  return (await fsp.readdir(tmpDir)).filter(f => f.endsWith('.token')).length;
}

async function pollDone(doneUrl: string, attempts = 20): Promise<string> {
  for (let i = 0; i < attempts; i++) {
    const doneRes = await fetch(doneUrl);
    const body = await doneRes.json();
    if (body.token) return body.token;
    await new Promise(r => setTimeout(r, 50));
  }
  throw new Error('login never completed');
}

// Drives the full npm/yarn web-login handshake against a running plugin
// server: POST /-/v1/login, confirm at loginUrl, follow the redirect
// straight to /-/oidc/callback (skipping the real browser round-trip to the
// fake issuer's own /authorize, which openid-client never calls
// server-side anyway), then poll /-/oidc/done for the npm token.
async function performLogin(baseUrl: string): Promise<{
  npmToken: string;
  callbackHtml: string;
  doneUrl: string;
}> {
  const loginRes = await fetch(`${baseUrl}/-/v1/login`, {method: 'POST'});
  const {loginUrl, doneUrl} = await loginRes.json();

  const jar = new CookieJar();
  const authorizeUrl = await confirmLogin(loginUrl, jar);
  const state = authorizeUrl.searchParams.get('state')!;

  const callbackRes = await fetch(callbackUrl(baseUrl, state), {
    headers: {Cookie: jar.header()},
  });
  expect(callbackRes.status).toBe(200);
  const callbackHtml = await callbackRes.text();

  return {npmToken: await pollDone(doneUrl), callbackHtml, doneUrl};
}

async function withServer(
  configOverrides: Record<string, unknown>,
  fn: (server: {baseUrl: string}, plugin: OidcPlugin) => Promise<void>,
  {
    appConfigOverrides,
    auth,
    beforePlugin,
  }: {
    appConfigOverrides?: Record<string, unknown>;
    auth?: any;
    beforePlugin?: express.RequestHandler;
  } = {},
): Promise<void> {
  const {plugin, config} = createPlugin(configOverrides, appConfigOverrides);
  const server = await startServer(plugin, config, auth ?? makeAuth(), {
    beforePlugin,
  });
  try {
    await fn(server, plugin);
  } finally {
    await server.close();
    plugin.close();
  }
}

describe('OidcPlugin: constructor', () => {
  it('throws when no storage backend is configured', () => {
    expect(() => createPlugin({filesystem: undefined})).toThrow(
      /invalid configuration/,
    );
  });

  it('needs only filesystem.tokenPath; a leftover sessionPath is ignored with a warning', () => {
    const {plugin, logger} = createPlugin({
      filesystem: {sessionPath: tmpDir, tokenPath: tmpDir},
    });
    expect(logger.warn).toHaveBeenCalledWith(
      {},
      'filesystem.sessionPath is no longer used',
    );
    plugin.close();
  });

  it('a second construction with the shared instance in its config returns that instance', () => {
    const {plugin} = createPlugin();
    const again = new OidcPlugin(
      {oidcPluginInstance: plugin} as any,
      {
        config: {},
        logger: makeLogger(),
      } as any,
    );
    expect(again).toBe(plugin);
    plugin.close();
  });

  it.each([
    ['a string', 'fortmesa.com'],
    ['an empty list', {hd: []}],
    ['an object value', {hd: {nested: true}}],
  ])('rejects requiredClaims given as %s', (_label, requiredClaims) => {
    expect(() => createPlugin({requiredClaims})).toThrow(/requiredClaims/);
  });
});

describe('OidcPlugin: full login flow (confidential client)', () => {
  it('logs in and issues a working npm token with no session id in it', async () => {
    await withServer({}, async server => {
      const {npmToken, callbackHtml} = await performLogin(server.baseUrl);

      const payload = jwt.verify(npmToken, JWT_SECRET) as Record<
        string,
        unknown
      >;
      expect(payload.name).toBe('alice');
      expect(payload.real_groups).toEqual([]);
      expect(payload).not.toHaveProperty('sid');
      expect(callbackHtml).toContain('alice');
    });
  });

  it('sends a nonce derived from the login request and checks it in the ID token', async () => {
    await withServer({}, async server => {
      const loginRes = await fetch(`${server.baseUrl}/-/v1/login`, {
        method: 'POST',
      });
      const {loginUrl} = await loginRes.json();
      const jar = new CookieJar();
      const authorizeUrl = await confirmLogin(loginUrl, jar);
      expect(authorizeUrl.searchParams.get('nonce')).toBeTruthy();

      // An ID token without that nonce is refused.
      issuer.state.echoNonce = false;
      const callbackRes = await fetch(
        callbackUrl(server.baseUrl, authorizeUrl.searchParams.get('state')!),
        {headers: {Cookie: jar.header()}},
      );
      expect(callbackRes.status).not.toBe(200);
    });
  });

  it('refuses a callback that carries an ID token but no authorization code', async () => {
    await withServer({}, async server => {
      const loginRes = await fetch(`${server.baseUrl}/-/v1/login`, {
        method: 'POST',
      });
      const {loginUrl, doneUrl} = await loginRes.json();
      const jar = new CookieJar();
      const authorizeUrl = await confirmLogin(loginUrl, jar);
      const state = authorizeUrl.searchParams.get('state')!;

      const url = new URL(`${server.baseUrl}/-/oidc/callback`);
      url.searchParams.set('state', state);
      url.searchParams.set(
        'id_token',
        signIdToken(issuer.url, CLIENT_ID, {
          preferred_username: 'mallory',
          nonce: authorizeUrl.searchParams.get('nonce'),
        }),
      );
      const callbackRes = await fetch(url, {headers: {Cookie: jar.header()}});
      expect(callbackRes.status).not.toBe(200);
      expect(doneUrl).toBeTruthy();
      expect(await storedTokens()).toBe(0);
    });
  });

  it('escapes a "</script>"-shaped username claim so it cannot break out of the callback page\'s inline <script> block', async () => {
    const payload = '</script><script>window.pwned=true</script>';
    issuer.state.claims = {preferred_username: payload};
    await withServer({}, async server => {
      const {callbackHtml} = await performLogin(server.baseUrl);

      // The raw HTML must never contain an actual "</script>" sequence
      // originating from the claim value -- only the two real <script>
      // tags this page itself renders.
      const scriptCloseCount = (callbackHtml.match(/<\/script>/g) ?? []).length;
      expect(scriptCloseCount).toBe(2);
      // The value must still be recoverable as the original string once
      // actually parsed as JS -- confirms this is an escape, not a filter
      // that mangles/drops the content. Only "<" needs escaping (it's the
      // one character the HTML parser's `</script` scan cares about) --
      // ">" is left as a literal character, same as JSON.stringify would
      // have produced.
      expect(callbackHtml).toContain('\\u003c/script>\\u003cscript>');
    });
  });

  it('extracts roles into real_groups per the configured claim', async () => {
    issuer.state.claims = {
      preferred_username: 'alice',
      resource_access: {[CLIENT_ID]: {roles: ['admin']}},
    };
    await withServer(
      {roles: {claim: 'resource_access', allowList: {[CLIENT_ID]: ['admin']}}},
      async server => {
        const {npmToken} = await performLogin(server.baseUrl);
        const payload = jwt.verify(npmToken, JWT_SECRET) as Record<
          string,
          unknown
        >;
        expect(payload.real_groups).toEqual([CLIENT_ID]);
      },
    );
  });

  it("falls back to a 7-day token when Verdaccio's security config sets no expiresIn", async () => {
    await withServer(
      {},
      async server => {
        const {npmToken} = await performLogin(server.baseUrl);
        const {iat, exp} = jwt.verify(npmToken, JWT_SECRET) as {
          iat: number;
          exp: number;
        };
        expect(exp - iat).toBe(7 * 24 * 60 * 60);
      },
      {appConfigOverrides: {security: {}}},
    );
  });
});

describe('OidcPlugin: full login flow (public/PKCE client)', () => {
  it('logs in without a client secret, with a PKCE verifier the IdP accepts', async () => {
    await withServer({clientSecret: undefined}, async server => {
      const {npmToken} = await performLogin(server.baseUrl);
      expect(jwt.verify(npmToken, JWT_SECRET)).toBeTruthy();

      // The fake issuer rejects the code unless S256(code_verifier) equals
      // the code_challenge the authorization URL carried.
      const codeRequest = issuer.state.tokenRequests.find(
        p => p.get('grant_type') === 'authorization_code',
      );
      expect(codeRequest?.get('code_verifier')).toBeTruthy();
      expect(issuer.state.codeChallenge).toBeTruthy();
    });
  });
});

describe('OidcPlugin: loginUrl confirmation page', () => {
  it('shows a confirmation page instead of redirecting, and cannot be framed', async () => {
    await withServer({}, async server => {
      const loginRes = await fetch(`${server.baseUrl}/-/v1/login`, {
        method: 'POST',
      });
      const {loginUrl} = await loginRes.json();
      const page = await fetch(loginUrl, {redirect: 'manual'});

      expect(page.status).toBe(200);
      expect(page.headers.get('content-type')).toMatch(/text\/html/);
      expect(page.headers.get('content-security-policy')).toContain(
        "frame-ancestors 'none'",
      );
      expect(page.headers.get('x-frame-options')).toBe('DENY');
      expect(page.headers.get('cache-control')).toBe('no-store');
      expect(await page.text()).toContain('<form method="POST"');
    });
  });

  it('refuses a confirmation POST without the cookie its page set (a form another site submitted)', async () => {
    await withServer({}, async server => {
      const loginRes = await fetch(`${server.baseUrl}/-/v1/login`, {
        method: 'POST',
      });
      const {loginUrl} = await loginRes.json();
      const page = await fetch(loginUrl);
      const csrf = /name="csrf" value="([^"]+)"/.exec(await page.text())![1];

      const forged = await fetch(loginUrl, {
        method: 'POST',
        redirect: 'manual',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: new URLSearchParams({csrf}).toString(),
      });
      expect(forged.status).toBe(403);

      const jar = new CookieJar();
      jar.store(page);
      const wrongValue = await fetch(loginUrl, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Cookie: jar.header(),
        },
        body: new URLSearchParams({csrf: 'something-else'}).toString(),
      });
      expect(wrongValue.status).toBe(403);
    });
  });

  it('refuses a callback in a browser that did not start the login (a handed-over callback URL)', async () => {
    await withServer({}, async server => {
      const loginRes = await fetch(`${server.baseUrl}/-/v1/login`, {
        method: 'POST',
      });
      const {loginUrl, doneUrl} = await loginRes.json();
      const authorizeUrl = await confirmLogin(loginUrl, new CookieJar());

      const callbackRes = await fetch(
        callbackUrl(server.baseUrl, authorizeUrl.searchParams.get('state')!),
      );
      expect(callbackRes.status).toBe(403);
      expect(doneUrl).toBeTruthy();
      expect(await storedTokens()).toBe(0);
    });
  });
});

describe('OidcPlugin: doneUrl', () => {
  it('hands the token out once: picking it up removes it from storage', async () => {
    await withServer({}, async server => {
      await performLogin(server.baseUrl);
      expect(await storedTokens()).toBe(0);
    });
  });

  it('answers a poll after the pickup with 202 once its long-poll runs out', async () => {
    await withServer({}, async server => {
      const {doneUrl} = await performLogin(server.baseUrl);
      const again = await fetch(doneUrl);
      expect(again.status).toBe(202);
    });
  }, 20_000);

  it('rejects a forged loginRequestId on /-/oidc/login and /-/oidc/done', async () => {
    await withServer({}, async server => {
      for (const route of ['login', 'done']) {
        const res = await fetch(`${server.baseUrl}/-/oidc/${route}/forged-id`);
        expect(res.status).toBe(400);
      }
    });
  });
});

describe('OidcPlugin: CORS on the login routes', () => {
  it("strips Verdaccio's Access-Control-Allow-Origin from /-/v1/login, loginUrl and doneUrl", async () => {
    await withServer(
      {},
      async server => {
        const loginRes = await fetch(`${server.baseUrl}/-/v1/login`, {
          method: 'POST',
        });
        expect(loginRes.headers.get('access-control-allow-origin')).toBeNull();
        const {loginUrl} = await loginRes.json();
        // An invalid id makes doneUrl answer at once instead of long-polling;
        // it goes through the same route.
        for (const url of [loginUrl, `${server.baseUrl}/-/oidc/done/x`]) {
          const res = await fetch(url, {redirect: 'manual'});
          expect(res.headers.get('access-control-allow-origin')).toBeNull();
        }
        // Other routes keep it.
        const other = await fetch(`${server.baseUrl}/-/ping`);
        expect(other.headers.get('access-control-allow-origin')).toBe('*');
      },
      {
        beforePlugin: (req, res, next) => {
          res.set('Access-Control-Allow-Origin', '*');
          next();
        },
      },
    );
  });
});

describe('OidcPlugin: requiredClaims', () => {
  const GATE = {hd: 'fortmesa.com', email_verified: true};

  it('lets a login through when every required claim matches', async () => {
    issuer.state.claims = {
      preferred_username: 'alice',
      hd: 'fortmesa.com',
      email_verified: true,
    };
    await withServer({requiredClaims: GATE}, async server => {
      const {npmToken} = await performLogin(server.baseUrl);
      expect(jwt.verify(npmToken, JWT_SECRET)).toBeTruthy();
    });
  });

  it.each([
    ['a different domain', {hd: 'gmail.com', email_verified: true}],
    ['a missing claim', {email_verified: true}],
    ['"true" as a string', {hd: 'fortmesa.com', email_verified: 'true'}],
  ])(
    'refuses the callback with 403 and stores no token for %s',
    async (_label, claims) => {
      issuer.state.claims = {preferred_username: 'alice', ...claims};
      await withServer({requiredClaims: GATE}, async server => {
        const loginRes = await fetch(`${server.baseUrl}/-/v1/login`, {
          method: 'POST',
        });
        const {loginUrl, doneUrl} = await loginRes.json();
        const jar = new CookieJar();
        const authorizeUrl = await confirmLogin(loginUrl, jar);
        const callbackRes = await fetch(
          callbackUrl(server.baseUrl, authorizeUrl.searchParams.get('state')!),
          {headers: {Cookie: jar.header()}},
        );
        expect(callbackRes.status).toBe(403);
        expect(doneUrl).toBeTruthy();
        expect(await storedTokens()).toBe(0);
      });
    },
  );

  it('accepts any listed value, matches any element of an array claim, and follows dot-paths', async () => {
    issuer.state.claims = {
      preferred_username: 'alice',
      groups: ['users', 'npm-publishers'],
      realm_access: {roles: ['npm']},
    };
    await withServer(
      {
        requiredClaims: {
          groups: ['admins', 'npm-publishers'],
          'realm_access.roles': 'npm',
        },
      },
      async server => {
        const {npmToken} = await performLogin(server.baseUrl);
        expect(jwt.verify(npmToken, JWT_SECRET)).toBeTruthy();
      },
    );
  });
});

describe('OidcPlugin: GET /-/oidc/start (web UI sign-in)', () => {
  it('goes straight to the IdP, binds the browser, and leaves no token for doneUrl', async () => {
    await withServer({}, async server => {
      const jar = new CookieJar();
      const startRes = await fetch(`${server.baseUrl}/-/oidc/start`, {
        redirect: 'manual',
      });
      expect(startRes.status).toBe(302);
      jar.store(startRes);
      const authorizeUrl = primeIssuer(
        new URL(startRes.headers.get('location')!),
      );
      expect(authorizeUrl.origin + authorizeUrl.pathname).toBe(
        `${issuer.url}/authorize`,
      );
      const state = authorizeUrl.searchParams.get('state')!;

      const callbackRes = await fetch(callbackUrl(server.baseUrl, state), {
        headers: {Cookie: jar.header()},
      });
      expect(callbackRes.status).toBe(200);
      const callbackHtml = await callbackRes.text();

      // Same response as the CLI-triggered flow: attempts window.close()
      // (a harmless no-op here, since this tab wasn't opened via script),
      // but must NOT auto-redirect -- that would be a false success signal
      // for a CLI/browser-launch caller, which looks identical to this at
      // the HTTP level. A visible, clickable link covers the human case
      // instead of an assumption about which caller this is.
      expect(callbackHtml).toContain('alice');
      expect(callbackHtml).toContain('window.close()');
      expect(callbackHtml).not.toContain('window.location.href');
      expect(callbackHtml).toContain('href="/"');

      // A web sign-in id is not a CLI login: doneUrl refuses it.
      const done = await fetch(`${server.baseUrl}/-/oidc/done/${state}`);
      expect(done.status).toBe(400);
    });
  });
});

describe('OidcPlugin: accessTokenAuth', () => {
  it('disables /-/v1/login and /-/oidc/start when accessTokenAuth is true', async () => {
    await withServer({accessTokenAuth: true}, async server => {
      const login = await fetch(`${server.baseUrl}/-/v1/login`, {
        method: 'POST',
      });
      expect(login.status).toBe(404);
      const start = await fetch(`${server.baseUrl}/-/oidc/start`, {
        redirect: 'manual',
      });
      expect(start.status).toBe(404);
    });
  });
});

describe('OidcPlugin: token exchange (PUT /-/user/...)', () => {
  function putUser(baseUrl: string, name: string, password: string) {
    return fetch(`${baseUrl}/-/user/org.couchdb.user:${name}`, {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name, password}),
    });
  }
  // An access token as this test's IdP would issue one.
  const issuerAccessToken = () =>
    signIdToken(issuer.url, 'some-resource', {sub: 'alice'});

  async function ready(plugin: OidcPlugin): Promise<void> {
    await (plugin as any).clientPromise;
  }

  it('exchanges an access token from this IdP for an npm token', async () => {
    await withServer({}, async (server, plugin) => {
      await ready(plugin);
      const res = await putUser(server.baseUrl, 'alice', issuerAccessToken());
      expect(res.status).toBe(201);
      const {token} = await res.json();
      const payload = jwt.verify(token, JWT_SECRET) as Record<string, unknown>;
      expect(payload.name).toBe('alice');
      expect(
        issuer.state.tokenRequests.some(
          p => p.get('grant_type') === TOKEN_EXCHANGE_GRANT,
        ),
      ).toBe(true);
    });
  });

  it.each([
    ['an htpasswd password', () => 'correct horse battery staple'],
    [
      'a JWT from another issuer',
      () => jwt.sign({iss: 'https://elsewhere.example'}, randomSecret()),
    ],
  ])(
    'passes %s on to the next route without sending it to the IdP',
    async (_label, password) => {
      await withServer({}, async (server, plugin) => {
        await ready(plugin);
        const res = await putUser(server.baseUrl, 'alice', password());
        // The test app has no Verdaccio route behind this one.
        expect(res.status).toBe(404);
        expect(issuer.state.tokenRequests).toHaveLength(0);
      });
    },
  );

  it('passes on when the IdP does not advertise token exchange', async () => {
    issuer.state.grantTypes = ['authorization_code'];
    await withServer({}, async (server, plugin) => {
      await ready(plugin);
      const res = await putUser(server.baseUrl, 'alice', issuerAccessToken());
      expect(res.status).toBe(404);
      expect(issuer.state.tokenRequests).toHaveLength(0);
    });
  });

  it('rejects when the URL user and body user do not match', async () => {
    await withServer({}, async (server, plugin) => {
      await ready(plugin);
      const res = await fetch(
        `${server.baseUrl}/-/user/org.couchdb.user:alice`,
        {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({name: 'bob', password: issuerAccessToken()}),
        },
      );
      expect(res.status).toBe(401);
    });
  });

  it('rejects when the token belongs to a different user', async () => {
    issuer.state.claims = {preferred_username: 'someone-else'};
    await withServer({}, async (server, plugin) => {
      await ready(plugin);
      const res = await putUser(server.baseUrl, 'alice', issuerAccessToken());
      expect(res.status).toBe(401);
    });
  });

  it('applies requiredClaims to the exchanged identity', async () => {
    issuer.state.claims = {preferred_username: 'alice', hd: 'gmail.com'};
    await withServer(
      {requiredClaims: {hd: 'fortmesa.com'}},
      async (server, plugin) => {
        await ready(plugin);
        const res = await putUser(server.baseUrl, 'alice', issuerAccessToken());
        expect(res.status).toBe(403);
      },
    );
  });

  it("limits exchange attempts per client to Verdaccio's userRateLimit", async () => {
    await withServer(
      {},
      async (server, plugin) => {
        await ready(plugin);
        for (let i = 0; i < 2; i++) {
          const res = await putUser(
            server.baseUrl,
            'alice',
            issuerAccessToken(),
          );
          expect(res.status).toBe(201);
        }
        const limited = await putUser(
          server.baseUrl,
          'alice',
          issuerAccessToken(),
        );
        expect(limited.status).toBe(429);
      },
      {appConfigOverrides: {userRateLimit: {windowMs: 60_000, max: 2}}},
    );
  });
});

describe('OidcPlugin: authenticate()', () => {
  it('declines every credential at once, so the chain moves on to the next plugin', () => {
    const {plugin} = createPlugin();
    const cb = vi.fn();
    plugin.authenticate('alice', 'anything-at-all', cb);
    expect(cb).toHaveBeenCalledWith(null, false);
    plugin.close();
  });
});

describe('OidcPlugin: apiJWTmiddleware()', () => {
  function makeReq(headers: Record<string, string>) {
    return {
      headers,
      pause: vi.fn(),
      resume: vi.fn(),
    } as any;
  }
  function makeRes() {
    return {locals: {}} as any;
  }
  function makeHelpers() {
    return {
      createAnonymousRemoteUser: () => ({
        name: undefined,
        groups: [],
        real_groups: [],
      }),
      createRemoteUser: (name: string, real_groups: string[]) => ({
        name,
        real_groups,
        groups: [...real_groups, '$all', '$authenticated'],
      }),
    };
  }

  describe('Bearer tokens', () => {
    it('a bearer token with a foreign iss claim is skipped quietly, not logged as an error', () => {
      const {plugin, logger} = createPlugin();
      const handler = (plugin as any).apiJWTmiddleware(makeHelpers());
      const foreignToken = jwt.sign(
        {iss: 'https://token.actions.githubusercontent.com', sub: 'x'},
        randomSecret(),
      );
      const req = makeReq({authorization: `Bearer ${foreignToken}`});
      let nextCalledWithError: Error | undefined | 'not-called' = 'not-called';
      handler(req, makeRes(), (err?: Error) => {
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
      const noIssToken = jwt.sign({sub: 'x'}, randomSecret());
      const req = makeReq({authorization: `Bearer ${noIssToken}`});
      // The next() wrapper always calls the real _next() with no arguments,
      // regardless of whether an internal error occurred (see its own
      // comments) -- the actual signal that verification failed is
      // req.remote_user.error, set inside the wrapper itself.
      handler(req, makeRes(), () => {});

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
        handler(req, makeRes(), () => {});
      }).not.toThrow();

      expect((req.remote_user as {error?: string}).error).toBe(
        'unable to verify jwt bearer token',
      );
      expect(logger.error).toHaveBeenCalled();
    });

    it('a valid, own-issued token authenticates synchronously from its own claims', () => {
      const {plugin} = createPlugin();
      const handler = (plugin as any).apiJWTmiddleware(makeHelpers());
      const validToken = jwt.sign(
        {name: 'alice', real_groups: ['fortmesa.com']},
        JWT_SECRET,
      );
      const req = makeReq({authorization: `Bearer ${validToken}`});
      const res = makeRes();
      let nextCalled = false;
      // No async gap: an async gap here breaks Verdaccio's own web-UI route
      // dispatch (reproduced directly against a real Verdaccio server) --
      // this asserts next() fires within the same synchronous call, not
      // just eventually.
      handler(req, res, () => {
        nextCalled = true;
      });

      expect(nextCalled).toBe(true);
      expect((req.remote_user as {error?: string}).error).toBeUndefined();
      expect(req.remote_user.name).toBe('alice');
      expect(req.remote_user.real_groups).toEqual(['fortmesa.com']);
      expect(req.remote_user).not.toHaveProperty('token');
      expect(res.locals.remote_user).toBeDefined();
    });

    it("keeps a generated token's key, which Verdaccio's router checks revocation, read-only and CIDR limits under", () => {
      const {plugin} = createPlugin();
      const handler = (plugin as any).apiJWTmiddleware(makeHelpers());
      const generated = jwt.sign(
        {name: 'alice', real_groups: [], token: {key: 'abc123'}},
        JWT_SECRET,
      );
      const req = makeReq({authorization: `Bearer ${generated}`});
      handler(req, makeRes(), () => {});

      expect(req.remote_user.name).toBe('alice');
      expect(req.remote_user.token).toEqual({key: 'abc123'});
    });

    it('accepts a token whose nbf is a few seconds ahead, as from a replica with a faster clock', () => {
      const {plugin} = createPlugin();
      const handler = (plugin as any).apiJWTmiddleware(makeHelpers());
      const early = jwt.sign({name: 'alice', real_groups: []}, JWT_SECRET, {
        notBefore: 5,
      });
      const req = makeReq({authorization: `Bearer ${early}`});
      handler(req, makeRes(), () => {});

      expect((req.remote_user as {error?: string}).error).toBeUndefined();
      expect(req.remote_user.name).toBe('alice');
    });

    it('a malformed authorization header is rejected, and the header never reaches the log', () => {
      const {plugin, logger} = createPlugin();
      const handler = (plugin as any).apiJWTmiddleware(makeHelpers());
      const req = makeReq({authorization: 'bare-secret-token-value'});
      handler(req, makeRes(), () => {});

      expect((req.remote_user as {error?: string}).error).toBe(
        'malformed authorization header',
      );
      expect(JSON.stringify((logger.warn as any).mock.calls)).not.toContain(
        'bare-secret-token-value',
      );
    });
  });

  describe('Basic-Auth scheme delegation', () => {
    // This plugin's apiJWTmiddleware entirely replaces Verdaccio's own
    // (Verdaccio calls a plugin-provided one instead of its default, never
    // both) -- without delegating Basic-Auth to the real, multi-plugin auth
    // chain here, no sibling plugin configured alongside this one (htpasswd,
    // or any other) could ever authenticate anything. Confirmed directly
    // against a real deployment: removing this plugin restored htpasswd's
    // own Basic-Auth login.
    function basicAuthHeader(credentials: string): string {
      return `Basic ${Buffer.from(credentials).toString('base64')}`;
    }

    function setUp(
      authenticateImpl: (
        user: string,
        password: string,
        cb: (err: Error | null, user: unknown) => void,
      ) => void,
    ) {
      const {plugin} = createPlugin();
      const authenticate = vi.fn(authenticateImpl);
      plugin.register_middlewares(express() as any, makeAuth({authenticate}));
      const handler = (plugin as any).apiJWTmiddleware(makeHelpers());
      return {plugin, authenticate, handler};
    }

    it('delegates a Basic-Auth request to the real auth chain and adopts its remote_user on success', () => {
      const authChainUser = {
        name: 'htpasswd-user',
        groups: ['htpasswd-user', '$all', '$authenticated'],
        real_groups: [],
      };
      const {authenticate, handler} = setUp((user, password, cb) =>
        cb(null, authChainUser),
      );
      const req = makeReq({
        authorization: basicAuthHeader('htpasswd-user:correct-password'),
      });
      let nextCalled = false;
      handler(req, makeRes(), () => {
        nextCalled = true;
      });

      expect(authenticate).toHaveBeenCalledWith(
        'htpasswd-user',
        'correct-password',
        expect.any(Function),
      );
      expect(nextCalled).toBe(true);
      expect(req.remote_user).toBe(authChainUser);
    });

    it('pauses the request for the asynchronous auth chain and resumes it before moving on', async () => {
      let finish!: () => void;
      const {handler} = setUp((user, password, cb) => {
        finish = () => cb(null, false);
      });
      const req = makeReq({authorization: basicAuthHeader('someuser:pw')});
      const next = vi.fn();
      handler(req, makeRes(), next);

      expect(req.pause).toHaveBeenCalledTimes(1);
      expect(req.resume).not.toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
      finish();
      expect(req.resume).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('keeps the token key from the JSON form of Basic credentials, as Verdaccio does', () => {
      const user = {name: 'alice', groups: [], real_groups: []};
      const {authenticate, handler} = setUp((u, p, cb) => cb(null, user));
      const req = makeReq({
        authorization: basicAuthHeader(
          JSON.stringify({user: 'alice', password: 'pw', tokenKey: 'k1'}),
        ),
      });
      handler(req, makeRes(), () => {});

      expect(authenticate).toHaveBeenCalledWith(
        'alice',
        'pw',
        expect.any(Function),
      );
      expect(req.remote_user.token).toEqual({key: 'k1'});
    });

    it('a password containing a colon is preserved whole, not truncated at the first colon', () => {
      const {authenticate, handler} = setUp((user, password, cb) =>
        cb(null, false),
      );
      const req = makeReq({
        authorization: basicAuthHeader('someuser:pass:with:colons'),
      });
      handler(req, makeRes(), () => {});

      expect(authenticate).toHaveBeenCalledWith(
        'someuser',
        'pass:with:colons',
        expect.any(Function),
      );
    });

    it('rejects Basic credentials with no colon without calling the auth chain', () => {
      const {authenticate, handler} = setUp((user, password, cb) =>
        cb(null, false),
      );
      const req = makeReq({authorization: basicAuthHeader('no-colon-here')});
      handler(req, makeRes(), () => {});

      expect(authenticate).not.toHaveBeenCalled();
      expect((req.remote_user as {error?: string}).error).toBe(
        'malformed basic credentials',
      );
    });

    it('stays anonymous, without an error, when the auth chain rejects the credential', () => {
      const {handler} = setUp((user, password, cb) => cb(null, false));
      const req = makeReq({
        authorization: basicAuthHeader('someuser:wrong-password'),
      });
      handler(req, makeRes(), () => {});

      expect((req.remote_user as {error?: string}).error).toBeUndefined();
      expect(req.remote_user.name).toBeUndefined();
    });

    it('propagates a real error from the auth chain', () => {
      const {handler} = setUp((user, password, cb) =>
        cb(new Error('storage unavailable'), false),
      );
      const req = makeReq({authorization: basicAuthHeader('someuser:x')});
      handler(req, makeRes(), () => {});

      expect((req.remote_user as {error?: string}).error).toBe(
        'storage unavailable',
      );
      expect(req.resume).toHaveBeenCalled();
    });

    it('fails closed with a clear error if register_middlewares never ran', () => {
      const {plugin} = createPlugin();
      const handler = (plugin as any).apiJWTmiddleware(makeHelpers());
      const req = makeReq({authorization: basicAuthHeader('someuser:x')});
      expect(() => {
        handler(req, makeRes(), () => {});
      }).not.toThrow();

      expect((req.remote_user as {error?: string}).error).toBe(
        'authentication is not ready',
      );
    });
  });
});
