'use strict';

// Drives REAL yarn 3.x/4.x binaries (via corepack) against a real,
// throwaway project with this plugin's real built bundle imported -- not a
// simulated hook call. Separate from any future fast/mocked unit test since
// this activates real yarn releases and spins up a real (local, fake) HTTP
// registry.
//
// Yarn 2.x is deliberately NOT tested here -- confirmed directly (0 matches
// for both "wrapNetworkRequest" and "getNpmAuthenticationHeader" in yarn
// 2.4.3's own bundled yarn.js, vs 1 match each in 3.8.7 and 2/1 in 4.17.0)
// that BOTH hooks this plugin depends on don't exist there at all.
// `yarn plugin import` still SUCCEEDS on 2.x with no error -- a silent
// no-op, not a loud failure -- but 2.x support isn't a real requirement
// here, matching the same decision already made for yarnstatic's own
// plugins (see fortmesa/yarnstatic's plugins/*/test/cli-real.js).
//
// Test design: this plugin's own login handshake (browser + polling
// doneUrl) only ever runs when isInteractive() is true (a real TTY, no CI
// env var) -- see sources/loginHandshake.ts. Every automated test harness
// is exactly the "non-interactive" case the plugin is designed to no-op
// in, so this test verifies THAT behavior precisely (deterministic, no
// timeouts/polling needed) rather than trying to fake a browser handshake:
//   Scenario A ("no token configured"): getNpmAuthenticationHeader defers
//     (ensureLogin returns undefined -- non-interactive), so Yarn's own
//     preflight check refuses to send the request at all ("No
//     authentication configured for request", YN0033) -- confirmed
//     directly, this makes ZERO requests to the fake registry. Only
//     checked once (via `add`) since this path is fully generic --
//     getNpmAuthenticationHeader and Yarn's own preflight behave
//     identically regardless of which command triggered them.
//   Scenario B ("a stale token already configured"): Yarn's preflight
//     passes (a token IS configured, so it does attempt the request), the
//     fake registry always 401s, wrapNetworkRequest's retry-on-401 path
//     fires, calls refreshLogin, which ALSO returns undefined
//     (non-interactive) rather than opening a browser -- confirmed
//     directly: the fake registry sees the original request (proving
//     interception happened) and, critically, zero requests to
//     "/-/v1/login" (proving the login handshake was correctly skipped),
//     and the command fails fast with "Invalid authentication", not a
//     5-minute hang waiting on POLL_TIMEOUT_MS. Checked against `add`,
//     `npm whoami`, `npm publish`, and `npm audit` -- see the
//     REGISTRY_COMMANDS comment below for why those four and not every
//     `yarn npm` subcommand.
// All of this was verified by hand against real yarn 3.8.7 and 4.17.0
// before being encoded here; the exact error messages/codes (YN0033,
// YN0041) are what real Yarn actually printed, not invented. The
// hand-verification also covered `npm info`, `npm tag add/list`, and
// `npm stage list` (all fire both hooks identically) and `npm logout`
// (makes no network call at all, nothing to cover) -- not encoded as
// permanent checks below since they'd be redundant with the four that are:
// every `yarn npm` subcommand that touches the registry goes through the
// exact same shared @yarnpkg/plugin-npm HTTP/auth-header pipeline these
// two hooks are wired into, not a per-command reimplementation, so testing
// one read (whoami), one write (publish), and one bulk-query (audit)
// operation is representative of the whole surface, not just install/add.
//
// IMPORTANT: the fake registry below runs its own http.Server IN THIS SAME
// PROCESS. Learned the hard way while building this same style of test for
// yarnstatic's yarn-plugin-yarnstatic-s3: execFileSync (or any *Sync
// child_process call) blocks the entire Node.js event loop for as long as
// the child runs, so an in-process fake server can never accept/answer the
// child's connection and the child hangs forever waiting on a response
// nothing will ever send. Using the async execFile (via util.promisify)
// keeps this process's event loop running while awaiting the child, which
// is what lets the fake registry actually accept and answer requests.
//
// Run with:
//   node test/cli-real.js
// (separate from any fast/mocked test -- this activates real yarn releases
// via corepack on first run.)

const assert = require('node:assert/strict');
const http = require('node:http');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFile, execFileSync} = require('node:child_process');
const {promisify} = require('node:util');

const execFileAsync = promisify(execFile);

// Every yarn this test runs gets its own HOME, so none of them reads the
// real ~/.yarnrc.yml (registry credentials, settings an older Yarn
// rejects) and nothing the plugin persists lands there. COREPACK_HOME stays
// put, so the already-downloaded Yarn releases are reused.
function isolatedEnv(extra = {}) {
  const env = {
    ...process.env,
    HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'oidc-login-home-')),
    COREPACK_HOME:
      process.env.COREPACK_HOME ||
      path.join(os.homedir(), '.cache', 'node', 'corepack'),
    ...extra,
  };
  delete env.CI;
  return env;
}

const PLUGIN_BUNDLE = path.join(
  __dirname,
  '..',
  'bundles',
  '@yarnpkg',
  'plugin-oidc-login.js',
);

const TEST_PACKAGE = 'is-odd';
const TEST_VERSION = '3.0.1';

const YARN_VERSIONS = [
  {version: '3.8.7', major: 3},
  {version: '4.18.1', major: 4},
];

// Every `yarn npm` subcommand that actually touches the registry was
// verified by hand to fire both hooks identically (audit, info, publish,
// tag add/list, whoami, stage list) -- confirmed via a debug-instrumented
// copy of this plugin logging from inside both hooks, not just inferred
// from error text. `logout` makes no network call at all (nothing to
// cover). These four are encoded as permanent regression checks: `add`
// (the original install/fetch path), plus one read (`whoami`), one write
// (`publish`), and one bulk-query (`audit`) -- representative of the whole
// `@yarnpkg/plugin-npm` surface without redundantly re-testing every
// subcommand that shares the exact same underlying code path.
const REGISTRY_COMMANDS = [
  {
    label: 'add',
    args: ['add', `${TEST_PACKAGE}@${TEST_VERSION}`],
    needsInstall: false,
  },
  {label: 'npm whoami', args: ['npm', 'whoami'], needsInstall: false},
  // Both need a resolved lockfile first -- confirmed directly, both refuse
  // to run against a bare, unresolved workspace ("doesn't seem to be
  // present in your lockfile").
  {label: 'npm publish', args: ['npm', 'publish'], needsInstall: true},
  {label: 'npm audit', args: ['npm', 'audit'], needsInstall: true},
];

// Always 401s, whatever the request -- this plugin's own docs describe it
// degrading silently against any registry that doesn't implement its
// POST /-/v1/login handshake, so a bare always-401 server is enough to
// exercise both scenarios without needing to actually implement that
// endpoint.
function startFake401Server() {
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push({method: req.method, url: req.url});
    res.writeHead(401, {'content-type': 'application/json'});
    res.end(JSON.stringify({error: 'unauthorized'}));
  });
  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => resolve({server, requests}));
  });
}

async function runYarn(yarnVersion, projectDir, args, env) {
  try {
    const {stdout, stderr} = await execFileAsync(
      'corepack',
      ['yarn@' + yarnVersion, ...args],
      {
        cwd: projectDir,
        env,
        encoding: 'utf8',
      },
    );
    return {ok: true, output: stdout + stderr};
  } catch (err) {
    return {ok: false, output: (err.stdout || '') + (err.stderr || '')};
  }
}

function writeProjectFiles(projectDir, version, registryUrl, {withStaleToken}) {
  fs.writeFileSync(
    path.join(projectDir, 'package.json'),
    // version is only actually required for the `npm publish` check below,
    // but there's no harm giving every project one -- keeps this one
    // function usable for all four command checks instead of needing a
    // publish-specific variant.
    JSON.stringify({
      name: '@cli-real-test/pkg',
      version: '1.0.0',
      packageManager: `yarn@${version}`,
    }),
  );
  const registryConfig = {
    npmAlwaysAuth: true,
    ...(withStaleToken ? {npmAuthToken: 'stale-token-value'} : {}),
  };
  const yarnrc = {
    nodeLinker: 'node-modules',
    npmRegistryServer: registryUrl,
    // Yarn refuses to talk to a plain-http registry at all otherwise
    // ("Unsafe http requests must be explicitly whitelisted") -- confirmed
    // directly. Only relevant to this test's fake local server; a real
    // deployment uses https.
    unsafeHttpWhitelist: ['127.0.0.1'],
    npmRegistries: {[registryUrl]: registryConfig},
  };
  fs.writeFileSync(path.join(projectDir, '.yarnrc.yml'), toYaml(yarnrc));
}

// Minimal, purpose-built YAML writer -- this project's own config shape
// (strings, booleans, one level of nesting, one array of strings) doesn't
// need a real YAML library just to generate a throwaway test fixture.
function toYaml(obj, indent = 0) {
  const pad = '  '.repeat(indent);
  const lines = [];
  for (const [key, value] of Object.entries(obj)) {
    if (Array.isArray(value)) {
      lines.push(`${pad}${key}:`);
      for (const item of value) lines.push(`${pad}  - ${JSON.stringify(item)}`);
    } else if (value && typeof value === 'object') {
      lines.push(`${pad}${JSON.stringify(key)}:`);
      lines.push(toYaml(value, indent + 1));
    } else {
      lines.push(`${pad}${key}: ${JSON.stringify(value)}`);
    }
  }
  return lines.join('\n');
}

// Scenario C: a registry that implements the web-login handshake and only
// accepts the token it issues. loginUrl stands in for the browser page:
// requesting it completes the login, which the fake xdg-open below does.
// Every metadata and tarball request needs `Bearer fresh-token`.
function startFakeLoginRegistry(packages) {
  const requests = [];
  const completed = new Set();
  let logins = 0;
  const server = http.createServer((req, res) => {
    requests.push({method: req.method, url: req.url});
    const base = `http://127.0.0.1:${server.address().port}`;
    const json = (status, body) => {
      res.writeHead(status, {'content-type': 'application/json'});
      res.end(JSON.stringify(body));
    };

    if (req.method === 'POST' && req.url === '/-/v1/login') {
      logins += 1;
      const id = String(logins);
      return json(200, {
        loginUrl: `${base}/-/fake/login/${id}`,
        doneUrl: `${base}/-/fake/done/${id}`,
      });
    }
    const login = /^\/-\/fake\/login\/(\d+)$/.exec(req.url);
    if (login) {
      completed.add(login[1]);
      return json(200, {});
    }
    const done = /^\/-\/fake\/done\/(\d+)$/.exec(req.url);
    if (done) {
      return completed.has(done[1])
        ? json(200, {token: 'fresh-token'})
        : json(202, {});
    }

    if (req.headers.authorization !== 'Bearer fresh-token') {
      return json(401, {error: 'unauthorized'});
    }
    for (const pkg of packages) {
      if (req.url === `/${pkg.name}`) {
        return json(200, {
          name: pkg.name,
          'dist-tags': {latest: pkg.version},
          // Old enough for Yarn's default npmMinimalAgeGate.
          time: {
            created: '2020-01-01T00:00:00.000Z',
            modified: '2020-01-01T00:00:00.000Z',
            [pkg.version]: '2020-01-01T00:00:00.000Z',
          },
          versions: {
            [pkg.version]: {
              name: pkg.name,
              version: pkg.version,
              dist: {
                tarball: `${base}/${pkg.name}/-/${pkg.name}-${pkg.version}.tgz`,
                shasum: pkg.shasum,
                integrity: pkg.integrity,
              },
            },
          },
        });
      }
      if (req.url === `/${pkg.name}/-/${pkg.name}-${pkg.version}.tgz`) {
        res.writeHead(200, {'content-type': 'application/octet-stream'});
        return res.end(pkg.tarball);
      }
    }
    json(404, {error: 'not found'});
  });
  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () =>
      resolve({server, requests, loginCount: () => logins}),
    );
  });
}

function makeFakePackage(name, version) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oidc-login-pkg-'));
  try {
    fs.mkdirSync(path.join(dir, 'package'));
    fs.writeFileSync(
      path.join(dir, 'package', 'package.json'),
      JSON.stringify({name, version}),
    );
    execFileSync('tar', [
      'czf',
      path.join(dir, 'out.tgz'),
      '-C',
      dir,
      'package',
    ]);
    const tarball = fs.readFileSync(path.join(dir, 'out.tgz'));
    return {
      name,
      version,
      tarball,
      shasum: crypto.createHash('sha1').update(tarball).digest('hex'),
      integrity: `sha512-${crypto.createHash('sha512').update(tarball).digest('base64')}`,
    };
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
}

// The plugin only logs in from a terminal (process.stdout.isTTY, no CI), so
// yarn runs under script(1) for a pseudo-terminal.
async function runYarnInTerminal(yarnVersion, projectDir, args, env) {
  const command = ['corepack', `yarn@${yarnVersion}`, ...args]
    .map(arg => `'${arg.replace(/'/g, "'\\''")}'`)
    .join(' ');
  try {
    const {stdout} = await execFileAsync(
      'script',
      ['-q', '-e', '-c', command, '/dev/null'],
      {cwd: projectDir, env, encoding: 'utf8'},
    );
    return {ok: true, output: stdout};
  } catch (err) {
    return {ok: false, output: (err.stdout || '') + (err.stderr || '')};
  }
}

async function main() {
  let passed = 0;

  async function check(name, fn) {
    try {
      await fn();
      passed++;
      console.log(`PASS: ${name}`);
    } catch (err) {
      console.error(`FAIL: ${name}`);
      console.error(err);
      process.exitCode = 1;
    }
  }

  if (!fs.existsSync(PLUGIN_BUNDLE)) {
    console.error(
      `Plugin bundle not found at ${PLUGIN_BUNDLE} -- run "yarn build" first.`,
    );
    process.exit(1);
  }

  for (const {version, major} of YARN_VERSIONS) {
    await check(
      `yarn ${version} (major ${major}): getNpmAuthenticationHeader defers with no token configured, no request sent`,
      async () => {
        const {server, requests} = await startFake401Server();
        const registryUrl = `http://127.0.0.1:${server.address().port}`;
        const projectDir = fs.mkdtempSync(
          path.join(os.tmpdir(), `oidc-login-cli-${major}-`),
        );
        const globalFolder = fs.mkdtempSync(
          path.join(os.tmpdir(), `oidc-login-global-${major}-`),
        );
        try {
          writeProjectFiles(projectDir, version, registryUrl, {
            withStaleToken: false,
          });
          const env = isolatedEnv({YARN_GLOBAL_FOLDER: globalFolder});

          await execFileAsync(
            'corepack',
            ['yarn@' + version, 'plugin', 'import', PLUGIN_BUNDLE],
            {cwd: projectDir, env, encoding: 'utf8'},
          );

          const start = Date.now();
          const result = await runYarn(
            version,
            projectDir,
            ['add', `${TEST_PACKAGE}@${TEST_VERSION}`],
            {...env, CI: '1'},
          );
          const elapsedMs = Date.now() - start;

          assert.equal(
            result.ok,
            false,
            `expected the add to fail on yarn ${version}:\n${result.output}`,
          );
          assert.match(
            result.output,
            /No authentication configured for request/,
            `expected Yarn's own "no authentication configured" preflight error on yarn ${version}:\n${result.output}`,
          );
          assert.equal(
            requests.length,
            0,
            `expected zero requests to the fake registry on yarn ${version} (Yarn's own preflight should reject before sending anything) -- got: ${JSON.stringify(requests)}`,
          );
          // Sanity bound, not a strict timing assertion -- this should be
          // near-instant (no request, no handshake); a multi-second wait
          // would suggest something is unexpectedly blocking.
          assert.ok(
            elapsedMs < 15000,
            `expected a near-instant failure on yarn ${version}, took ${elapsedMs}ms`,
          );
        } finally {
          server.close();
          fs.rmSync(projectDir, {recursive: true, force: true});
          fs.rmSync(globalFolder, {recursive: true, force: true});
        }
      },
    );

    // Scenario B, parameterized across every registry-touching command
    // worth its own regression check -- see the REGISTRY_COMMANDS comment
    // below for why these four. `needsInstall` runs a plain `yarn install`
    // first (against this same fake registry) to produce a lockfile --
    // needed for `npm publish` specifically (it refuses to run against an
    // unresolved workspace); harmless no-op for the others since an
    // install with zero real dependencies never touches the network at
    // all (nothing to resolve/fetch), so it can't accidentally interfere
    // with the fake server's request log the later assertions check.
    for (const {label, args, needsInstall} of REGISTRY_COMMANDS) {
      await check(
        `yarn ${version} (major ${major}): wrapNetworkRequest retries a 401 but skips the login handshake non-interactively (${label})`,
        async () => {
          const {server, requests} = await startFake401Server();
          const registryUrl = `http://127.0.0.1:${server.address().port}`;
          const projectDir = fs.mkdtempSync(
            path.join(os.tmpdir(), `oidc-login-cli-${major}-`),
          );
          const globalFolder = fs.mkdtempSync(
            path.join(os.tmpdir(), `oidc-login-global-${major}-`),
          );
          try {
            writeProjectFiles(projectDir, version, registryUrl, {
              withStaleToken: true,
            });
            const env = isolatedEnv({YARN_GLOBAL_FOLDER: globalFolder});

            await execFileAsync(
              'corepack',
              ['yarn@' + version, 'plugin', 'import', PLUGIN_BUNDLE],
              {cwd: projectDir, env, encoding: 'utf8'},
            );

            if (needsInstall) {
              // Deliberately NOT CI:'1' here -- Yarn Berry treats a set CI
              // env var as implying --immutable, which refuses to CREATE a
              // lockfile that doesn't exist yet (confirmed directly:
              // "The lockfile would have been created by this install,
              // which is explicitly forbidden"). This setup step has zero
              // real dependencies to resolve, so it never touches the
              // network regardless -- only the command under test below
              // needs CI:'1' to exercise the non-interactive path.
              const installResult = await runYarn(
                version,
                projectDir,
                ['install'],
                env,
              );
              assert.equal(
                installResult.ok,
                true,
                `expected the setup "yarn install" to succeed on yarn ${version} (${label}):\n${installResult.output}`,
              );
              requests.length = 0; // only care about requests from the command under test below
            }

            const start = Date.now();
            const result = await runYarn(version, projectDir, args, {
              ...env,
              CI: '1',
            });
            const elapsedMs = Date.now() - start;

            assert.equal(
              result.ok,
              false,
              `expected "${label}" to fail on yarn ${version}:\n${result.output}`,
            );
            assert.match(
              result.output,
              /Invalid authentication/,
              `expected Yarn's own "invalid authentication" error after the 401 on yarn ${version} (${label}):\n${result.output}`,
            );
            assert.ok(
              requests.length > 0,
              `expected the fake registry to receive at least one request on yarn ${version} (${label}) (none were received) -- output:\n${result.output}`,
            );
            assert.ok(
              requests.every(r => !r.url.includes('/-/v1/login')),
              `expected the login handshake to be skipped entirely (non-interactive) on yarn ${version} (${label}), but saw a request to it: ${JSON.stringify(requests)}`,
            );
            // The real bug this guards against: refreshLogin failing to
            // short-circuit non-interactively would wait up to
            // POLL_TIMEOUT_MS (5 minutes) polling a doneUrl that will never
            // resolve, instead of failing in well under a second.
            assert.ok(
              elapsedMs < 15000,
              `expected a fast failure (no 5-minute poll wait) on yarn ${version} (${label}), took ${elapsedMs}ms`,
            );
          } finally {
            server.close();
            fs.rmSync(projectDir, {recursive: true, force: true});
            fs.rmSync(globalFolder, {recursive: true, force: true});
          }
        },
      );
    }
  }

  const fakePackages = [
    makeFakePackage('fake-dep-a', '1.0.0'),
    makeFakePackage('fake-dep-b', '1.0.0'),
  ];
  for (const {version, major} of YARN_VERSIONS) {
    await check(
      `yarn ${version} (major ${major}): a stale token in a terminal logs in once, and the install succeeds through metadata and tarball requests`,
      async () => {
        const {server, requests, loginCount} =
          await startFakeLoginRegistry(fakePackages);
        const registryUrl = `http://127.0.0.1:${server.address().port}`;
        const projectDir = fs.mkdtempSync(
          path.join(os.tmpdir(), `oidc-login-cli-${major}-`),
        );
        const globalFolder = fs.mkdtempSync(
          path.join(os.tmpdir(), `oidc-login-global-${major}-`),
        );
        const fakeBin = fs.mkdtempSync(
          path.join(os.tmpdir(), 'oidc-login-bin-'),
        );
        fs.writeFileSync(
          path.join(fakeBin, 'xdg-open'),
          `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} -e 'fetch(process.argv[1]).then(r => r.text())' "$1"\n`,
          {mode: 0o755},
        );
        const env = isolatedEnv({
          PATH: `${fakeBin}${path.delimiter}${process.env.PATH}`,
          YARN_GLOBAL_FOLDER: globalFolder,
        });
        // The plugin saves the new token to $HOME/.yarnrc.yml.
        const home = env.HOME;
        try {
          writeProjectFiles(projectDir, version, registryUrl, {
            withStaleToken: true,
          });
          await execFileAsync(
            'corepack',
            ['yarn@' + version, 'plugin', 'import', PLUGIN_BUNDLE],
            {cwd: projectDir, env, encoding: 'utf8'},
          );

          const result = await runYarnInTerminal(
            version,
            projectDir,
            ['add', 'fake-dep-a@1.0.0', 'fake-dep-b@1.0.0'],
            env,
          );

          assert.equal(
            result.ok,
            true,
            `expected the add to succeed after logging in on yarn ${version}:\n${result.output}`,
          );
          for (const pkg of fakePackages) {
            assert.ok(
              fs.existsSync(
                path.join(projectDir, 'node_modules', pkg.name, 'package.json'),
              ),
              `${pkg.name} should be installed on yarn ${version}`,
            );
          }
          assert.equal(
            loginCount(),
            1,
            `expected exactly one login for the whole install on yarn ${version}, saw ${loginCount()}: ${JSON.stringify(requests)}`,
          );
          assert.match(
            fs.readFileSync(path.join(home, '.yarnrc.yml'), 'utf8'),
            /fresh-token/,
            `the new token should be saved to $HOME/.yarnrc.yml on yarn ${version}`,
          );
        } finally {
          server.close();
          for (const dir of [projectDir, globalFolder, home, fakeBin]) {
            fs.rmSync(dir, {recursive: true, force: true});
          }
        }
      },
    );
  }

  console.log(`\n${passed} check(s) passed.`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
