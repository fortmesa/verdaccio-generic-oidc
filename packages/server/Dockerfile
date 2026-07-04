ARG VERDACCIO_VERSION=6.0.0
FROM verdaccio/verdaccio:${VERDACCIO_VERSION} AS base

# Build context is the repo root (see docker-compose.yml's `context: ../..`),
# not this directory -- packages/server is a yarn workspace member, and
# `yarn workspaces focus` needs to see the whole workspace's manifests
# (root package.json + yarn.lock + every member's package.json) to resolve
# correctly, even though it only ends up installing this one package's tree.

FROM base AS manifests
USER root
WORKDIR /opt/build
COPY package.json yarn.lock .yarnrc.yml ./
COPY packages/server/package.json packages/server/package.json
COPY packages/yarn-plugin-oidc-login/package.json packages/yarn-plugin-oidc-login/package.json

# ioredis / generic-pool / @aws-sdk/client-dynamodb / @aws-sdk/lib-dynamodb
# are declared as optional peerDependencies (peerDependenciesMeta.optional)
# in the real, published package.json -- correct for real consumers, who
# explicitly install whichever backend they use, per this plugin's whole
# "don't force Redis or the AWS SDK on filesystem-only users" design. This
# image is the one place that wants all three backends baked in
# unconditionally.
#
# `yarn workspaces focus` does NOT auto-install optional peerDependencies
# any more than npm does -- confirmed empirically, same as the finding that
# already bit us once for npm (see git history). Unlike npm, though, Yarn
# refuses `yarn add --optional <pkg>` outright when <pkg> is already
# declared as a peerDependency ("use either of -D or -P, or remove it from
# your peer dependencies first"), and `yarn add --peer` "works" but
# silently drops the `focus` scoping and re-resolves the *entire* unscoped
# project (442 packages instead of 93, confirmed empirically) -- not what
# a lean, single-package image wants.
#
# The fix: since Node's require() doesn't consult package.json's
# dependency-type fields at all at runtime (only a package manager does,
# at install time), it's harmless to temporarily move these four entries
# from peerDependencies into plain optionalDependencies just to drive this
# image's install -- `optionalDependencies` behaves like a normal
# dependency for install purposes (attempted by default, not required to
# succeed), unlike peerDependencies (never auto-installed for the focused
# package itself). This mutated manifest is used ONLY here, to resolve
# node_modules; the final image below copies the real, unmutated
# package.json straight from the build context, never from this stage.
RUN node -e "\
  const fs = require('fs'); \
  const p = JSON.parse(fs.readFileSync('packages/server/package.json')); \
  p.optionalDependencies = p.peerDependencies; \
  delete p.peerDependencies; \
  delete p.peerDependenciesMeta; \
  fs.writeFileSync('packages/server/package.json', JSON.stringify(p, null, 2)); \
  "

FROM manifests AS builder
USER root
RUN corepack enable
RUN yarn workspaces focus @fortmesa/verdaccio-generic-oidc

COPY packages/server/tsconfig.json packages/server/tsconfig.json
COPY packages/server/src packages/server/src
RUN yarn workspace @fortmesa/verdaccio-generic-oidc build

# Separate, from-scratch production-only install -- Yarn's own recommended
# pattern for "lean node_modules for one workspace member" is a fresh
# --production focus install, not an install-then-prune step (unlike npm,
# there's no equivalent prune command for a node-modules-linked project).
# A distinct stage (rather than reusing `builder`'s own node_modules) keeps
# this independent of and buildable in parallel with the dev/build stage.
FROM manifests AS deps
USER root
RUN corepack enable
RUN yarn workspaces focus @fortmesa/verdaccio-generic-oidc --production

FROM base AS final

# Verdaccio's plugin loader resolves a scoped package name verbatim as the
# plugins-dir path, so this must match `name` in package.json exactly.
COPY --chown=verdaccio:verdaccio packages/server/package.json /verdaccio/plugins/@fortmesa/verdaccio-generic-oidc/package.json
COPY --from=deps --chown=verdaccio:verdaccio /opt/build/node_modules /verdaccio/plugins/@fortmesa/verdaccio-generic-oidc/node_modules
COPY --from=builder --chown=verdaccio:verdaccio /opt/build/packages/server/lib /verdaccio/plugins/@fortmesa/verdaccio-generic-oidc/lib
