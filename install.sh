#!/bin/sh
# Installs the yarn-plugin-oidc-login Yarn Berry plugin (packages/yarn-plugin-
# oidc-login) from this repo's GitHub Releases into an existing Yarn Berry
# project - via `yarn plugin import` for a real Yarn project (yarn.lock
# present), or by writing .yarn/plugins/ and .yarnrc.yml directly otherwise
# (the only option when corepack/yarn.lock aren't available to run
# `plugin import` for you).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/fortmesa/verdaccio-generic-oidc/main/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- /path/to/project
#
# Env vars:
#   OIDC_LOGIN_PLUGIN_VERSION  release tag to install, e.g. v1.1.1 (default: latest)

set -eu

REPO="fortmesa/verdaccio-generic-oidc"
VERSION="${OIDC_LOGIN_PLUGIN_VERSION:-latest}"
PROJECT_DIR="${1:-$PWD}"

say() { printf '%s\n' "$*"; }
die() { printf 'yarn-plugin-oidc-login install: %s\n' "$*" >&2; exit 1; }

resolve_version() {
  if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
      | grep '"tag_name":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
    [ -n "$VERSION" ] || die "could not resolve the latest release version"
  fi
}

install_plugin() {
  yarnrc="$PROJECT_DIR/.yarnrc.yml"
  plugin_url="https://github.com/$REPO/releases/download/$VERSION/plugin-oidc-login.cjs"

  # A real Yarn project (yarn.lock-anchored) can install the plugin the
  # correct way: `yarn plugin import` reads the plugin's own declared name
  # (@yarnpkg/plugin-oidc-login) and derives the install path and
  # .yarnrc.yml entry from that, rather than us hand-editing YAML.
  if [ -f "$PROJECT_DIR/yarn.lock" ] && command -v corepack >/dev/null 2>&1; then
    say "Found a Yarn project at $PROJECT_DIR - installing the plugin via 'yarn plugin import'..."
    if (cd "$PROJECT_DIR" && corepack yarn plugin import "$plugin_url"); then
      return 0
    fi
    say "'yarn plugin import' failed - falling back to a manual install."
  fi

  # Manual fallback: matches the path `yarn plugin import` itself uses for
  # this plugin (its declared name, @yarnpkg/plugin-oidc-login, lands under
  # a @yarnpkg/ subdirectory of .yarn/plugins -- confirmed directly against
  # a real `yarn plugin import` run of this exact plugin).
  plugin_dir="$PROJECT_DIR/.yarn/plugins/@yarnpkg"
  plugin_path="$plugin_dir/plugin-oidc-login.cjs"

  say "Installing the plugin manually to $plugin_path..."
  mkdir -p "$plugin_dir"
  curl -fsSL "$plugin_url" -o "$plugin_path"
  say "Installed plugin to $plugin_path"

  if grep -q "plugin-oidc-login.cjs" "$yarnrc" 2>/dev/null; then
    say "$yarnrc already references the plugin."
  else
    say "Add this to $yarnrc:"
    say "  plugins:"
    say "    - path: .yarn/plugins/@yarnpkg/plugin-oidc-login.cjs"
    say "      spec: \"https://github.com/$REPO\""
  fi
}

[ -f "$PROJECT_DIR/.yarnrc.yml" ] || die "no .yarnrc.yml found at $PROJECT_DIR - this only installs into an existing Yarn Berry project"

resolve_version
install_plugin

say "Done. See docs/yarn-integration.md for required .yarnrc.yml settings and usage."
