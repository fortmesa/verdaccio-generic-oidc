#!/bin/sh
# Installs the yarn-plugin-oidc-login Yarn Berry plugin (packages/yarn-plugin-
# oidc-login) from this repo's GitHub Releases into an existing Yarn Berry
# project - via `yarn plugin import` for a real Yarn project (yarn.lock
# present), or by writing .yarn/plugins/ directly otherwise (the only option
# when corepack/yarn.lock aren't available to run `plugin import` for you).
# Either way the plugin is checked against the release's checksums.txt
# before Yarn sees it.
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

# checksums.txt is published alongside every release (see
# .github/workflows/release.yml's "Generate checksums" step -- `sha256sum *`
# over the same dist/ dir whose contents become the release assets).
CHECKSUMS_FILE=""

# Temp files the cleanup trap removes. Each download lands in one of these
# and is moved into place only after its checksum matches.
PLUGIN_TMP=""
YARNRC_TMP=""

cleanup() {
  for f in "$CHECKSUMS_FILE" "$PLUGIN_TMP" "$YARNRC_TMP"; do
    if [ -n "$f" ]; then rm -f "$f"; fi
  done
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# mktemp creates files 0600. file_mode prints the mode a plain download
# would get under the current umask, so the installed file keeps it.
file_mode() {
  printf '%o' $(( $1 & ~0$(umask) ))
}

fetch_checksums() {
  [ -n "$CHECKSUMS_FILE" ] && return 0
  CHECKSUMS_FILE=$(mktemp)
  curl -fsSL "https://github.com/$REPO/releases/download/$VERSION/checksums.txt" \
    -o "$CHECKSUMS_FILE" \
    || die "could not fetch checksums.txt for $VERSION"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "no sha256sum/shasum available to verify downloaded file integrity"
  fi
}

# Verifies $file (already downloaded to disk) against its entry for $name in
# this release's checksums.txt. Fails loud on a mismatch or a missing entry
# -- a checksum file present but silent about the one file being installed
# is exactly as unsafe as no checksum file at all.
verify_checksum() {
  file="$1"
  name="$2"
  fetch_checksums
  expected=$(grep " $name\$" "$CHECKSUMS_FILE" | awk '{print $1}')
  [ -n "$expected" ] || die "no checksum entry for $name in checksums.txt"
  actual=$(sha256_of "$file")
  [ "$expected" = "$actual" ] \
    || die "checksum mismatch for $name (expected $expected, got $actual) -- refusing to install"
}

resolve_version() {
  if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
      | grep '"tag_name":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
    [ -n "$VERSION" ] || die "could not resolve the latest release version"
  fi
}

# `yarn plugin import` of a local file records that file's path as the
# plugin's spec. Yarn re-downloads a missing plugin only from an http(s)
# spec, so this points the spec back at the release URL the verified file
# came from. Args: .yarnrc.yml path, spec Yarn wrote, release URL.
set_plugin_spec() {
  YARNRC_TMP=$(mktemp)
  if YS_OLD_SPEC="$2" YS_NEW_SPEC="$3" awk '
    { line = $0; sub(/^ +/, "", line) }
    line == ("spec: " ENVIRON["YS_OLD_SPEC"]) {
      sub(/spec: .*/, "")
      print $0 "spec: \"" ENVIRON["YS_NEW_SPEC"] "\""
      n++
      next
    }
    { print }
    END { exit (n == 1 ? 0 : 1) }
  ' "$1" > "$YARNRC_TMP"; then
    cat "$YARNRC_TMP" > "$1"
  fi
  rm -f "$YARNRC_TMP"
  YARNRC_TMP=""
  grep -qF "spec: \"$3\"" "$1" \
    || die "the plugin is installed and verified, but its spec in $1 still names a temp file - set it to \"$3\" by hand"
}

install_plugin() {
  yarnrc="$PROJECT_DIR/.yarnrc.yml"
  plugin_url="https://github.com/$REPO/releases/download/$VERSION/plugin-oidc-login.cjs"

  # A real Yarn project (yarn.lock-anchored) can install the plugin the
  # correct way: `yarn plugin import` reads the plugin's own declared name
  # (@yarnpkg/plugin-oidc-login) and derives the install path and
  # .yarnrc.yml entry from that, rather than us hand-editing YAML. The one
  # line this script edits afterwards is the spec, in set_plugin_spec.
  #
  # The script downloads and verifies the plugin before Yarn sees it,
  # because `yarn plugin import <url>` runs the plugin's code to read its
  # name before anything could check it.
  if [ -f "$PROJECT_DIR/yarn.lock" ] && command -v corepack >/dev/null 2>&1; then
    say "Found a Yarn project at $PROJECT_DIR - installing the plugin via 'yarn plugin import'..."
    mkdir -p "$PROJECT_DIR/.yarn"
    PLUGIN_TMP=$(mktemp "$PROJECT_DIR/.yarn/.plugin-oidc-login.XXXXXX")
    curl -fsSL "$plugin_url" -o "$PLUGIN_TMP" || die "could not download plugin-oidc-login.cjs"
    verify_checksum "$PLUGIN_TMP" "plugin-oidc-login.cjs"
    import_spec=".yarn/${PLUGIN_TMP##*/}"
    if (cd "$PROJECT_DIR" && corepack yarn plugin import "./$import_spec"); then
      rm -f "$PLUGIN_TMP"
      PLUGIN_TMP=""
      set_plugin_spec "$yarnrc" "$import_spec" "$plugin_url"
      return 0
    fi
    rm -f "$PLUGIN_TMP"
    PLUGIN_TMP=""
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
  PLUGIN_TMP=$(mktemp "$plugin_dir/.plugin-oidc-login.XXXXXX")
  curl -fsSL "$plugin_url" -o "$PLUGIN_TMP" || die "could not download plugin-oidc-login.cjs"
  verify_checksum "$PLUGIN_TMP" "plugin-oidc-login.cjs"
  chmod "$(file_mode 0666)" "$PLUGIN_TMP"
  mv -f "$PLUGIN_TMP" "$plugin_path"
  PLUGIN_TMP=""
  say "Installed plugin to $plugin_path"

  if grep -q "plugin-oidc-login.cjs" "$yarnrc" 2>/dev/null; then
    say "$yarnrc already references the plugin."
  else
    say "Add this to $yarnrc:"
    say "  plugins:"
    say "    - path: .yarn/plugins/@yarnpkg/plugin-oidc-login.cjs"
    say "      spec: \"$plugin_url\""
  fi
}

[ -f "$PROJECT_DIR/.yarnrc.yml" ] || die "no .yarnrc.yml found at $PROJECT_DIR - this only installs into an existing Yarn Berry project"

resolve_version
install_plugin

say "Done. See docs/yarn-integration.md for required .yarnrc.yml settings and usage."
