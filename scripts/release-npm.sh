#!/usr/bin/env bash
#
# Build the release binaries and assemble the npm packages.
#
#   ./scripts/release-npm.sh 0.1.0            # build + assemble, publish dry-run
#   ./scripts/release-npm.sh 0.1.0 --publish  # actually publish to npm
#
# Publishing is opt-in on purpose: an npm release cannot be taken back, only
# deprecated.
#
# Layout produced under dist/npm:
#   mcp-audit-proxy/                     the launcher everyone installs
#   mcp-audit-proxy-<platform>/          one prebuilt binary each
#
# The launcher lists the platform packages as optionalDependencies, so npm
# installs exactly the one that matches the machine and skips the rest.

set -euo pipefail

VERSION="${1:-}"
PUBLISH="${2:-}"

if [ -z "$VERSION" ]; then
  echo "usage: $0 <version> [--publish]" >&2
  echo "example: $0 0.1.0" >&2
  exit 2
fi

if ! printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
  echo "error: '$VERSION' is not a semantic version (expected e.g. 0.1.0)" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DIST="$REPO_ROOT/dist/npm"
LAUNCHER_SRC="$REPO_ROOT/packaging/npm/mcp-audit-proxy"

# platform triples: <npm os> <npm cpu> <GOOS> <GOARCH>
PLATFORMS="
darwin arm64 darwin arm64
darwin x64 darwin amd64
linux arm64 linux arm64
linux x64 linux amd64
win32 x64 windows amd64
"

echo "==> Testing before we build anything"
go test ./... >/dev/null
echo "    tests pass"

rm -rf "$DIST"
mkdir -p "$DIST"

# --- platform packages ------------------------------------------------------

echo "$PLATFORMS" | while read -r NPM_OS NPM_CPU GOOS GOARCH; do
  [ -z "${NPM_OS:-}" ] && continue

  PKG="mcp-audit-proxy-$NPM_OS-$NPM_CPU"
  OUT="$DIST/$PKG"
  EXE=""
  [ "$GOOS" = "windows" ] && EXE=".exe"

  echo "==> $PKG ($GOOS/$GOARCH)"
  mkdir -p "$OUT/bin"

  # -s -w strips the symbol table and DWARF: smaller download, and nothing here
  # needs a debuggable release binary.
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath -ldflags "-s -w -X main.Version=$VERSION" \
    -o "$OUT/bin/mcp-audit$EXE" ./cmd/mcp-audit

  cat > "$OUT/package.json" <<EOF
{
  "name": "$PKG",
  "version": "$VERSION",
  "description": "Prebuilt mcp-audit binary for $NPM_OS-$NPM_CPU",
  "license": "Apache-2.0",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/firatmio/mcp-audit-proxy.git"
  },
  "os": ["$NPM_OS"],
  "cpu": ["$NPM_CPU"],
  "files": ["bin/"]
}
EOF

  cat > "$OUT/README.md" <<EOF
# $PKG

The prebuilt \`mcp-audit\` binary for $NPM_OS-$NPM_CPU.

You are not meant to install this directly. Install
[\`mcp-audit-proxy\`](https://www.npmjs.com/package/mcp-audit-proxy) instead; it
pulls in the right platform package for your machine automatically.
EOF
done

# --- launcher package -------------------------------------------------------

echo "==> mcp-audit-proxy (launcher)"
mkdir -p "$DIST/mcp-audit-proxy/bin"
cp "$LAUNCHER_SRC/bin/mcp-audit.js" "$DIST/mcp-audit-proxy/bin/"
cp "$LAUNCHER_SRC/README.md" "$DIST/mcp-audit-proxy/"
cp "$REPO_ROOT/LICENSE" "$DIST/mcp-audit-proxy/" 2>/dev/null || \
  echo "    warning: no LICENSE file at the repo root yet"

# Stamp the version into the launcher and into every optionalDependency, so the
# launcher can only ever resolve binaries built from this same commit.
#
# Done with node rather than python or sed: node is guaranteed to be present
# wherever npm is, and editing JSON with a regex is how versions end up subtly
# malformed.
node -e '
  const fs = require("node:fs");
  const [source, target, version] = process.argv.slice(1);
  const pkg = JSON.parse(fs.readFileSync(source, "utf8"));

  pkg.version = version;
  for (const name of Object.keys(pkg.optionalDependencies ?? {})) {
    pkg.optionalDependencies[name] = version;
  }

  fs.writeFileSync(target, JSON.stringify(pkg, null, 2) + "\n");
' "$LAUNCHER_SRC/package.json" "$DIST/mcp-audit-proxy/package.json" "$VERSION"

# --- verify -----------------------------------------------------------------

echo "==> Verifying the launcher runs the binary it just built"
HOST_OS="$(go env GOOS)"; HOST_ARCH="$(go env GOARCH)"
case "$HOST_OS-$HOST_ARCH" in
  darwin-arm64) HOST_PKG="mcp-audit-proxy-darwin-arm64" ;;
  darwin-amd64) HOST_PKG="mcp-audit-proxy-darwin-x64" ;;
  linux-arm64)  HOST_PKG="mcp-audit-proxy-linux-arm64" ;;
  linux-amd64)  HOST_PKG="mcp-audit-proxy-linux-x64" ;;
  windows-amd64) HOST_PKG="mcp-audit-proxy-win32-x64" ;;
  *) HOST_PKG="" ;;
esac

if [ -n "$HOST_PKG" ]; then
  # Put the platform package where require.resolve will find it.
  mkdir -p "$DIST/mcp-audit-proxy/node_modules"
  rm -rf "$DIST/mcp-audit-proxy/node_modules/$HOST_PKG"
  cp -r "$DIST/$HOST_PKG" "$DIST/mcp-audit-proxy/node_modules/$HOST_PKG"

  REPORTED="$(node "$DIST/mcp-audit-proxy/bin/mcp-audit.js" version)"
  echo "    launcher reports: $REPORTED"
  if [ "$REPORTED" != "mcp-audit $VERSION" ]; then
    echo "error: expected 'mcp-audit $VERSION', got '$REPORTED'" >&2
    exit 1
  fi
  rm -rf "$DIST/mcp-audit-proxy/node_modules"
else
  echo "    skipped: no platform package for $HOST_OS-$HOST_ARCH"
fi

# --- publish ----------------------------------------------------------------

# Platform packages go first: the launcher declares them as dependencies, so
# publishing it first would briefly point users at versions that do not exist.
PUBLISH_ORDER=""
for dir in "$DIST"/mcp-audit-proxy-*; do
  PUBLISH_ORDER="$PUBLISH_ORDER $dir"
done
PUBLISH_ORDER="$PUBLISH_ORDER $DIST/mcp-audit-proxy"

if [ "$PUBLISH" = "--publish" ]; then
  echo "==> Publishing to npm"
  for dir in $PUBLISH_ORDER; do
    echo "    npm publish $(basename "$dir")"
    (cd "$dir" && npm publish --access public)
  done
  echo "Published $VERSION."
else
  echo "==> Dry run (pass --publish to release for real)"
  for dir in $PUBLISH_ORDER; do
    (cd "$dir" && npm publish --dry-run --access public 2>&1 | sed 's/^/    /')
  done
  echo
  echo "Assembled in $DIST"
  echo "To publish: $0 $VERSION --publish"
fi
