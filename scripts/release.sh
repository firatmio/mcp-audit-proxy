#!/usr/bin/env bash
#
# Build the release archives and create the GitHub release.
#
#   ./scripts/release.sh 0.1.0            # build, checksum and verify only
#   ./scripts/release.sh 0.1.0 --draft    # also tag and create a draft release
#   ./scripts/release.sh 0.1.0 --publish  # also tag and publish it
#
# The default touches nothing outside dist/. Tagging pushes to the remote and a
# published release is an artifact people start linking to, so both are opt-in.
#
# npm is released separately, by scripts/release-npm.sh. Order for a full
# release:
#
#   1. ./scripts/release.sh 0.1.0 --publish       tag + binaries
#   2. ./scripts/release-npm.sh 0.1.0 --publish   npm packages
#   3. mcp-publisher publish                      official MCP registry
#
# npm comes second because its packages reference the GitHub tag, and the
# registry comes last because it verifies the npm package.

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

TAG="v$VERSION"
DIST="$REPO_ROOT/dist/release"

# make_zip <archive.zip> <directory>, run from the directory's parent.
#
# There is no one zip tool present everywhere this might run: Git Bash has no
# `zip`, GNU tar cannot write zip, and bsdtar (Windows' built-in tar.exe, and
# plain `tar` on macOS) can. Try each rather than let the Windows archive
# quietly go missing from a release.
make_zip() {
  local archive="$1" dir="$2"

  if command -v zip >/dev/null 2>&1; then
    zip -qr "$archive" "$dir"
    return
  fi
  for candidate in /c/Windows/System32/tar.exe tar; do
    if command -v "$candidate" >/dev/null 2>&1 &&
      "$candidate" --version 2>/dev/null | grep -qi bsdtar; then
      "$candidate" -a -c -f "$archive" "$dir"
      return
    fi
  done
  if command -v powershell >/dev/null 2>&1; then
    powershell -NoProfile -Command \
      "Compress-Archive -Path '$dir' -DestinationPath '$archive' -Force"
    return
  fi

  echo "error: no tool available to create $archive (need zip, bsdtar or powershell)" >&2
  exit 1
}

# --- preflight --------------------------------------------------------------
#
# Everything below this line is cheap. A release that goes out with a stale
# version number in one of three files, or from a dirty tree, is expensive.

echo "==> Preflight"

if [ -n "$(git status --porcelain)" ]; then
  echo "error: the working tree is dirty; commit or stash first" >&2
  git status --short >&2
  exit 1
fi

if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "error: tag $TAG already exists" >&2
  exit 1
fi

# The version is written down in three places and they have to agree, or
# someone installs 0.1.0 from npm and gets a binary that reports 0.0.9.
check_version() {
  local file="$1" actual="$2"
  if [ "$actual" != "$VERSION" ]; then
    echo "error: $file says version $actual, expected $VERSION" >&2
    exit 1
  fi
  echo "    $file: $actual"
}

check_version "server.json" \
  "$(node -e 'console.log(require("./server.json").version)')"
check_version "server.json (packages[0])" \
  "$(node -e 'console.log(require("./server.json").packages[0].version)')"
check_version "packaging/npm/mcp-audit-proxy/package.json" \
  "$(node -e 'console.log(require("./packaging/npm/mcp-audit-proxy/package.json").version)')"

if ! grep -q "^## \[$VERSION\]" CHANGELOG.md; then
  echo "error: CHANGELOG.md has no '## [$VERSION]' section" >&2
  exit 1
fi
echo "    CHANGELOG.md: has a section for $VERSION"

echo "==> Tests"
go test ./... >/dev/null
echo "    tests pass"

# --- build ------------------------------------------------------------------

rm -rf "$DIST"
mkdir -p "$DIST"

# <GOOS> <GOARCH>
PLATFORMS="
darwin arm64
darwin amd64
linux arm64
linux amd64
windows amd64
"

echo "==> Building $TAG"
echo "$PLATFORMS" | while read -r GOOS GOARCH; do
  [ -z "${GOOS:-}" ] && continue

  NAME="mcp-audit_${VERSION}_${GOOS}_${GOARCH}"
  STAGE="$DIST/$NAME"
  EXE=""
  [ "$GOOS" = "windows" ] && EXE=".exe"

  mkdir -p "$STAGE"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath -ldflags "-s -w -X main.Version=$VERSION" \
    -o "$STAGE/mcp-audit$EXE" ./cmd/mcp-audit

  # Ship the licence and the docs a user needs offline alongside the binary.
  cp LICENSE NOTICE README.md CHANGELOG.md config.example.yaml "$STAGE/"

  if [ "$GOOS" = "windows" ]; then
    (cd "$DIST" && make_zip "$NAME.zip" "$NAME")
    echo "    $NAME.zip"
  else
    (cd "$DIST" && tar -czf "$NAME.tar.gz" "$NAME")
    echo "    $NAME.tar.gz"
  fi
  rm -rf "$STAGE"
done

echo "==> Checksums"
CHECKSUMS="mcp-audit_${VERSION}_checksums.txt"
(cd "$DIST" && sha256sum ./*.tar.gz ./*.zip | sed 's|\./||' > "$CHECKSUMS")
sed 's/^/    /' "$DIST/$CHECKSUMS"

# --- verify -----------------------------------------------------------------

echo "==> Verifying the built binary reports $VERSION"
HOST_OS="$(go env GOOS)"; HOST_ARCH="$(go env GOARCH)"
HOST_NAME="mcp-audit_${VERSION}_${HOST_OS}_${HOST_ARCH}"
VERIFY="$DIST/.verify"
mkdir -p "$VERIFY"

if [ -f "$DIST/$HOST_NAME.tar.gz" ]; then
  tar -xzf "$DIST/$HOST_NAME.tar.gz" -C "$VERIFY"
elif [ -f "$DIST/$HOST_NAME.zip" ]; then
  unzip -qo "$DIST/$HOST_NAME.zip" -d "$VERIFY"
else
  echo "    skipped: no archive for $HOST_OS/$HOST_ARCH"
fi

HOST_EXE=""
[ "$HOST_OS" = "windows" ] && HOST_EXE=".exe"
if [ -x "$VERIFY/$HOST_NAME/mcp-audit$HOST_EXE" ]; then
  REPORTED="$("$VERIFY/$HOST_NAME/mcp-audit$HOST_EXE" version)"
  echo "    reports: $REPORTED"
  if [ "$REPORTED" != "mcp-audit $VERSION" ]; then
    echo "error: expected 'mcp-audit $VERSION', got '$REPORTED'" >&2
    exit 1
  fi
fi
rm -rf "$VERIFY"

# --- release notes ----------------------------------------------------------

# Pull this version's section out of the CHANGELOG so the release notes and the
# changelog cannot drift apart.
NOTES="$DIST/release-notes.md"
awk -v ver="$VERSION" '
  $0 ~ "^## \\[" ver "\\]" { inside = 1; next }
  inside && /^## \[/       { exit }
  inside                   { print }
' CHANGELOG.md > "$NOTES"

{
  echo
  echo "---"
  echo
  echo "Verify a download against \`$CHECKSUMS\`:"
  echo
  echo '```bash'
  echo "sha256sum -c $CHECKSUMS --ignore-missing"
  echo '```'
} >> "$NOTES"

echo "==> Release notes"
head -5 "$NOTES" | sed 's/^/    /'
echo "    ... ($(wc -l < "$NOTES") lines)"

# --- publish ----------------------------------------------------------------

case "$PUBLISH" in
  "")
    echo
    echo "==> Built and verified, nothing pushed."
    echo "    Artifacts:  $DIST"
    echo "    Notes:      $NOTES"
    echo
    echo "    $0 $VERSION --draft      tag and create a draft release"
    echo "    $0 $VERSION --publish    tag and publish"
    exit 0
    ;;
  --draft)
    DRAFT_FLAG="--draft"
    STATE="draft"
    ;;
  --publish)
    DRAFT_FLAG=""
    STATE="published"
    ;;
  *)
    echo "error: unknown option '$PUBLISH' (expected --draft or --publish)" >&2
    exit 2
    ;;
esac

echo "==> Creating the $STATE GitHub release $TAG"
git tag -a "$TAG" -m "mcp-audit $VERSION"
git push origin "$TAG"

# shellcheck disable=SC2086
gh release create "$TAG" \
  $DRAFT_FLAG \
  --title "mcp-audit $VERSION" \
  --notes-file "$NOTES" \
  "$DIST"/*.tar.gz "$DIST"/*.zip "$DIST/$CHECKSUMS"

echo
echo "Done. Release $TAG is $STATE."
if [ "$STATE" = "draft" ]; then
  echo "Review it, then publish from the GitHub UI or re-run with --publish."
fi
echo "Next: ./scripts/release-npm.sh $VERSION --publish"
