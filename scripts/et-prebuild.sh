#!/usr/bin/env bash
#
# Rebuild the prebuilt core that ships with the sources.
#
#   scripts/et-prebuild.sh
#
# Run this whenever VERSION changes. check-panel.sh fails if you forget, because
# a stale prebuilt is worse than none at all: the installer prefers it over
# compiling, so every install would quietly receive the previous release while
# every version string in the tree claimed otherwise.
#
# Why these files exist at all: with no release host reachable the installer
# falls through to building from source, and on the single-core VPS these
# tunnels run on that means installing a Go toolchain over the package mirror,
# fetching the modules, and compiling — 29 s of compiling alone on four cores,
# so minutes there, after well over a hundred megabytes of downloads. The core
# is 11 MB, and 4.2 MB gzipped. A whole install becomes a few seconds.
#
# They are stored compressed because on these paths the difference between
# 11 MB and 4.2 MB is most of the install time.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(tr -d '[:space:]' < VERSION)"
OUT="$ROOT/prebuilt"
# amd64 and arm64 cover essentially every VPS these run on. Anything else still
# has the source build, which is why this is a fast path and not the only path.
ARCHES="${ARCHES:-amd64 arm64}"

echo "building v${VERSION} for: ${ARCHES}"
mkdir -p "$OUT"
rm -f "$OUT"/et-core-linux-*.gz "$OUT"/et-panel.sh.gz

for a in $ARCHES; do
    tmp="$(mktemp -d)"
    CGO_ENABLED=0 GOOS=linux GOARCH="$a" go build -trimpath \
        -ldflags "-s -w -X github.com/emergency-tunnel/et/internal/core.CoreVersion=${VERSION}" \
        -o "$tmp/et-core-linux-$a" ./cmd/et-core
    gzip -9 -c "$tmp/et-core-linux-$a" > "$OUT/et-core-linux-$a.gz"
    printf '  %-6s %s\n' "$a" "$(du -h "$OUT/et-core-linux-$a.gz" | cut -f1)"
    rm -rf "$tmp"
done

gzip -9 -c scripts/et-panel.sh > "$OUT/et-panel.sh.gz"
cp -f scripts/emergency-tunnel@.service "$OUT/" 2>/dev/null || true
cp -f scripts/uninstall.sh "$OUT/" 2>/dev/null || true
printf '%s\n' "$VERSION" > "$OUT/VERSION"

# The checksum file cannot list itself: the previous copy is still on disk when
# the list is built, so it would be recorded and then immediately replaced,
# leaving a file that fails its own verification.
( cd "$OUT" && rm -f SHA256SUMS && sha256sum -- * > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS )
echo "prebuilt/ is now v${VERSION} ($(du -sh "$OUT" | cut -f1))"
