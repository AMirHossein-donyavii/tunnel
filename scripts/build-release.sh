#!/usr/bin/env bash
#
# Build a publishable Emergency Tunnel release.
#
# Produces a web-servable tree under ./release/ containing per-arch static
# binaries, SHA256SUMS, an optional minisign signature, a manifest, and the
# channel pointer. rsync ./release/ to your web server's document root.
#
# Usage:
#   scripts/build-release.sh [VERSION] [--channel stable|beta] [--sign]
#
# Env:
#   MINISIGN_KEY   path to a minisign secret key (enables signing without --sign)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-$(cat VERSION 2>/dev/null || echo 0.0.0)}"
VERSION="${VERSION#v}"                       # accept v1.2.3 or 1.2.3
CHANNEL="stable"
SIGN="no"
shift || true
while [ $# -gt 0 ]; do
    case "$1" in
        --channel) CHANNEL="$2"; shift 2 ;;
        --sign)    SIGN="yes"; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

OUTROOT="release"
RELDIR="${OUTROOT}/releases/v${VERSION}"
PKG="github.com/emergency-tunnel/et/internal/core"
LDFLAGS="-s -w -X ${PKG}.CoreVersion=${VERSION}"

# target triples: GOOS/GOARCH[/GOARM] -> asset suffix
TARGETS=(
    "linux amd64 - linux-amd64"
    "linux arm64 - linux-arm64"
    "linux arm 7 linux-armv7"
)

command -v go >/dev/null 2>&1 || { echo "go toolchain required" >&2; exit 1; }

echo "==> Building Emergency Tunnel v${VERSION} (channel: ${CHANNEL})"
rm -rf "$RELDIR"; mkdir -p "$RELDIR"

for t in "${TARGETS[@]}"; do
    read -r goos goarch goarm suffix <<<"$t"
    out="${RELDIR}/et-core-${suffix}"
    echo "  - ${suffix}"
    env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        $( [ "$goarm" != "-" ] && echo GOARM="$goarm" ) \
        go build -trimpath -ldflags "$LDFLAGS" -o "$out" ./cmd/et-core
done

# Ship the panel and unit alongside the binaries so the installer fetches one set.
cp scripts/et-panel.sh "${RELDIR}/et-panel.sh"
# Stamp the panel the same way the core is stamped. Without this, building an
# explicit version out of a tree whose VERSION says something else ships a
# console that reports the tree's version — and every consistency check
# downstream (installer verify, the panel's own header) then fires on a release
# that is actually fine.
sed -i.bak -E "s|^SCRIPT_VERSION=\".*\"|SCRIPT_VERSION=\"${VERSION}\"|" "${RELDIR}/et-panel.sh"
rm -f "${RELDIR}/et-panel.sh.bak"
grep -q "^SCRIPT_VERSION=\"${VERSION}\"$" "${RELDIR}/et-panel.sh" \
    || { echo "could not stamp SCRIPT_VERSION into et-panel.sh" >&2; exit 1; }
cp scripts/uninstall.sh "${RELDIR}/uninstall.sh"
cp systemd/emergency-tunnel@.service "${RELDIR}/emergency-tunnel@.service"

echo "==> Generating checksums"
# Explicit list so we never hash SHA256SUMS/manifest.json themselves.
( cd "$RELDIR" && sha256sum et-core-linux-* et-panel.sh uninstall.sh emergency-tunnel@.service > SHA256SUMS && cat SHA256SUMS )

# Optional integrity signature (recommended for a public URL).
if [ "$SIGN" = "yes" ] || [ -n "${MINISIGN_KEY:-}" ]; then
    if command -v minisign >/dev/null 2>&1 && [ -n "${MINISIGN_KEY:-}" ]; then
        echo "==> Signing SHA256SUMS with minisign"
        minisign -S -m "${RELDIR}/SHA256SUMS" -s "${MINISIGN_KEY}" \
            -c "emergency-tunnel v${VERSION}" >/dev/null
        # produces ${RELDIR}/SHA256SUMS.minisig
        # Publish the matching public key at the web root as minisign.pub.
        [ -f "${OUTROOT}/minisign.pub" ] || echo "  (!) place your minisign.pub at ${OUTROOT}/minisign.pub"
    else
        echo "  (!) signing requested but minisign/MINISIGN_KEY missing — skipping"
    fi
fi

echo "==> Writing manifest"
{
    echo "{"
    echo "  \"version\": \"${VERSION}\","
    echo "  \"channel\": \"${CHANNEL}\","
    echo "  \"assets\": ["
    first=1
    for f in "${RELDIR}"/*; do
        b="$(basename "$f")"
        [ "$b" = "manifest.json" ] && continue
        sz=$(wc -c < "$f" | tr -d ' ')
        [ $first -eq 1 ] || echo ","
        first=0
        printf '    {"name": "%s", "size": %s}' "$b" "$sz"
    done
    echo ""
    echo "  ]"
    echo "}"
} > "${RELDIR}/manifest.json"

echo "==> Publishing channel pointer and installer"
echo "${VERSION}" > "${OUTROOT}/${CHANNEL}"
cp scripts/install.sh "${OUTROOT}/install.sh"
( cd "$OUTROOT" && sha256sum install.sh > install.sh.sha256 )

echo
echo "Release staged in ./${OUTROOT}/"
echo "  releases/v${VERSION}/   binaries + SHA256SUMS(+.minisig) + manifest.json"
echo "  ${CHANNEL}              -> ${VERSION}"
echo "  install.sh              public installer"
echo
echo "Publish with e.g.:"
echo "  rsync -av --delete ${OUTROOT}/ user@server:/var/www/emergency-tunnel/"
