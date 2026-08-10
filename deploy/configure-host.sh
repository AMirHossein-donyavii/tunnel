#!/usr/bin/env bash
#
# Configure Emergency Tunnel for self-hosting: build the release tree and bake
# your domain into install.sh so users can install with a single clean command.
#
# Usage:
#   deploy/configure-host.sh <domain> [version]
#
# Example:
#   deploy/configure-host.sh dl.example.com 1.2.0
#
# Then follow the printed steps: rsync ./release/ to your web root and serve it
# over HTTPS (deploy/nginx or deploy/caddy).
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DOMAIN="${1:-}"
VERSION="${2:-$(cat VERSION 2>/dev/null || echo 0.0.0)}"
VERSION="${VERSION#v}"

C_G='\033[0;32m'; C_Y='\033[1;33m'; C_C='\033[0;36m'; C_R='\033[0;31m'; C_0='\033[0m'
die() { echo -e "${C_R}error: $*${C_0}" >&2; exit 1; }

[ -n "$DOMAIN" ] || die "usage: deploy/configure-host.sh <domain> [version]"
case "$DOMAIN" in http*://*) die "pass a bare domain (dl.example.com), not a URL";; esac
command -v go >/dev/null || die "Go toolchain required to build the release"

BASE_URL="https://${DOMAIN}"

echo -e "${C_C}==> Building release v${VERSION}${C_0}"
SIGN_ARGS=()
if command -v minisign >/dev/null 2>&1 && [ -n "${MINISIGN_KEY:-}" ]; then
    SIGN_ARGS=(--sign)
    echo "    (signing enabled via MINISIGN_KEY)"
fi
scripts/build-release.sh "$VERSION" --channel stable "${SIGN_ARGS[@]}"

echo -e "${C_C}==> Baking host settings into release/install.sh${C_0}"
IN="release/install.sh"
[ -f "$IN" ] || die "release/install.sh not found (build failed?)"
# Flip the two defaults so the hosted copy targets YOUR server with no env vars.
# Match whatever default is currently there rather than one specific literal: a
# pattern that silently stops matching turns this whole step into a no-op that
# still reports success, and the mis-targeted installer only surfaces later on a
# user's server.
sed -i.bak -E \
    -e 's|^ET_SOURCE="\$\{ET_SOURCE:-[^}]*\}"|ET_SOURCE="${ET_SOURCE:-host}"|' \
    -e "s|^ET_BASE_URL=\"\\\$\\{ET_BASE_URL:-[^}]*\\}\"|ET_BASE_URL=\"\\\${ET_BASE_URL:-${BASE_URL}}\"|" \
    "$IN"
rm -f "${IN}.bak"
grep -qF "ET_BASE_URL=\"\${ET_BASE_URL:-${BASE_URL}}\"" "$IN" \
    || die "could not bake ET_BASE_URL into ${IN} — the installer's defaults changed shape"
grep -qF 'ET_SOURCE="${ET_SOURCE:-host}"' "$IN" \
    || die "could not bake ET_SOURCE into ${IN} — the installer's defaults changed shape"
echo "    ET_BASE_URL=${BASE_URL}  ET_SOURCE=host"

# If a public signing key is present, embed it and publish it too.
if [ -f minisign.pub ]; then
    PUB="$(sed -n '2p' minisign.pub)"
    sed -i.bak "s|^ET_PUBKEY=\"\${ET_PUBKEY:-}\"|ET_PUBKEY=\"\${ET_PUBKEY:-${PUB}}\"|" "$IN"
    rm -f "${IN}.bak"
    cp minisign.pub release/minisign.pub
    echo "    embedded minisign public key (offline verification enabled)"
fi

# Refresh the root checksum for the (now edited) installer.
( cd release && sha256sum install.sh > install.sh.sha256 )

echo
echo -e "${C_G}Release ready in ./release/ for https://${DOMAIN}${C_0}"
echo
echo -e "Next steps:"
echo -e "  1) Upload to your web root:"
echo -e "       ${C_Y}rsync -av --delete ./release/ root@${DOMAIN}:/var/www/emergency-tunnel/${C_0}"
echo -e "  2) Serve it over HTTPS (pick one):"
echo -e "       Caddy:  edit deploy/caddy/Caddyfile (set ${DOMAIN}) then run caddy"
echo -e "       nginx:  cp deploy/nginx/emergency-tunnel.conf /etc/nginx/conf.d/ ; certbot --nginx -d ${DOMAIN}"
echo -e "  3) Your users install with:"
echo -e "       ${C_Y}curl -fsSL https://${DOMAIN}/install.sh | bash${C_0}"
echo
echo -e "Verify after upload: ${C_C}curl -fsSL https://${DOMAIN}/stable${C_0}  (should print ${VERSION})"
