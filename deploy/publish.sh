#!/usr/bin/env bash
#
# Publish a release to your host, in one command that stops at the first failure.
#
#   deploy/publish.sh <domain> [--allow-downgrade] [--no-pull]
#
# Env:
#   WEB_ROOT   document root to publish into (default /var/www/emergency-tunnel)
#   BRANCH     branch to pull            (default main)
#
# Steps: pull, build + bake, copy to the web root, verify what is served.
#
# Every step is fatal. Running these by hand is how a release goes wrong: a
# `git pull` that fails on authentication leaves a stale checkout behind, and the
# build that follows succeeds — at the old version — and quietly stages a
# downgrade for every user.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WEB_ROOT="${WEB_ROOT:-/var/www/emergency-tunnel}"
BRANCH="${BRANCH:-main}"
DOMAIN=""
PASS_ARGS=()
DO_PULL=1
while [ $# -gt 0 ]; do
    case "$1" in
        --allow-downgrade) PASS_ARGS+=("$1"); shift ;;
        --no-pull)         DO_PULL=0; shift ;;
        -*) echo "unknown option: $1" >&2; exit 2 ;;
        *)  DOMAIN="$1"; shift ;;
    esac
done

C_G='\033[0;32m'; C_Y='\033[1;33m'; C_C='\033[0;36m'; C_R='\033[0;31m'; C_0='\033[0m'
die()  { echo -e "${C_R}error: $*${C_0}" >&2; exit 1; }
step() { echo -e "\n${C_C}==> $*${C_0}"; }

[ -n "$DOMAIN" ] || die "usage: deploy/publish.sh <domain> [--allow-downgrade] [--no-pull]"

if [ "$DO_PULL" = "1" ]; then
    step "Updating the checkout"
    git rev-parse --git-dir >/dev/null 2>&1 || die "${ROOT} is not a git checkout"
    if ! git pull --ff-only origin "$BRANCH"; then
        echo
        echo -e "${C_Y}  The pull failed, so this checkout is still at:${C_0}"
        git log -1 --format='    %h %s (%cr)'
        echo -e "${C_Y}  Building from it would publish that old version. Fix the pull first.${C_0}"
        echo -e "${C_Y}  For a token, store it once instead of typing it:${C_0}"
        echo    "    git config --global credential.helper store"
        echo    "    printf 'https://x-access-token:<TOKEN>@github.com\\n' > ~/.git-credentials"
        echo    "    chmod 600 ~/.git-credentials"
        exit 1
    fi
fi
echo -e "  $(git log -1 --format='%h %s')"
echo -e "  VERSION: ${C_G}$(cat VERSION)${C_0}"

step "Building and baking for ${DOMAIN}"
deploy/configure-host.sh "$DOMAIN" "${PASS_ARGS[@]+"${PASS_ARGS[@]}"}"

step "Publishing to ${WEB_ROOT}"
[ -d "$WEB_ROOT" ] || die "${WEB_ROOT} does not exist (set WEB_ROOT=…)"
if command -v rsync >/dev/null 2>&1; then
    rsync -a release/ "${WEB_ROOT}/"
else
    cp -a release/. "${WEB_ROOT}/"
fi
chmod -R a+rX "$WEB_ROOT"
echo "  published $(cat VERSION)"

step "Verifying what ${DOMAIN} serves"
deploy/verify-host.sh "$DOMAIN" "$(cat VERSION)"

echo -e "${C_G}Published. Users update with:${C_0}"
echo    "  curl -fsSL https://${DOMAIN}/install.sh | bash -s -- --force"
