#!/usr/bin/env bash
#
# Verify what a release host is actually serving.
#
#   deploy/verify-host.sh <domain|base-url> [expected-version]
#
# Run this after uploading ./release/ to the web root, before telling anyone to
# update. Building and copying a release can succeed while the host still serves
# a stale file — most damagingly a stale et-panel.sh, which installs a current
# core next to an old console: same menus, new binary, and an update that looks
# like it did nothing.
#
# Checks, in order:
#   1. the channel pointer resolves to a version
#   2. install.sh is present, matches its published checksum, and is baked to
#      this host
#   3. every asset in the release directory matches SHA256SUMS
#   4. the served panel's SCRIPT_VERSION equals the channel version
#   5. the served core binary reports the channel version (native arch only)
#
# Exits non-zero if any check fails.
#
set -uo pipefail

BASE="${1:-}"
WANT="${2:-}"
case "$BASE" in
    "")        echo "usage: deploy/verify-host.sh <domain|base-url> [expected-version]" >&2; exit 2 ;;
    http://*|https://*|file://*) ;;
    *)         BASE="https://${BASE}" ;;
esac
BASE="${BASE%/}"
WANT="${WANT#v}"

if [ -t 1 ]; then
    R=$'\033[0m'; B=$'\033[1m'; RED=$'\033[38;5;203m'; GRN=$'\033[38;5;114m'
    YEL=$'\033[38;5;221m'; CYN=$'\033[38;5;80m'; GRY=$'\033[38;5;245m'
else R=''; B=''; RED=''; GRN=''; YEL=''; CYN=''; GRY=''; fi

FAILED=0
pass() { printf "  ${GRN}✓${R} %s\n" "$*"; }
fail() { printf "  ${RED}✗${R} %s\n" "$*"; FAILED=$((FAILED+1)); }
warn() { printf "  ${YEL}!${R} %s\n" "$*"; }
note() { printf "    ${GRY}%s${R}\n" "$*"; }
step() { printf "\n${B}${CYN}%s${R}\n" "$*"; }

CURL=(curl --fail --silent --show-error --location --connect-timeout 15 --max-time 300)
get()  { "${CURL[@]}" "$1"; }
save() { "${CURL[@]}" -o "$2" "$1"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

sha_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

printf "\n${B}Verifying %s${R}\n" "$BASE"

# ---- 1. channel pointer ----------------------------------------------------
step "Channel"
VERSION="$(get "${BASE}/stable" 2>/dev/null | tr -d '[:space:]')"
if [ -z "$VERSION" ]; then
    fail "cannot read ${BASE}/stable"
    note "the web root is missing the channel pointer — nothing else can be checked"
    exit 1
fi
pass "stable -> ${VERSION}"
if [ -n "$WANT" ] && [ "$WANT" != "$VERSION" ]; then
    fail "expected v${WANT}, host advertises v${VERSION}"
    note "the upload did not land, or it was built for a different version"
fi

REL="${BASE}/releases/v${VERSION}"

# ---- 2. installer ----------------------------------------------------------
step "Installer"
if save "${BASE}/install.sh" "${TMP}/install.sh"; then
    pass "install.sh served"
    if pub="$(get "${BASE}/install.sh.sha256" 2>/dev/null | awk '{print $1}')" && [ -n "$pub" ]; then
        if [ "$pub" = "$(sha_of "${TMP}/install.sh")" ]; then pass "install.sh matches its published checksum"
        else fail "install.sh does not match install.sh.sha256 — a stale copy is being served"; fi
    else
        warn "install.sh.sha256 not published"
    fi
    host_default="$(grep -m1 '^ET_BASE_URL=' "${TMP}/install.sh" | sed -E 's/.*:-([^}]*)\}.*/\1/')"
    if [ "${host_default%/}" = "$BASE" ]; then pass "baked to this host"
    else fail "install.sh targets ${host_default:-<unset>}, not ${BASE}"
         note "re-run deploy/configure-host.sh <domain> and re-upload"; fi
    bash -n "${TMP}/install.sh" 2>/dev/null && pass "install.sh parses" || fail "install.sh is not valid bash"
else
    fail "cannot fetch ${BASE}/install.sh — 'curl … | bash' is broken for every user"
fi

# ---- 3. release assets -----------------------------------------------------
step "Release v${VERSION}"
if ! save "${REL}/SHA256SUMS" "${TMP}/SHA256SUMS"; then
    fail "cannot fetch ${REL}/SHA256SUMS"
    note "the installer aborts here, so no client can update to v${VERSION}"
    exit 1
fi
pass "SHA256SUMS served"

while read -r want name; do
    [ -n "$name" ] || continue
    name="${name#./}"
    if ! save "${REL}/${name}" "${TMP}/${name}"; then fail "missing: ${name}"; continue; fi
    if [ "$want" = "$(sha_of "${TMP}/${name}")" ]; then pass "${name}"
    else fail "${name} — checksum mismatch (stale file on the host)"; fi
done < "${TMP}/SHA256SUMS"

# ---- 4. panel version ------------------------------------------------------
step "Console"
if [ -f "${TMP}/et-panel.sh" ]; then
    pv="$(grep -m1 '^SCRIPT_VERSION=' "${TMP}/et-panel.sh" | cut -d'"' -f2)"
    if [ "$pv" = "$VERSION" ]; then pass "et-panel.sh is v${pv}"
    else fail "et-panel.sh is v${pv:-unknown}, channel is v${VERSION}"
         note "this is the stale-console case: users get a current core and old menus"; fi
else
    fail "et-panel.sh is not listed in SHA256SUMS — the console will not be installed"
fi

# ---- 5. core binary --------------------------------------------------------
step "Core"
case "$(uname -m)" in
    x86_64|amd64)  native="et-core-linux-amd64" ;;
    aarch64|arm64) native="et-core-linux-arm64" ;;
    armv7l|armv7)  native="et-core-linux-armv7" ;;
    *)             native="" ;;
esac
if [ -n "$native" ] && [ -f "${TMP}/${native}" ]; then
    chmod +x "${TMP}/${native}"
    cv="$("${TMP}/${native}" version 2>/dev/null | awk -F': *' '/Core Version/{print $2}' | tr -d 'v ')"
    if [ "$cv" = "$VERSION" ]; then pass "${native} reports v${cv}"
    elif [ -z "$cv" ]; then fail "${native} will not run on this host"
    else fail "${native} reports v${cv}, channel is v${VERSION}"; fi
else
    warn "no binary for $(uname -m) to run here — checksums above still apply"
fi

# ---- verdict ---------------------------------------------------------------
echo
if [ "$FAILED" -eq 0 ]; then
    printf "${GRN}${B}  %s is serving v%s correctly.${R}\n\n" "$BASE" "$VERSION"
    printf "  Users install with: ${B}curl -fsSL %s/install.sh | bash${R}\n\n" "$BASE"
    exit 0
fi
printf "${RED}${B}  %d check(s) failed — do not announce this release yet.${R}\n\n" "$FAILED"
exit 1
