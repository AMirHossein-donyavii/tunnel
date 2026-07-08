#!/usr/bin/env bash
#
# Emergency Tunnel installer.
#
#   curl -fsSL https://raw.githubusercontent.com/AMirHossein-donyavii/tunnel/main/scripts/install.sh | bash
#
# Pin a version (note the `-s --` to pass args through a pipe):
#   curl -fsSL <install-url> | bash -s -- --version 1.2.0
#
# Sources (ET_SOURCE):
#   github  (default) — download signed binaries from this repo's GitHub Releases
#   host              — download from your own web server (ET_BASE_URL layout)
#   (ET_FROM_SOURCE=1 builds from Go source instead of downloading)
#
# Environment overrides:
#   ET_SOURCE         github | host            (default: github)
#   ET_REPO_SLUG      owner/repo for github source (default below)
#   ET_BASE_URL       release host root (host source) — set to YOUR domain
#   ET_CHANNEL        stable | beta            (host source; default: stable)
#   ET_VERSION        pin an exact version, e.g. 1.2.0
#   ET_PUBKEY         minisign public key line for signature verification (host)
#   ET_FROM_SOURCE=1  build from Go source instead of downloading a binary
#   ET_ALLOW_INSECURE=1  permit non-HTTPS base URL / skip signature (discouraged)
#   ET_FORCE=1        reinstall even if the target version is already installed
#
set -euo pipefail

# ============================ configuration =================================
ET_SOURCE="${ET_SOURCE:-github}"
ET_REPO_SLUG="${ET_REPO_SLUG:-AMirHossein-donyavii/tunnel}"
ET_BASE_URL="${ET_BASE_URL:-https://example.com}"
ET_CHANNEL="${ET_CHANNEL:-stable}"
ET_VERSION="${ET_VERSION:-}"
# Paste your release signing key here so the installer can verify offline.
# Get it from your web root: https://<host>/minisign.pub  (second line).
ET_PUBKEY="${ET_PUBKEY:-}"
ET_FROM_SOURCE="${ET_FROM_SOURCE:-0}"
ET_ALLOW_INSECURE="${ET_ALLOW_INSECURE:-0}"
ET_FORCE="${ET_FORCE:-0}"
# Source-build fallback settings:
ET_REPO="${ET_REPO:-https://github.com/${ET_REPO_SLUG}.git}"
ET_GO_VERSION="${ET_GO_VERSION:-1.22.5}"

PREFIX="/usr/local/bin"
CONF_DIR="/etc/emergency-tunnel"
LOG_DIR="/var/log/emergency-tunnel"
UNIT_DIR="/etc/systemd/system"
LIB_DIR="/usr/local/lib/emergency-tunnel"
# ============================================================================

# ---- argument parsing (supports `bash -s -- --flag`) -----------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --version)   ET_VERSION="${2#v}"; shift 2 ;;
        --channel)   ET_CHANNEL="$2"; shift 2 ;;
        --base-url)  ET_BASE_URL="$2"; shift 2 ;;
        --from-source) ET_FROM_SOURCE=1; shift ;;
        --force)     ET_FORCE=1; shift ;;
        --uninstall) DO_UNINSTALL=1; shift ;;
        -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# ---- pretty output ---------------------------------------------------------
if [ -t 1 ]; then
    C_RESET='\033[0m'; C_R='\033[0;31m'; C_G='\033[0;32m'; C_Y='\033[1;33m'; C_B='\033[0;34m'; C_C='\033[0;36m'
else
    C_RESET=''; C_R=''; C_G=''; C_Y=''; C_B=''; C_C=''
fi
info()  { echo -e "${C_C}[*]${C_RESET} $*"; }
ok()    { echo -e "${C_G}[+]${C_RESET} $*"; }
warn()  { echo -e "${C_Y}[!]${C_RESET} $*"; }
step()  { echo -e "\n${C_B}==>${C_RESET} ${C_Y}$*${C_RESET}"; }
die()   { echo -e "${C_R}[-] ERROR: $*${C_RESET}" >&2; exit 1; }

TMP=""
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP" 2>/dev/null || true; }
trap cleanup EXIT
trap 'die "interrupted"' INT TERM

[ "$(id -u)" -eq 0 ] || die "please run as root (e.g. pipe into 'sudo bash')."

# ---- helpers ---------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

DL_OPTS=(--fail --silent --show-error --location --retry 3 --retry-delay 1 --connect-timeout 15)
if [ "$ET_ALLOW_INSECURE" = "1" ]; then
    warn "insecure mode: TLS enforcement disabled"
else
    DL_OPTS+=(--proto '=https' --tlsv1.2)
    case "$ET_BASE_URL" in
        https://*) : ;;
        *) die "ET_BASE_URL must be https:// (set ET_ALLOW_INSECURE=1 to override for testing)";;
    esac
fi

dl() { # dl <url> <dest>
    curl "${DL_OPTS[@]}" -o "$2" "$1" || die "download failed: $1"
}
dl_str() { # dl_str <url> -> stdout
    curl "${DL_OPTS[@]}" "$1"
}

sha256_of() { # file -> hash
    if have sha256sum; then sha256sum "$1" | awk '{print $1}'
    elif have shasum; then shasum -a 256 "$1" | awk '{print $1}'
    else die "no sha256 tool (need coreutils)"; fi
}

# ---- distro / arch detection ----------------------------------------------
detect() {
    step "Detecting system"
    [ "$(uname -s)" = "Linux" ] || die "Emergency Tunnel targets Linux servers."
    if [ -r /etc/os-release ]; then . /etc/os-release; DISTRO_ID="${ID:-unknown}"; else DISTRO_ID="unknown"; fi
    case "$(uname -m)" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l|armv7)  ARCH="armv7" ;;
        *) die "unsupported architecture: $(uname -m)";;
    esac
    have systemctl || warn "systemd not detected — service management will be unavailable."
    ok "Linux/${DISTRO_ID} on ${ARCH}"
}

pkg_install() {
    local pkgs="$*"
    if   have apt-get; then DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $pkgs
    elif have dnf;     then dnf install -y -q $pkgs
    elif have yum;     then yum install -y -q $pkgs
    elif have pacman;  then pacman -Sy --noconfirm --needed $pkgs
    elif have apk;     then apk add --no-cache $pkgs
    elif have zypper;  then zypper --non-interactive install $pkgs
    else warn "no known package manager; ensure installed: $pkgs"; return 1; fi
}

install_deps() {
    step "Ensuring dependencies"
    have curl || pkg_install curl ca-certificates || die "curl is required"
    have tar  || pkg_install tar || true
    { have sha256sum || have shasum; } || pkg_install coreutils || true
    ok "Dependencies ready"
}

# ---- version resolution ----------------------------------------------------
resolve_version() {
    step "Resolving version"
    if [ "$ET_SOURCE" = "github" ]; then
        if [ -n "$ET_VERSION" ]; then
            VERSION="$ET_VERSION"; info "pinned version: ${VERSION}"
        else
            info "fetching latest release from github.com/${ET_REPO_SLUG}"
            VERSION="$(dl_str "https://api.github.com/repos/${ET_REPO_SLUG}/releases/latest" \
                | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name":[[:space:]]*"v?([^"]+)".*/\1/')" \
                || die "cannot query GitHub releases"
        fi
        REL_URL="https://github.com/${ET_REPO_SLUG}/releases/download/v${VERSION}"
    else
        if [ -n "$ET_VERSION" ]; then
            VERSION="$ET_VERSION"; info "pinned version: ${VERSION}"
        else
            info "fetching channel '${ET_CHANNEL}' from ${ET_BASE_URL}"
            VERSION="$(dl_str "${ET_BASE_URL}/${ET_CHANNEL}" | tr -d '[:space:]')" \
                || die "cannot resolve channel '${ET_CHANNEL}'"
        fi
        REL_URL="${ET_BASE_URL}/releases/v${VERSION}"
    fi
    echo "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z]+)*$' \
        || die "resolved version looks invalid: '${VERSION}'"
    ok "Target version: v${VERSION}  (source: ${ET_SOURCE})"
}

installed_version() { [ -f "${LIB_DIR}/VERSION" ] && cat "${LIB_DIR}/VERSION" || echo ""; }

# ---- download + verify -----------------------------------------------------
verify_against_sums() { # <name>
    local name="$1"
    local expected actual
    # Accept both "name" and "./name" forms in SHA256SUMS for robustness.
    expected="$(awk -v f="${name}" '$2==f || $2=="./"f {print $1}' "${TMP}/SHA256SUMS")"
    [ -n "$expected" ] || die "no checksum listed for ${name}"
    actual="$(sha256_of "${TMP}/${name}")"
    [ "$expected" = "$actual" ] || die "checksum mismatch for ${name} (expected ${expected}, got ${actual})"
    ok "verified ${name}"
}

download_release() {
    step "Downloading release v${VERSION}"
    TMP="$(mktemp -d)"
    dl "${REL_URL}/SHA256SUMS" "${TMP}/SHA256SUMS"

    # Signature verification (host source only; GitHub relies on TLS + SHA-256).
    if [ "$ET_SOURCE" = "host" ] && [ -n "$ET_PUBKEY" ] && [ "$ET_ALLOW_INSECURE" != "1" ]; then
        have minisign || pkg_install minisign || true
        if have minisign; then
            dl "${REL_URL}/SHA256SUMS.minisig" "${TMP}/SHA256SUMS.minisig"
            minisign -Vm "${TMP}/SHA256SUMS" -P "$ET_PUBKEY" >/dev/null 2>&1 \
                || die "signature verification FAILED — refusing to install"
            ok "minisign signature verified"
        else
            warn "minisign unavailable; relying on TLS + SHA-256 only"
        fi
    else
        info "integrity: TLS + SHA-256 checksums"
    fi

    local asset="et-core-linux-${ARCH}"
    for f in "$asset" et-panel.sh emergency-tunnel@.service uninstall.sh; do
        info "fetching ${f}"
        dl "${REL_URL}/${f}" "${TMP}/${f}"
        verify_against_sums "$f"
    done
    CORE_BIN="${TMP}/${asset}"
}

# ---- source build fallback -------------------------------------------------
ensure_go() {
    have go && { GO_BIN="$(command -v go)"; return; }
    step "Bootstrapping Go ${ET_GO_VERSION}"
    local tb="go${ET_GO_VERSION}.linux-${ARCH}.tar.gz"
    [ "$ARCH" = "armv7" ] && tb="go${ET_GO_VERSION}.linux-armv6l.tar.gz"
    dl "https://go.dev/dl/${tb}" "${TMP}/${tb}"
    rm -rf /usr/local/go && tar -C /usr/local -xzf "${TMP}/${tb}"
    GO_BIN="/usr/local/go/bin/go"; export PATH="/usr/local/go/bin:${PATH}"
    ok "installed $("$GO_BIN" version)"
}

build_from_source() {
    step "Building from source"
    TMP="$(mktemp -d)"
    ensure_go
    have git || pkg_install git || die "git required for source build"
    local src="${TMP}/src"
    if [ -f "./go.mod" ] && grep -q emergency-tunnel ./go.mod 2>/dev/null; then
        src="$(pwd)"; info "using current checkout"
    else
        info "cloning ${ET_REPO}"
        git clone --depth 1 "$ET_REPO" "$src" || die "git clone failed"
    fi
    ( cd "$src" && CGO_ENABLED=0 "$GO_BIN" build -trimpath \
        -ldflags "-s -w -X github.com/emergency-tunnel/et/internal/core.CoreVersion=${VERSION:-dev}" \
        -o "${TMP}/et-core-linux-${ARCH}" ./cmd/et-core ) || die "build failed"
    CORE_BIN="${TMP}/et-core-linux-${ARCH}"
    cp "$src/scripts/et-panel.sh" "${TMP}/et-panel.sh"
    cp "$src/scripts/uninstall.sh" "${TMP}/uninstall.sh"
    cp "$src/systemd/emergency-tunnel@.service" "${TMP}/emergency-tunnel@.service"
}

# ---- install ---------------------------------------------------------------
install_files() {
    step "Installing"
    local prev; prev="$(installed_version)"
    if [ -n "$prev" ] && [ "$prev" = "$VERSION" ] && [ "$ET_FORCE" != "1" ]; then
        info "v${VERSION} already installed (use --force to reinstall)"
    fi

    install -d -m 0755 "$PREFIX" "$LIB_DIR"
    install -d -m 0750 "$CONF_DIR" "$LOG_DIR"

    install -m 0755 "$CORE_BIN"                 "${PREFIX}/et-core"
    install -m 0755 "${TMP}/et-panel.sh"        "${PREFIX}/et"
    install -m 0755 "${TMP}/uninstall.sh"       "${LIB_DIR}/uninstall.sh"
    install -m 0644 "${TMP}/emergency-tunnel@.service" "${UNIT_DIR}/emergency-tunnel@.service"
    echo "$VERSION" > "${LIB_DIR}/VERSION"
    # Record how to update later (used by the panel's "Update core").
    if [ "$ET_SOURCE" = "github" ]; then
        echo "https://raw.githubusercontent.com/${ET_REPO_SLUG}/main/scripts/install.sh" > "${LIB_DIR}/UPDATE_URL"
    else
        echo "${ET_BASE_URL}/install.sh" > "${LIB_DIR}/UPDATE_URL"
    fi

    if have systemctl; then systemctl daemon-reload; fi
    ok "installed to ${PREFIX}/et-core and ${PREFIX}/et"
    if [ -n "$prev" ] && [ "$prev" != "$VERSION" ]; then
        ok "upgraded ${prev} -> ${VERSION}"
        restart_running
    fi
}

restart_running() {
    have systemctl || return 0
    local units; units="$(systemctl list-units 'emergency-tunnel@*.service' --no-legend 2>/dev/null | awk '{print $1}')"
    [ -n "$units" ] || return 0
    info "restarting active tunnels with the new core"
    # shellcheck disable=SC2086
    systemctl restart $units || warn "some tunnels failed to restart; check 'et' -> status"
}

verify_install() {
    step "Verifying"
    local v
    v="$("${PREFIX}/et-core" version 2>/dev/null | awk -F': *' '{print $2}' | tr -d ' v')" || die "et-core will not run"
    [ "$v" = "$VERSION" ] || warn "reported core version '${v}' != target '${VERSION}'"
    ok "core responds: v${v}"
    "${PREFIX}/et-core" transports || true
    have et >/dev/null 2>&1 || warn "panel 'et' not on PATH (expected ${PREFIX} in PATH)"
}

banner() {
    echo -e "${C_G}"
    cat <<'BANNER'
  ______                                                 _____                       _
 |  ____|                                               |_   _|                     | |
 | |__   _ __ ___   ___ _ __ __ _  ___ _ __   ___ _   _   | |  _   _ _ __  _ __   ___| |
 |  __| | '_ ` _ \ / _ \ '__/ _` |/ _ \ '_ \ / __| | | |  | | | | | | '_ \| '_ \ / _ \ |
 | |____| | | | | |  __/ | | (_| |  __/ | | | (__| |_| |  | |_| |_| | | | | | | |  __/ |
 |______|_| |_| |_|\___|_|  \__, |\___|_| |_|\___|\__, | |_____\__,_|_| |_|_| |_|\___|_|
                             __/ |                 __/ |
                            |___/                 |___/
BANNER
    echo -e "${C_RESET}       Emergency Tunnel installer\n"
}

# ---- uninstall passthrough -------------------------------------------------
if [ "${DO_UNINSTALL:-0}" = "1" ]; then
    [ -f "${LIB_DIR}/uninstall.sh" ] && exec bash "${LIB_DIR}/uninstall.sh"
    die "uninstaller not found; reinstall first or remove manually"
fi

# ---- main ------------------------------------------------------------------
main() {
    banner
    detect
    install_deps
    resolve_version
    if [ "$ET_FROM_SOURCE" = "1" ]; then
        build_from_source
    else
        download_release
    fi
    install_files
    verify_install

    echo
    ok "Installation complete — Emergency Tunnel v${VERSION}"
    echo -e "   Panel:   ${C_Y}et${C_RESET}"
    echo -e "   Configs: ${C_C}${CONF_DIR}${C_RESET}    Logs: ${C_C}${LOG_DIR}${C_RESET}"
    local upd; upd="$(cat "${LIB_DIR}/UPDATE_URL" 2>/dev/null || echo "")"
    [ -n "$upd" ] && echo -e "   Update later:  ${C_C}curl -fsSL ${upd} | bash${C_RESET}"
    echo
    if [ -t 0 ] && have et; then
        read -r -p "Launch the panel now? [Y/n] " ans
        case "${ans:-Y}" in [Nn]*) : ;; *) exec et ;; esac
    fi
}
main
