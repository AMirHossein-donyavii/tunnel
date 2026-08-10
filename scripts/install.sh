#!/usr/bin/env bash
#
# Emergency Tunnel installer.
#
#   curl -fsSL https://script-tunnel.emergency-service.org/install.sh | bash
#
# Options (note the `-s --` when piping):
#   curl -fsSL <url> | bash -s -- --version 1.13.0
#
#   --version <v>    install an exact version instead of the channel head
#   --channel <c>    stable | beta                     (default: stable)
#   --base-url <u>   release host root                 (default below)
#   --source <s>     host | github | source | auto     (default: auto)
#   --from-source    build from Go source instead of downloading
#   --force          reinstall even if already at the target version
#   --no-tune        skip host network tuning (BBR/fq/buffers)
#   --uninstall      remove the tunnel (configs are kept unless you confirm)
#
# Environment overrides: ET_SOURCE, ET_REPO_SLUG, ET_BASE_URL, ET_CHANNEL,
# ET_VERSION, ET_PUBKEY, ET_FROM_SOURCE, ET_ALLOW_INSECURE, ET_FORCE, ET_NO_TUNE
#
# Where the build comes from (auto): the release host first, then GitHub
# Releases. Whichever answers, its version is compared against the VERSION file
# on the default branch — if the branch is newer, the installer builds that from
# source. An unreleased fix therefore still reaches you through `et` → Update;
# it never silently reinstalls the last published binary.
#
# Upgrades are safe: configurations in /etc/emergency-tunnel are never
# rewritten by the installer, running tunnels are restarted onto the new core,
# and `et --migrate` brings pre-2.0 configs forward afterwards.
set -euo pipefail

# ============================ configuration =================================
ET_BASE_URL="${ET_BASE_URL:-https://script-tunnel.emergency-service.org}"
ET_REPO_SLUG="${ET_REPO_SLUG:-AMirHossein-donyavii/tunnel}"
# host = the release web root above; github = this repo's Releases.
# "auto" tries host first and falls back to github, so a CDN or host outage
# does not block an install.
ET_SOURCE="${ET_SOURCE:-auto}"
ET_CHANNEL="${ET_CHANNEL:-stable}"
ET_VERSION="${ET_VERSION:-}"
ET_PUBKEY="${ET_PUBKEY:-}"
ET_FROM_SOURCE="${ET_FROM_SOURCE:-0}"
ET_ALLOW_INSECURE="${ET_ALLOW_INSECURE:-0}"
ET_FORCE="${ET_FORCE:-0}"
ET_NO_TUNE="${ET_NO_TUNE:-0}"
ET_REPO="${ET_REPO:-https://github.com/${ET_REPO_SLUG}.git}"
ET_GO_VERSION="${ET_GO_VERSION:-1.22.5}"

PREFIX="/usr/local/bin"
CONF_DIR="/etc/emergency-tunnel"
LOG_DIR="/var/log/emergency-tunnel"
UNIT_DIR="/etc/systemd/system"
LIB_DIR="/usr/local/lib/emergency-tunnel"
# ============================================================================

while [ $# -gt 0 ]; do
    case "$1" in
        --version)     ET_VERSION="${2#v}"; shift 2 ;;
        --channel)     ET_CHANNEL="$2"; shift 2 ;;
        --base-url)    ET_BASE_URL="$2"; ET_SOURCE="host"; shift 2 ;;
        --source)      ET_SOURCE="$2"; shift 2 ;;
        --from-source) ET_FROM_SOURCE=1; shift ;;
        --force)       ET_FORCE=1; shift ;;
        --no-tune)     ET_NO_TUNE=1; shift ;;
        --uninstall)   DO_UNINSTALL=1; shift ;;
        -h|--help)     sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# ---- output ----------------------------------------------------------------
if [ -t 1 ]; then
    R=$'\033[0m'; B=$'\033[1m'; RED=$'\033[38;5;203m'; GRN=$'\033[38;5;114m'
    YEL=$'\033[38;5;221m'; CYN=$'\033[38;5;80m'; GRY=$'\033[38;5;245m'
else R=''; B=''; RED=''; GRN=''; YEL=''; CYN=''; GRY=''; fi
info() { printf "  ${GRY}%s${R}\n" "$*"; }
ok()   { printf "  ${GRN}✓${R} %s\n" "$*"; }
warn() { printf "  ${YEL}!${R} %s\n" "$*"; }
step() { printf "\n${B}${CYN}%s${R}\n" "$*"; }
die()  { printf "  ${RED}✗ %s${R}\n" "$*" >&2; exit 1; }

TMP=""
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP" 2>/dev/null || true; }
trap cleanup EXIT
trap 'die "interrupted"' INT TERM

[ "$(id -u)" -eq 0 ] || die "run as root (pipe into 'sudo bash')."
have() { command -v "$1" >/dev/null 2>&1; }

DL_OPTS=(--fail --silent --show-error --location --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 300)
if [ "$ET_ALLOW_INSECURE" = "1" ]; then
    warn "insecure mode: TLS enforcement relaxed"
else
    DL_OPTS+=(--proto '=https' --tlsv1.2)
fi
dl()     { curl "${DL_OPTS[@]}" -o "$2" "$1"; }
dl_str() { curl "${DL_OPTS[@]}" "$1"; }
sha256_of() {
    if have sha256sum; then sha256sum "$1" | awk '{print $1}'
    elif have shasum;  then shasum -a 256 "$1" | awk '{print $1}'
    else die "no sha256 tool available (install coreutils)"; fi
}

# ---- detection -------------------------------------------------------------
detect() {
    step "System"
    [ "$(uname -s)" = "Linux" ] || die "Emergency Tunnel targets Linux servers."
    [ -r /etc/os-release ] && . /etc/os-release
    DISTRO="${PRETTY_NAME:-${ID:-unknown}}"
    case "$(uname -m)" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l|armv7)  ARCH="armv7" ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
    KERNEL="$(uname -r)"
    info "${DISTRO} · ${ARCH} · kernel ${KERNEL} · $(nproc 2>/dev/null || echo '?') core(s)"
    have systemctl || warn "systemd not found — tunnels can be built but not managed as services"
    # /dev/net/tun is required by the TUN, Gaming and SPF sections.
    if [ ! -c /dev/net/tun ]; then
        modprobe tun 2>/dev/null || true
        [ -c /dev/net/tun ] || warn "/dev/net/tun missing — only the Basic section will work on this host"
    fi
    ok "system supported"
}

pkg_install() {
    if   have apt-get; then DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
                            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1
    elif have dnf;     then dnf install -y -q "$@" >/dev/null 2>&1
    elif have yum;     then yum install -y -q "$@" >/dev/null 2>&1
    elif have pacman;  then pacman -Sy --noconfirm --needed "$@" >/dev/null 2>&1
    elif have apk;     then apk add --no-cache "$@" >/dev/null 2>&1
    elif have zypper;  then zypper --non-interactive install "$@" >/dev/null 2>&1
    else return 1; fi
}

install_deps() {
    step "Dependencies"
    local missing=()
    have curl || missing+=(curl)
    have ss   || missing+=(iproute2)
    have ip   || missing+=(iproute2)
    { have sha256sum || have shasum; } || missing+=(coreutils)
    if [ "${#missing[@]}" -gt 0 ]; then
        info "installing: ${missing[*]}"
        pkg_install "${missing[@]}" || warn "could not install ${missing[*]} automatically"
    fi
    have curl || die "curl is required"
    have ip   || warn "iproute2 missing — TUN tunnels cannot configure their interface"
    ok "dependencies ready"
}

# ---- version + source resolution -------------------------------------------
is_semver() { printf '%s' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z]+)*$'; }

# ver_gt A B — true when A is strictly newer than B.
ver_gt() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" = "$1" ]
}

# The version of the sources on the default branch. This is the authority for
# "what is the newest Emergency Tunnel", independently of whether a release has
# been cut for it — an unreleased commit must never leave `et` stuck on an old
# binary with no way forward.
branch_version() {
    dl_str "https://raw.githubusercontent.com/${ET_REPO_SLUG}/main/VERSION" 2>/dev/null | tr -d '[:space:]'
}

# resolve_from <host|github> — sets VERSION and REL_URL, or fails.
resolve_from() {
    case "$1" in
      host)
        if [ -n "$ET_VERSION" ]; then VERSION="$ET_VERSION"
        else VERSION="$(dl_str "${ET_BASE_URL}/${ET_CHANNEL}" | tr -d '[:space:]')" || return 1; fi
        REL_URL="${ET_BASE_URL}/releases/v${VERSION}" ;;
      github)
        if [ -n "$ET_VERSION" ]; then VERSION="$ET_VERSION"
        else VERSION="$(dl_str "https://api.github.com/repos/${ET_REPO_SLUG}/releases/latest" \
              | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name":[[:space:]]*"v?([^"]+)".*/\1/')" || return 1; fi
        REL_URL="https://github.com/${ET_REPO_SLUG}/releases/download/v${VERSION}" ;;
    esac
    [ -n "${VERSION:-}" ] || return 1
    is_semver "$VERSION" || return 1
    SOURCE_USED="$1"
    return 0
}

# prefer_branch_source switches an otherwise-resolved install over to a source
# build when the default branch carries a newer version than any published
# release. Without this, an update run silently reinstalls the last released
# binary and the user sees nothing change.
prefer_branch_source() {
    [ -n "$ET_VERSION" ] && return 0   # an exact version was requested — honour it
    local bv; bv="$(branch_version)" || return 0
    [ -n "$bv" ] && is_semver "$bv" || return 0
    if [ -z "${VERSION:-}" ] || ver_gt "$bv" "$VERSION"; then
        if [ -n "${VERSION:-}" ]; then
            warn "newest release is v${VERSION}, but the sources are at v${bv} — building from source"
        else
            warn "no published release reachable — building v${bv} from source"
        fi
        VERSION="$bv"; RESOLVED_FROM="$SOURCE_USED"; SOURCE_USED="source"
    fi
}

resolve_version() {
    step "Release"
    case "$ET_SOURCE" in
        host|github) resolve_from "$ET_SOURCE" || die "cannot resolve a version from '${ET_SOURCE}'" ;;
        source)      VERSION="${ET_VERSION:-}"; SOURCE_USED="source" ;;
        auto)
            if resolve_from host; then :
            elif warn "release host unreachable — falling back to GitHub Releases"; resolve_from github; then :
            else
                VERSION=""; SOURCE_USED="source"
            fi
            prefer_branch_source ;;
        *) die "unknown ET_SOURCE '${ET_SOURCE}' (host|github|source|auto)" ;;
    esac
    [ "$SOURCE_USED" = "source" ] || ok "v${VERSION} (source: ${SOURCE_USED})"
}

installed_version() { [ -f "${LIB_DIR}/VERSION" ] && cat "${LIB_DIR}/VERSION" || echo ""; }

verify_against_sums() {
    local name="$1" expected actual
    expected="$(awk -v f="$name" '$2==f || $2=="./"f {print $1}' "${TMP}/SHA256SUMS")"
    [ -n "$expected" ] || die "no checksum listed for ${name}"
    actual="$(sha256_of "${TMP}/${name}")"
    [ "$expected" = "$actual" ] || die "checksum mismatch for ${name}"
}

download_release() {
    step "Download"
    TMP="$(mktemp -d)"
    dl "${REL_URL}/SHA256SUMS" "${TMP}/SHA256SUMS" || die "cannot fetch SHA256SUMS from ${REL_URL}"

    if [ "$SOURCE_USED" = "host" ] && [ -n "$ET_PUBKEY" ] && [ "$ET_ALLOW_INSECURE" != "1" ]; then
        have minisign || pkg_install minisign || true
        if have minisign; then
            dl "${REL_URL}/SHA256SUMS.minisig" "${TMP}/SHA256SUMS.minisig" || die "signature missing"
            minisign -Vm "${TMP}/SHA256SUMS" -P "$ET_PUBKEY" >/dev/null 2>&1 \
                || die "signature verification FAILED — refusing to install"
            ok "signature verified"
        else warn "minisign unavailable — relying on TLS + SHA-256"; fi
    fi

    local asset="et-core-linux-${ARCH}"
    for f in "$asset" et-panel.sh emergency-tunnel@.service uninstall.sh; do
        dl "${REL_URL}/${f}" "${TMP}/${f}" || die "cannot fetch ${f}"
        verify_against_sums "$f"
    done
    ok "4 files downloaded and verified"
    CORE_BIN="${TMP}/${asset}"
}

# ---- source build ----------------------------------------------------------
ensure_go() {
    have go && { GO_BIN="$(command -v go)"; return; }
    step "Go toolchain"
    local tb="go${ET_GO_VERSION}.linux-${ARCH}.tar.gz"
    [ "$ARCH" = "armv7" ] && tb="go${ET_GO_VERSION}.linux-armv6l.tar.gz"
    dl "https://go.dev/dl/${tb}" "${TMP}/${tb}" || die "cannot download Go"
    rm -rf /usr/local/go && tar -C /usr/local -xzf "${TMP}/${tb}"
    GO_BIN="/usr/local/go/bin/go"; export PATH="/usr/local/go/bin:${PATH}"
    ok "$("$GO_BIN" version)"
}

build_from_source() {
    step "Build from source"
    TMP="$(mktemp -d)"; ensure_go
    have git || pkg_install git || die "git required"
    local src="${TMP}/src"
    if [ -f ./go.mod ] && grep -q emergency-tunnel ./go.mod 2>/dev/null; then
        src="$(pwd)"; info "using the current checkout"
    else
        info "cloning ${ET_REPO}"
        git clone --depth 1 "$ET_REPO" "$src" >/dev/null 2>&1 || die "git clone failed"
    fi
    # The tree being compiled is the authority on its own version — trust it over
    # anything guessed earlier, so the stamped core and the recorded VERSION can
    # never disagree. An explicit --version still wins.
    if [ -z "$ET_VERSION" ] && [ -r "${src}/VERSION" ]; then
        VERSION="$(tr -d '[:space:]' < "${src}/VERSION")"
    fi
    is_semver "${VERSION:-}" || VERSION="dev"
    ( cd "$src" && CGO_ENABLED=0 "$GO_BIN" build -trimpath \
        -ldflags "-s -w -X github.com/emergency-tunnel/et/internal/core.CoreVersion=${VERSION}" \
        -o "${TMP}/et-core-linux-${ARCH}" ./cmd/et-core ) || die "build failed"
    CORE_BIN="${TMP}/et-core-linux-${ARCH}"
    cp "$src/scripts/et-panel.sh" "$src/scripts/uninstall.sh" "${TMP}/"
    cp "$src/systemd/emergency-tunnel@.service" "${TMP}/"
    ok "built v${VERSION}"
}

# ---- install ---------------------------------------------------------------
install_files() {
    step "Install"
    local prev; prev="$(installed_version)"
    if [ -n "$prev" ] && [ "$prev" = "$VERSION" ] && [ "$ET_FORCE" != "1" ]; then
        info "v${VERSION} is already installed (--force to reinstall)"
    fi

    install -d -m 0755 "$PREFIX" "$LIB_DIR" "${LIB_DIR}/state"
    install -d -m 0750 "$CONF_DIR" "$LOG_DIR"

    # Install to a temporary name and rename, so a partially written binary can
    # never replace a working one.
    install -m 0755 "$CORE_BIN"           "${PREFIX}/.et-core.new"
    install -m 0755 "${TMP}/et-panel.sh"  "${PREFIX}/.et.new"
    mv -f "${PREFIX}/.et-core.new" "${PREFIX}/et-core"
    mv -f "${PREFIX}/.et.new"      "${PREFIX}/et"
    install -m 0755 "${TMP}/uninstall.sh" "${LIB_DIR}/uninstall.sh"
    install -m 0644 "${TMP}/emergency-tunnel@.service" "${UNIT_DIR}/emergency-tunnel@.service"
    echo "$VERSION" > "${LIB_DIR}/VERSION"

    # Keep updating from wherever this install came from. A source build that
    # only happened because the release was stale still belongs to its host.
    if [ "$SOURCE_USED" = "host" ] || [ "${RESOLVED_FROM:-}" = "host" ]; then
        echo "${ET_BASE_URL}/install.sh" > "${LIB_DIR}/UPDATE_URL"
    else echo "https://raw.githubusercontent.com/${ET_REPO_SLUG}/main/scripts/install.sh" > "${LIB_DIR}/UPDATE_URL"; fi

    # systemctl can be present but non-functional (containers, chroots, images
    # built offline). Never let that abort an otherwise good install.
    have systemctl && systemctl daemon-reload >/dev/null 2>&1 || true
    ok "et-core and et installed"
    PREV_VERSION="$prev"
}

# ---- post-install ----------------------------------------------------------
tune_host() {
    [ "$ET_NO_TUNE" = "1" ] && { info "host tuning skipped (--no-tune)"; return; }
    step "Host tuning"
    "${PREFIX}/et" --tune >/dev/null 2>&1 && ok "BBR, fq and socket buffers applied" \
        || warn "could not apply sysctls (container without privileges?)"
    local cc; cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')"
    info "congestion control: ${cc}"
}

migrate_and_restart() {
    [ -z "${PREV_VERSION:-}" ] && return 0
    step "Upgrade"
    info "${PREV_VERSION} -> ${VERSION}"
    "${PREFIX}/et" --migrate 2>/dev/null | sed 's/^/  /' || true
    :
    have systemctl || return 0
    local units; units="$(systemctl list-units 'emergency-tunnel@*.service' --no-legend 2>/dev/null | awk '{print $1}')" || units=""
    [ -z "$units" ] && return 0
    # shellcheck disable=SC2086
    systemctl restart $units && ok "restarted running tunnels onto the new core" \
        || warn "some tunnels did not restart — check 'et' → Manage → logs"
}

verify_install() {
    step "Verify"
    local v
    v="$("${PREFIX}/et-core" version 2>/dev/null | awk -F': *' '/Core Version/{print $2}' | tr -d 'v ')" \
        || die "et-core will not run"
    [ "$v" = "$VERSION" ] || warn "core reports v${v}, expected v${VERSION}"
    ok "core v${v}"
    # Verify the panel by version, not merely that it runs. A stale console next
    # to a fresh core is the failure that looks exactly like "the update did
    # nothing" — same menus, new binary — so it must never pass silently.
    local pv
    pv="$("${PREFIX}/et" --version 2>/dev/null | awk '{print $2}' | tr -d 'v ')"
    if [ -z "$pv" ]; then warn "panel did not report a version — it may be a pre-2.0 console"
    elif [ "$pv" != "$VERSION" ]; then warn "panel reports v${pv}, expected v${VERSION}"
    else ok "panel v${pv}"; fi

    # An older copy earlier in PATH keeps launching after a successful install,
    # which presents as an update that changed nothing at all.
    local onpath; onpath="$(command -v et 2>/dev/null || true)"
    if [ -n "$onpath" ] && [ "$onpath" != "${PREFIX}/et" ]; then
        warn "'et' on PATH is ${onpath}, not ${PREFIX}/et — remove the old copy"
    fi
    local n; n="$(find "$CONF_DIR" -maxdepth 1 -name '*.toml' 2>/dev/null | wc -l)"
    [ "$n" -gt 0 ] && ok "${n} existing configuration(s) preserved"
    printf "\n  ${GRY}%s${R}\n" "transports built into this core:"
    "${PREFIX}/et-core" transports 2>/dev/null | sed 's/^/    /'
}

banner() {
    printf "${CYN}${B}"
    cat <<'ART'
   ┌─┐┌┬┐   ┌─┐┌┬┐┌─┐┬─┐┌─┐┌─┐┌┐┌┌─┐┬ ┬  ┌┬┐┬ ┬┌┐┌┌┐┌┌─┐┬
   ├┤  │    ├┤ │││├┤ ├┬┘│ ┬├┤ ││││  └┬┘   │ │ │││││││├┤ │
   └─┘ ┴    └─┘┴ ┴└─┘┴└─└─┘└─┘┘└┘└─┘ ┴    ┴ └─┘┘└┘┘└┘└─┘┴─┘
ART
    printf "${R}${GRY}   installer${R}\n"
}

if [ "${DO_UNINSTALL:-0}" = "1" ]; then
    [ -f "${LIB_DIR}/uninstall.sh" ] && exec bash "${LIB_DIR}/uninstall.sh"
    die "uninstaller not found — reinstall first, or remove files manually"
fi

main() {
    banner
    detect
    install_deps
    if [ "$ET_FROM_SOURCE" = "1" ]; then
        VERSION="${ET_VERSION:-}"; SOURCE_USED="source"
    else
        resolve_version
    fi
    if [ "$SOURCE_USED" = "source" ]; then build_from_source; else download_release; fi
    install_files
    tune_host
    migrate_and_restart
    verify_install

    printf "\n${GRN}${B}  Emergency Tunnel v%s is installed.${R}\n\n" "$VERSION"
    printf "  Run ${B}${CYN}et${R} to open the console.\n"
    printf "  ${GRY}configs %s · logs %s${R}\n" "$CONF_DIR" "$LOG_DIR"
    printf "  ${GRY}update later: curl -fsSL %s | bash${R}\n\n" "$(cat "${LIB_DIR}/UPDATE_URL" 2>/dev/null)"
    if [ -t 0 ] && have et; then
        read -r -p "  Open the console now? [Y/n] " a || a=n
        case "${a:-Y}" in [Nn]*) : ;; *) exec et ;; esac
    fi
}
main
