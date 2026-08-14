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
#   --local <path>   install a release directory or tarball already on this
#                    machine — no network at all
#   --force          reinstall even if already at the target version
#   --no-tune        skip host network tuning (BBR/fq/buffers)
#   --allow-downgrade  permit installing an older version than the one present
#   --uninstall      remove the tunnel (configs are kept unless you confirm)
#
# Environment overrides: ET_SOURCE, ET_REPO_SLUG, ET_BASE_URL, ET_CHANNEL,
# ET_VERSION, ET_PUBKEY, ET_FROM_SOURCE, ET_ALLOW_INSECURE, ET_FORCE, ET_NO_TUNE,
# ET_LOCAL, ET_GOPROXY, ET_GO_MIN
#
# Where the build comes from (auto): the release host first, then GitHub
# Releases. Whichever answers, its version is compared against the VERSION file
# on the default branch — if the branch is newer, the installer builds that from
# source. An unreleased fix therefore still reaches you through `et` → Update;
# it never silently reinstalls the last published binary.
#
# On a filtered path all of those can fail at once — the host times out, the
# GitHub API does not answer, and a source build needs a Go toolchain from a
# third host. --local takes the release straight off disk in that case; it is
# checksum-verified exactly as a download would be.
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
ET_ALLOW_DOWNGRADE="${ET_ALLOW_DOWNGRADE:-0}"
ET_REPO="${ET_REPO:-https://github.com/${ET_REPO_SLUG}.git}"
# A release directory or tarball already on this machine. On a path where every
# URL in this script is filtered, the files can still arrive by another route,
# and the installer should be able to use them.
ET_LOCAL="${ET_LOCAL:-}"
# The version of this script. raw.githubusercontent.com serves it with a
# five-minute cache, so a machine that re-runs the published one-liner shortly
# after a fix can be handed the previous copy and hit a bug that is already
# fixed — with no way to tell from the output that this is what happened.
# Compared against the sources at startup; see check_installer_age.
INSTALLER_VERSION="2.12.0"
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
        --local)       ET_LOCAL="$2"; shift 2 ;;
        --force)       ET_FORCE=1; shift ;;
        --no-tune)     ET_NO_TUNE=1; shift ;;
        --allow-downgrade) ET_ALLOW_DOWNGRADE=1; shift ;;
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

# Resolving a version fetches a few bytes and is allowed to fail: the whole
# point of trying several sources is that one of them may be unreachable. Doing
# that with the download options meant four attempts at fifteen seconds each
# before the fallback was even considered — a minute of a frozen "Release" step
# on a path where the host is blocked, which reads as a hung installer. Probes
# get one quick attempt; only the actual download is patient.
PROBE_OPTS=(--fail --silent --location --connect-timeout 5 --max-time 10)
[ "$ET_ALLOW_INSECURE" = "1" ] || PROBE_OPTS+=(--proto '=https' --tlsv1.2)
probe_str() { curl "${PROBE_OPTS[@]}" "$1"; }
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
    # The query string defeats the CDN cache. Without it this can report the same
    # stale value as the cached copy of the script asking the question, and the
    # two agree with each other about a version that is no longer current.
    probe_str "https://raw.githubusercontent.com/${ET_REPO_SLUG}/main/VERSION?cb=$(date +%s)" \
        2>/dev/null | tr -d '[:space:]'
}

# check_installer_age warns when this script is an old cached copy. A stale
# installer reproduces bugs that are already fixed, and nothing in its output
# says so — the version it prints is the one it knows about.
check_installer_age() {
    local bv; bv="$(branch_version)" || return 0
    [ -n "$bv" ] && is_semver "$bv" && is_semver "$INSTALLER_VERSION" || return 0
    ver_gt "$bv" "$INSTALLER_VERSION" || return 0
    warn "this installer is v${INSTALLER_VERSION}; v${bv} is available."
    info "You are running a cached copy — raw.githubusercontent.com caches for 5 minutes."
    info "To force the current one:"
    info "    bash <(curl -fsSL 'https://raw.githubusercontent.com/${ET_REPO_SLUG}/main/scripts/install.sh?cb='\$(date +%s))"
}

# resolve_from <host|github> — sets VERSION and REL_URL, or fails.
resolve_from() {
    case "$1" in
      host)
        if [ -n "$ET_VERSION" ]; then VERSION="$ET_VERSION"
        else VERSION="$(probe_str "${ET_BASE_URL}/${ET_CHANNEL}" 2>/dev/null | tr -d '[:space:]')" || return 1; fi
        REL_URL="${ET_BASE_URL}/releases/v${VERSION}" ;;
      github)
        if [ -n "$ET_VERSION" ]; then VERSION="$ET_VERSION"
        else VERSION="$(probe_str "https://api.github.com/repos/${ET_REPO_SLUG}/releases/latest" 2>/dev/null \
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
            # Say which source is being tried before trying it. A blocked host
            # shows up here as a pause, and a pause under a bare "Release"
            # heading is indistinguishable from a hung installer.
            info "checking ${ET_BASE_URL}"
            if resolve_from host; then :
            else
                warn "release host unreachable — trying GitHub Releases"
                if resolve_from github; then :
                else
                    warn "no GitHub release reachable either"
                    VERSION=""; SOURCE_USED="source"
                fi
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

# install_from_local takes a release that is already on this machine: either the
# release directory itself, or the tarball it was packaged in.
#
# Every other path here depends on reaching a URL, and on a filtered path all of
# them can fail at once — the host times out, the GitHub API does not answer, and
# a source build needs a Go toolchain from a third host. The files themselves
# travel fine by any other route, so accept them directly. They are checksummed
# against the release's own SHA256SUMS exactly as a download would be.
install_from_local() {
    step "Local release"
    TMP="$(mktemp -d)"
    local dir="$ET_LOCAL" sums
    if [ ! -e "$dir" ]; then
        warn "there is no ${ET_LOCAL} on this machine."
        info "Copy the release tarball here first, from the computer that has it:"
        info "    scp et-<version>.tar.gz root@<this server>:/root/"
        info "then re-run with --local pointing at where you put it."
        die "no such file: ${ET_LOCAL}"
    fi
    if [ -f "$dir" ]; then
        mkdir -p "${TMP}/unpack"
        tar -xzf "$dir" -C "${TMP}/unpack" 2>/dev/null || die "cannot unpack ${ET_LOCAL}"
        # A packaged tarball may hold several releases; take the newest.
        sums="$(find "${TMP}/unpack" -type f -name SHA256SUMS | sort -V | tail -n1)"
        [ -n "$sums" ] || die "${ET_LOCAL} contains no release (no SHA256SUMS inside)"
        dir="$(dirname "$sums")"
    fi
    [ -d "$dir" ] || die "${ET_LOCAL} is neither a release directory nor a tarball"
    [ -f "${dir}/SHA256SUMS" ] || die "${dir} is not a release directory (no SHA256SUMS)"

    local asset="et-core-linux-${ARCH}"
    cp "${dir}/SHA256SUMS" "${TMP}/SHA256SUMS"
    for f in "$asset" et-panel.sh emergency-tunnel@.service uninstall.sh; do
        [ -f "${dir}/${f}" ] || die "${dir} has no ${f} — is this a release for ${ARCH}?"
        cp "${dir}/${f}" "${TMP}/${f}"
        verify_against_sums "$f"
    done

    # The release states its own version; never guess one that the binary then
    # contradicts.
    if [ -n "$ET_VERSION" ]; then VERSION="$ET_VERSION"
    else
        VERSION="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
                   "${dir}/manifest.json" 2>/dev/null | head -n1)"
        [ -n "$VERSION" ] || VERSION="$(basename "$dir")"
        VERSION="${VERSION#v}"
    fi
    is_semver "$VERSION" || die "cannot tell which version the release in ${dir} is"
    SOURCE_USED="local"
    CORE_BIN="${TMP}/${asset}"
    ok "v${VERSION} from ${ET_LOCAL} — 4 files verified against its SHA256SUMS"
}

# ---- source build ----------------------------------------------------------
# ET_GO_MIN is the oldest toolchain that can build this tree; keep it in step
# with the `go` line in go.mod. A Go older than this fails deep in the build with
# a message about language features, which reads as a broken source tree.
ET_GO_MIN="${ET_GO_MIN:-1.22}"

# go_ok <binary> — true when that Go is new enough to build this tree.
go_ok() {
    local v
    v="$("$1" env GOVERSION 2>/dev/null | sed 's/^go//')" || return 1
    [ -n "$v" ] || return 1
    [ "$(printf '%s\n%s\n' "$ET_GO_MIN" "$v" | sort -V | head -n1)" = "$ET_GO_MIN" ]
}

ensure_go() {
    if have go && go_ok "$(command -v go)"; then GO_BIN="$(command -v go)"; return; fi
    step "Go toolchain"

    # The distribution's Go first. It comes over the package mirror, which this
    # installer has already used successfully by the time it gets here, and it is
    # signed. Downloading a toolchain from go.dev means a second host on a path
    # where the first one was already unreachable — and on a filtered path the
    # redirect to Google's download host is answered by the filter, which is why
    # this step could fail with a bare 404 rather than a timeout.
    if ! have go || ! go_ok "$(command -v go)"; then
        info "installing the distribution's Go"
        pkg_install golang-go || pkg_install go || true
        hash -r 2>/dev/null || true
    fi
    if have go && go_ok "$(command -v go)"; then
        GO_BIN="$(command -v go)"; ok "$("$GO_BIN" version)"; return
    fi

    local tb="go${ET_GO_VERSION}.linux-${ARCH}.tar.gz"
    [ "$ARCH" = "armv7" ] && tb="go${ET_GO_VERSION}.linux-armv6l.tar.gz"
    info "fetching go${ET_GO_VERSION} from go.dev"
    if dl "https://go.dev/dl/${tb}" "${TMP}/${tb}"; then
        rm -rf /usr/local/go && tar -C /usr/local -xzf "${TMP}/${tb}"
        GO_BIN="/usr/local/go/bin/go"; export PATH="/usr/local/go/bin:${PATH}"
        ok "$("$GO_BIN" version)"
        return
    fi

    # Out of options. Say what to do rather than what failed: there is a path
    # left that needs no network at all, and the user cannot be expected to know
    # it from "cannot download Go".
    printf '\n'
    warn "no Go toolchain available: the package mirror has none new enough (need ${ET_GO_MIN}+)"
    warn "and go.dev could not be reached."
    info "This machine cannot reach any of the release host, the GitHub API, or go.dev."
    info "Install the release directly instead — copy the tarball to this machine and run:"
    info "    bash install.sh --local /path/to/et-<version>.tar.gz"
    die "no way to obtain a build"
}

# fetch_source <dir> — put the sources in <dir>.
#
# A clone was the only route, and `git clone` against a filtered host has no
# timeout of its own: the installer stopped dead under "cloning …" and never
# came back, which is worse than any error. A source archive is an ordinary
# HTTPS GET with the same bounded options as every other download here, it is a
# tenth of the size of a clone, and codeload is a different host from github.com
# — so it can answer where the clone hangs. The clone stays as the last try,
# with a hard limit on how long it may take.
fetch_source() {
    local dest="$1" tb="${TMP}/src.tar.gz" u host
    for u in "https://codeload.github.com/${ET_REPO_SLUG}/tar.gz/refs/heads/main" \
             "https://github.com/${ET_REPO_SLUG}/archive/refs/heads/main.tar.gz"; do
        host="${u#https://}"; host="${host%%/*}"
        info "fetching sources from ${host}"
        if dl "$u" "$tb"; then
            mkdir -p "$dest"
            # The archive wraps everything in one directory named for the branch.
            if tar -xzf "$tb" -C "$dest" --strip-components=1 2>/dev/null && [ -f "${dest}/go.mod" ]; then
                return 0
            fi
            rm -rf "$dest"
        fi
    done
    if have git || pkg_install git; then
        info "fetching sources with git"
        if have timeout; then
            timeout 180 git clone --depth 1 "$ET_REPO" "$dest" >/dev/null 2>&1 && return 0
        else
            git clone --depth 1 "$ET_REPO" "$dest" >/dev/null 2>&1 && return 0
        fi
        rm -rf "$dest"
    fi
    return 1
}

build_from_source() {
    step "Build from source"
    TMP="$(mktemp -d)"; ensure_go
    local src="${TMP}/src"
    if [ -f ./go.mod ] && grep -q emergency-tunnel ./go.mod 2>/dev/null; then
        src="$(pwd)"; info "using the current checkout"
    elif ! fetch_source "$src"; then
        warn "the sources cannot be fetched from this machine."
        info "Copy a release tarball here and install it directly instead:"
        info "    bash install.sh --local /path/to/et-<version>.tar.gz"
        die "no way to obtain the sources"
    fi
    # The tree being compiled is the authority on its own version — trust it over
    # anything guessed earlier, so the stamped core and the recorded VERSION can
    # never disagree. An explicit --version still wins.
    if [ -z "$ET_VERSION" ] && [ -r "${src}/VERSION" ]; then
        VERSION="$(tr -d '[:space:]' < "${src}/VERSION")"
    fi
    is_semver "${VERSION:-}" || VERSION="dev"
    # Module downloads go through Google's proxy by default, which is one more
    # host that can be unreachable on exactly the paths this fallback exists to
    # serve. Try mirrors after it. This is safe whichever answers: every module
    # is checked against the hashes in go.sum, so a proxy can serve the build or
    # fail, but it cannot change what gets compiled.
    #
    # The separator is load-bearing and is NOT a comma. A comma-separated list
    # falls through only on 404 and 410; every other status is fatal, so the
    # mirrors are never reached. Google's proxy answers a blocked region with
    # 403, which is precisely the case this list exists for — with commas the
    # build dies there having never tried a single mirror. Pipes fall through on
    # any error.
    export GOPROXY="${ET_GOPROXY:-https://proxy.golang.org|https://goproxy.io|https://goproxy.cn|direct}"
    # `direct` fetches with git over HTTPS, which against a filtered host has no
    # timeout of its own — the same hang that used to stop the clone. Bound it.
    export GIT_HTTP_LOW_SPEED_LIMIT="${GIT_HTTP_LOW_SPEED_LIMIT:-1000}"
    export GIT_HTTP_LOW_SPEED_TIME="${GIT_HTTP_LOW_SPEED_TIME:-30}"
    export GIT_TERMINAL_PROMPT=0
    ( cd "$src" && CGO_ENABLED=0 "$GO_BIN" build -trimpath \
        -ldflags "-s -w -X github.com/emergency-tunnel/et/internal/core.CoreVersion=${VERSION}" \
        -o "${TMP}/et-core-linux-${ARCH}" ./cmd/et-core ) || {
        warn "the build could not fetch its dependencies or failed to compile."
        info "If the errors above are 403s from a module proxy, this machine's"
        info "region is blocked by it; set another and retry, e.g."
        info "    ET_GOPROXY='https://goproxy.io|direct' bash install.sh"
        info "Copy a release tarball here and install it directly instead:"
        info "    bash install.sh --local /path/to/et-<version>.tar.gz"
        die "build failed"
    }
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

    # Going backwards is never routine. The release host can regress — a stale
    # checkout republishes an old version over a newer one — and an update run
    # would then walk every server back without a word. It also breaks the
    # tunnel outright across the v2/v3 wire boundary (2.0.0+ speaks v3), because
    # the two ends stop understanding each other's handshake.
    if [ -n "$prev" ] && is_semver "$prev" && is_semver "$VERSION" \
       && ver_gt "$prev" "$VERSION" && [ "$ET_ALLOW_DOWNGRADE" != "1" ]; then
        warn "installed v${prev} is newer than v${VERSION} offered by ${SOURCE_USED}"
        [ "$SOURCE_USED" = "host" ] && info "the release host is serving an older build than this server runs"
        die "refusing to downgrade — pass --allow-downgrade to override (and upgrade BOTH ends together)"
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
    check_installer_age
    if [ -n "$ET_LOCAL" ]; then
        install_from_local
    elif [ "$ET_FROM_SOURCE" = "1" ]; then
        VERSION="${ET_VERSION:-}"; SOURCE_USED="source"; build_from_source
    else
        resolve_version
        if [ "$SOURCE_USED" = "source" ]; then build_from_source; else download_release; fi
    fi
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
