#!/usr/bin/env bash
#
# Static checks on the console.
#
# A menu entry that calls a function which no longer exists is invisible to
# `bash -n` — the syntax is perfect, and bash only discovers the problem when a
# user picks that option, at which point the screen simply returns to the menu
# with nothing having happened. That is exactly how every Backpack option except
# one came to be broken in a release: an edit replaced a span of the file that
# happened to contain four other builders, and nothing failed until someone
# chose one.
#
# So: every function a menu dispatches to must exist, and every builder must be
# reachable from a menu. Run from CI and before packaging a release.
#
set -uo pipefail

PANEL="${1:-$(dirname "$0")/et-panel.sh}"
fail=0

say()  { printf '%s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fail=1; }
good() { printf '  ok    %s\n' "$*"; }

[ -f "$PANEL" ] || { say "no such file: $PANEL"; exit 2; }

say "checking $PANEL"

# 1. Syntax.
if bash -n "$PANEL" 2>/dev/null; then good "syntax"; else bad "syntax errors"; fi

# Every function the file defines.
defined="$(grep -oE '^[a-z_][a-z0-9_]*\(\)' "$PANEL" | tr -d '()' | sort -u)"

# 2. Every case-arm target of the form `N) name ;;` must be defined.
#    This is the check that would have caught the deleted builders.
missing=0
while read -r fn; do
    [ -n "$fn" ] || continue
    grep -qx "$fn" <<<"$defined" || { bad "menu calls '$fn', which is not defined anywhere"; missing=1; }
done < <(grep -oE '^[[:space:]]*[0-9]+\)[[:space:]]+[a-z_][a-z0-9_]*[[:space:]]*;;' "$PANEL" \
         | sed -E 's/^[[:space:]]*[0-9]+\)[[:space:]]+//; s/[[:space:]]*;;$//' | sort -u)
[ "$missing" = "0" ] && good "every menu action resolves to a defined function"

# 3. Every section/builder must be reachable, so a rename cannot orphan one.
orphan=0
while read -r fn; do
    [ -n "$fn" ] || continue
    # Count references outside the definition line itself.
    n="$(grep -cE "(^|[^a-z0-9_])${fn}([^a-z0-9_]|$)" "$PANEL")"
    [ "$n" -le 1 ] && { bad "'$fn' is defined but never called — an orphaned menu builder"; orphan=1; }
done < <(grep -oE '^(section|backpack)_[a-z0-9_]*\(\)' "$PANEL" | tr -d '()' | sort -u)
[ "$orphan" = "0" ] && good "every section and builder is reachable"

# 4. Config keys the console writes must be ones the core understands. A key the
#    core does not know is silently ignored, which is how a whole latency mode
#    once shipped doing nothing.
core_keys="$(grep -oE '^[[:space:]]*case "[a-z0-9_]+":' "$(dirname "$PANEL")/../internal/config/toml.go" 2>/dev/null \
             | grep -oE '"[a-z0-9_]+"' | tr -d '"' | sort -u)"
if [ -n "$core_keys" ]; then
    unknown=0
    while read -r k; do
        [ -n "$k" ] || continue
        grep -qx "$k" <<<"$core_keys" || { bad "console writes '$k', which the core does not parse"; unknown=1; }
    done < <(grep -oE 'cfg_set [a-z0-9_]+' "$PANEL" | awk '{print $2}' | grep -v '^_' | sort -u)
    [ "$unknown" = "0" ] && good "every config key the console writes is understood by the core"
fi

# 5. Drive each config-writing builder to completion and require that it produces a
#    config the core accepts.
#
#    Checks 2 and 3 prove a builder EXISTS and is reachable. They cannot prove it
#    RUNS: a prompt loop that spins against a closed stdin, or a builder that
#    exits before writing anything, passes both and still leaves the user
#    staring at a menu that does nothing. This actually answers the prompts.
CORE_BIN="${ET_CORE_BIN:-$(dirname "$PANEL")/../et-core-test}"
if [ -x "$CORE_BIN" ] && command -v timeout >/dev/null; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    harness="$tmp/panel.sh"
    awk '/^# ---- non-interactive entry points/{exit} {print}' "$PANEL" > "$harness"
    # The console validates with the core it finds installed; under test that
    # must be the core built from THIS tree, or a builder writing a key the
    # installed core predates is reported as the console's fault.
    sed -i -e "s|^CONF_DIR=.*|CONF_DIR=\"$tmp/etc\"|" \
           -e "s|^WG_DIR=.*|WG_DIR=\"$tmp/wg\"|" \
           -e "s|^CORE=.*|CORE=\"$(cd "$(dirname "$CORE_BIN")" \&\& pwd)/$(basename "$CORE_BIN")\"|" "$harness"
    cat >> "$harness" <<'STUB'
systemctl() { return 0; }
port_in_use() { return 1; }
svc_state() { echo active; }
need_root() { return 0; }
enable_ip_forwarding() { return 0; }
STUB
    drive() { # drive <builder> <answers...>
        local fn="$1"; shift
        rm -rf "$tmp/etc"; mkdir -p "$tmp/etc"
        printf '%s\n' "$@" | timeout 25 bash -c "source $harness; $fn" >"$tmp/out" 2>&1
        local f; f="$(ls "$tmp"/etc/*.toml 2>/dev/null | head -1)"
        if [ -n "$f" ] && "$CORE_BIN" validate --config "$f" >/dev/null 2>&1; then
            good "$fn runs and writes a config the core accepts"
        else
            bad "$fn did not produce a valid config — the option does nothing for a user"
        fi
    }
    drive backpack_stealth t-stealth y 1 11234 15001 n
    drive backpack_wss     t-wss "" n 1 11235 15002 n
    drive backpack_quic    t-quic "" n 1 11236 15003 n
    drive backpack_fec     t-fec  n 1 11237 15004 n
    # Both halves of the WireGuard VPN write a tunnel config like any other
    # builder, so they are held to the same standard. The Foreign half in
    # particular shipped once creating WireGuard and no tunnel at all, so the
    # pair could never connect: it passed every check above because the builder
    # existed, was reachable, and ran — it just left out half its job.
    # users' port, the Foreign server's WireGuard port, name, tunnel port
    drive wg_vpn_entry     51820 51999 t-wgvpn 11238
    # The TUN section builds the raw-IP carriers; each method is a different
    # data plane, so each is driven. method, name, role, tunnel port, peer,
    # tun subnet defaults, forwards, proxy-protocol answer.
    drive_tun() { # drive_tun <method-number> <name>
        local n="$1" nm="$2"
        rm -rf "$tmp/etc"; mkdir -p "$tmp/etc"
        printf '%s\n' "$n" "$nm" 2 11250 203.0.113.9 "" "" "" \
            | timeout 25 bash -c "source $harness; section_tun" >"$tmp/out.tun$n" 2>&1
        local f; f="$(ls "$tmp"/etc/*.toml 2>/dev/null | head -1)"
        if [ -n "$f" ] && "$CORE_BIN" validate --config "$f" >/dev/null 2>&1; then
            good "TUN method $n ($nm) writes a config the core accepts"
        else
            bad "TUN method $n ($nm) did not produce a valid config"
        fi
    }
    drive_tun 5 t-ipip
    drive_tun 6 t-gre

    # Every Basic protocol is a different data plane; each is driven so a broken
    # one cannot ship looking like a menu entry that does nothing.
    drive_basic() { # drive_basic <choice> <name> <answers...>
        local n="$1" nm="$2"; shift 2
        rm -rf "$tmp/etc"; mkdir -p "$tmp/etc"
        printf '%s\n' "$n" "$nm" "$@" | timeout 25 bash -c "source $harness; section_basic" >"$tmp/out.b$n" 2>&1
        local f; f="$(ls "$tmp"/etc/*.toml 2>/dev/null | head -1)"
        if [ -n "$f" ] && "$CORE_BIN" validate --config "$f" >/dev/null 2>&1; then
            good "Basic $n ($nm) writes a config the core accepts"
        else
            bad "Basic $n ($nm) did not produce a valid config"
        fi
    }
    #            role tunnel-port  [ws path] [host] [sni]  ports  proxy-proto
    drive_basic 1 b-tcp      1 11260 8443 n
    drive_basic 2 b-tcpmux   1 11261 8444 n
    drive_basic 3 b-xtcpmux  y 1 11262 8445 n
    drive_basic 4 b-ws       1 11263 "" 8446 n
    drive_basic 5 b-wss      1 11264 "" 8447 n
    drive_basic 6 b-wsmux    1 11265 "" 8448 n
    drive_basic 7 b-wssmux   1 11266 "" 8449 n
    drive_basic 8 b-xwsmux   y 1 11267 "" 8450 n

    # listen port here, Iran IP, users' port there, tunnel port, client count, name
    if command -v wg >/dev/null; then
        drive wg_vpn_exit  51999 203.0.113.9 51820 11239 1 t-wgvpn
    fi

    # 6. The two halves of a paired builder must actually pair up. Each half can
    #    write a config the core accepts and still never connect to the other:
    #    that is precisely what shipped when the Foreign half wrote no tunnel at
    #    all. Opposite roles on a matching tunnel port is the property that makes
    #    a pair a pair, so assert it rather than the halves separately.
    if command -v wg >/dev/null; then
        pairport=11240
        rm -rf "$tmp/etc" "$tmp/wg"; mkdir -p "$tmp/etc"
        printf '%s\n' 51820 51999 pair-iran "$pairport" \
            | timeout 25 bash -c "source $harness; wg_vpn_entry" >/dev/null 2>&1
        printf '%s\n' 51999 203.0.113.9 51820 "$pairport" 1 pair-kharej \
            | timeout 25 bash -c "source $harness; wg_vpn_exit" >/dev/null 2>&1
        a="$tmp/etc/pair-iran.toml"; b="$tmp/etc/pair-kharej.toml"
        if [ ! -f "$a" ] || [ ! -f "$b" ]; then
            bad "the WireGuard VPN builders produced $( ls "$tmp"/etc/*.toml 2>/dev/null | wc -l ) of the 2 configs a working pair needs"
        elif ! grep -q 'role = "iran"' "$a" || ! grep -q 'role = "kharej"' "$b"; then
            bad "the WireGuard VPN halves do not take opposite roles"
        elif [ "$(grep -c "^tunnel_port = ${pairport}$" "$a" "$b" | grep -c ':1$')" != "2" ]; then
            bad "the WireGuard VPN halves disagree about the tunnel port, so they cannot connect"
        else
            good "the WireGuard VPN halves form a connectable pair"
        fi
    fi

    # 7. A prompt whose input runs out must stop, not spin. A loop that re-asks
    #    forever against a closed stdin burns a core and never returns.
    # The value must be one the prompt REJECTS, so the retry loop is entered and
    # then meets a closed stdin — typing something invalid and pressing Ctrl-D.
    # A valid answer exits cleanly through the signal path and proves nothing.
    rm -rf "$tmp/etc"; mkdir -p "$tmp/etc"
    start=$(date +%s)
    printf '!!invalid\n' | timeout 10 bash -c "source $harness; backpack_stealth" >/dev/null 2>&1
    if [ $(( $(date +%s) - start )) -ge 9 ]; then
        bad "a prompt spun until it was killed when input ran out"
    else
        good "prompts stop when stdin closes instead of spinning"
    fi
fi

[ "$fail" = "0" ] && say "panel checks passed" || say "panel checks FAILED"
exit "$fail"
