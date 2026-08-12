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
    sed -i -e "s|^CONF_DIR=.*|CONF_DIR=\"$tmp/etc\"|" "$harness"
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
    # The Iran half of the WireGuard VPN: it writes a tunnel config like any
    # other builder, so it is held to the same standard.
    drive wg_vpn_entry     51820 t-wgvpn 11238

    # 6. A prompt whose input runs out must stop, not spin. A loop that re-asks
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
