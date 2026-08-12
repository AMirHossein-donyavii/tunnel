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

[ "$fail" = "0" ] && say "panel checks passed" || say "panel checks FAILED"
exit "$fail"
