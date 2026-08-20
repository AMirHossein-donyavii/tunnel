#!/usr/bin/env bash
#
# Emergency Tunnel uninstaller. Stops and removes all tunnels, the core, the
# panel and (optionally) configs and logs.
#
set -euo pipefail

PREFIX="/usr/local/bin"
CONF_DIR="/etc/emergency-tunnel"
LOG_DIR="/var/log/emergency-tunnel"
UNIT_DIR="/etc/systemd/system"
LIB_DIR="/usr/local/lib/emergency-tunnel"

C_RESET='\033[0m'; C_R='\033[0;31m'; C_G='\033[0;32m'; C_Y='\033[1;33m'
info() { echo -e "${C_Y}[*]${C_RESET} $*"; }
ok()   { echo -e "${C_G}[+]${C_RESET} $*"; }
die()  { echo -e "${C_R}[-] $*${C_RESET}" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Please run as root."

info "Stopping and disabling all Emergency Tunnel services..."
mapfile -t units < <(systemctl list-unit-files 'emergency-tunnel@*.service' --no-legend 2>/dev/null | awk '{print $1}')
# Also catch instantiated units that are running but whose files were removed.
mapfile -t running < <(systemctl list-units 'emergency-tunnel@*.service' --no-legend 2>/dev/null | awk '{print $1}')
for u in "${units[@]}" "${running[@]}"; do
    [ -n "$u" ] || continue
    systemctl stop "$u" 2>/dev/null || true
    systemctl disable "$u" 2>/dev/null || true
    ok "Removed service: $u"
done

info "Removing systemd template unit..."
rm -f "${UNIT_DIR}/emergency-tunnel@.service"
systemctl daemon-reload || true
systemctl reset-failed 2>/dev/null || true

info "Removing binaries and panel..."
rm -f "${PREFIX}/et-core" "${PREFIX}/et"
rm -rf "$LIB_DIR"

PURGE="${1:-}"
if [ "$PURGE" = "--purge" ]; then
    info "Purging configs and logs..."
    rm -rf "$CONF_DIR" "$LOG_DIR"
    ok "Configs and logs removed."
else
    if [ -t 0 ]; then
        read -r -p "Also delete configs (${CONF_DIR}) and logs (${LOG_DIR})? [y/N] " ans
        case "${ans:-N}" in
            [Yy]*) rm -rf "$CONF_DIR" "$LOG_DIR"; ok "Configs and logs removed." ;;
            *) info "Kept configs and logs. Remove manually or re-run with --purge." ;;
        esac
    else
        info "Kept ${CONF_DIR} and ${LOG_DIR}. Re-run with --purge to remove them."
    fi
fi

ok "Emergency Tunnel has been uninstalled."
