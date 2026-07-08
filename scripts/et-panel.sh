#!/usr/bin/env bash
#
# Emergency Tunnel — interactive management panel.
# Installed as: /usr/local/bin/et
#
set -uo pipefail

SCRIPT_VERSION="1.0.0"
CORE="/usr/local/bin/et-core"
CONF_DIR="/etc/emergency-tunnel"
LOG_DIR="/var/log/emergency-tunnel"
SVC_PREFIX="emergency-tunnel@"

C_RESET='\033[0m'; C_R='\033[0;31m'; C_G='\033[0;32m'; C_Y='\033[1;33m'
C_B='\033[0;34m'; C_C='\033[0;36m'; C_M='\033[0;35m'; C_BOLD='\033[1m'
LINE="═══════════════════════════════════════════════════"

need_root() { [ "$(id -u)" -eq 0 ] || { echo -e "${C_R}Run as root.${C_RESET}"; exit 1; }; }
pause() { echo; read -r -p "Press Enter to continue..." _; }
have()  { command -v "$1" >/dev/null 2>&1; }

core_version() { [ -x "$CORE" ] && "$CORE" version 2>/dev/null | awk -F': *' '{print $2}' || echo "not installed"; }
core_status()  { [ -x "$CORE" ] && echo -e "${C_G}installed${C_RESET}" || echo -e "${C_R}missing${C_RESET}"; }

list_tunnels() {
    [ -d "$CONF_DIR" ] || return 0
    find "$CONF_DIR" -maxdepth 1 -name '*.toml' -printf '%f\n' 2>/dev/null | sed 's/\.toml$//' | sort
}

count_active() {
    local n=0 t
    while IFS= read -r t; do
        [ -n "$t" ] || continue
        systemctl is-active --quiet "${SVC_PREFIX}${t}" && n=$((n+1))
    done < <(list_tunnels)
    echo "$n"
}

# --- Server identity (IP / geo / ASN), cached for the session ----------------
SERVER_IP=""; SERVER_LOC=""; SERVER_DC=""
fetch_identity() {
    [ -n "$SERVER_IP" ] && return
    SERVER_IP="fetching..."; SERVER_LOC="..."; SERVER_DC="..."
    local json=""
    if have curl; then
        json="$(curl -fsS --max-time 4 'http://ip-api.com/json/?fields=query,country,city,as,isp' 2>/dev/null)"
    fi
    if [ -n "$json" ] && have grep; then
        SERVER_IP="$(echo "$json"  | grep -o '"query":"[^"]*"'   | cut -d'"' -f4)"
        local country city as isp
        country="$(echo "$json" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)"
        city="$(echo "$json"    | grep -o '"city":"[^"]*"'    | cut -d'"' -f4)"
        as="$(echo "$json"      | grep -o '"as":"[^"]*"'      | cut -d'"' -f4)"
        isp="$(echo "$json"     | grep -o '"isp":"[^"]*"'     | cut -d'"' -f4)"
        SERVER_LOC="${city:+$city, }${country:-unknown}"
        SERVER_DC="${as:-${isp:-unknown}}"
    fi
    [ -z "$SERVER_IP" ] && SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [ -z "$SERVER_IP" ] && SERVER_IP="unknown"
    [ -z "$SERVER_LOC" ] && SERVER_LOC="unknown (offline)"
    [ -z "$SERVER_DC" ]  && SERVER_DC="unknown"
}

banner() {
    clear
    echo -e "${C_C}${C_BOLD}"
    cat <<'ART'
 ___                                             _____                       _
| __|_ __  ___ _ _ __ _ ___ _ _  __ _  _    _ _ |_   _|  _ _ _ _ _  ___ | |
| _|| '  \/ -_) '_/ _` / -_) ' \/ _| || |  | ' \  | || || | ' \ ' \/ -_)| |
|___|_|_|_\___|_| \__, \___|_||_\__|\_, |  |_||_| |_| \_,_|_||_|_||_\___||_|
                  |___/             |__/
ART
    echo -e "${C_RESET}"
    echo -e "                 ${C_BOLD}Emergency Tunnel${C_RESET}"
    echo -e "     Script Version: ${C_G}v${SCRIPT_VERSION}${C_RESET}    Core Version: ${C_G}v$(core_version)${C_RESET}"
    echo -e "${C_B}${LINE}${C_RESET}"
    fetch_identity
    printf "  ${C_BOLD}%-16s${C_RESET} %s\n" "IP Address:"    "${SERVER_IP}"
    printf "  ${C_BOLD}%-16s${C_RESET} %s\n" "Location:"      "${SERVER_LOC}"
    printf "  ${C_BOLD}%-16s${C_RESET} %s\n" "Datacenter:"    "${SERVER_DC}"
    printf "  ${C_BOLD}%-16s${C_RESET} %b\n" "Core Status:"   "$(core_status)"
    printf "  ${C_BOLD}%-16s${C_RESET} %s\n" "Active Tunnels:" "$(count_active) / $(list_tunnels | grep -c . || echo 0)"
    echo -e "${C_B}${LINE}${C_RESET}"
}

# --- Small input helpers -----------------------------------------------------
ask() { # ask "Prompt" "default" -> echoes value
    local prompt="$1" def="${2:-}" ans
    if [ -n "$def" ]; then read -r -p "$(echo -e "  ${prompt} [${C_C}${def}${C_RESET}]: ")" ans
    else read -r -p "$(echo -e "  ${prompt}: ")" ans; fi
    echo "${ans:-$def}"
}
yesno() { local p="$1" d="${2:-n}" a; a="$(ask "$p (y/n)" "$d")"; case "$a" in [Yy]*) return 0;; *) return 1;; esac; }

# --- Create tunnel wizard ----------------------------------------------------
create_tunnel() {
    banner
    echo -e "  ${C_BOLD}Create New Tunnel${C_RESET}\n"

    echo -e "  Which server is THIS host?"
    echo -e "    ${C_G}1)${C_RESET} Iran   — origin server, users connect here"
    echo -e "    ${C_G}2)${C_RESET} Kharej — foreign exit server (runs Xray/services)"
    local rsel; rsel="$(ask "Select" "1")"
    local role; [ "$rsel" = "2" ] && role="kharej" || role="iran"

    echo; echo -e "  Tunnel method (protocol):"
    echo -e "    ${C_G}1)${C_RESET} TCP Reverse Tunnel   — multiplexed, lowest latency ${C_Y}[recommended, default]${C_RESET}"
    echo -e "    ${C_G}2)${C_RESET} TCP Simple forwarder — one link per connection (l4)"
    echo -e "    ${C_G}3)${C_RESET} TUN IP tunnel        — route all IP traffic (l3)"
    local esel; esel="$(ask "Select" "1")"
    local engine transport="tcp"
    case "$esel" in 2) engine="l4";; 3) engine="l3";; *) engine="mux";; esac

    echo; echo -e "  Direction:"
    echo -e "    ${C_G}1)${C_RESET} Reverse (recommended) — Kharej connects to Iran"
    echo -e "    ${C_G}2)${C_RESET} Direct                — Iran connects to Kharej"
    local dsel; dsel="$(ask "Select" "1")"
    local mode; [ "$dsel" = "2" ] && mode="direct" || mode="reverse"

    local defname="iran$RANDOM"; defname="${defname:0:8}"
    local name; name="$(ask "Tunnel name" "$defname")"
    name="$(echo "$name" | tr -cd '[:alnum:]_-')"
    [ -z "$name" ] && { echo -e "  ${C_R}Invalid name.${C_RESET}"; pause; return; }
    if [ -f "${CONF_DIR}/${name}.toml" ]; then
        echo -e "  ${C_R}A tunnel named '$name' already exists.${C_RESET}"; pause; return
    fi

    # Dialer side needs the peer address.
    local is_dialer="no" peer=""
    { [ "$mode" = "reverse" ] && [ "$role" = "kharej" ]; } && is_dialer="yes"
    { [ "$mode" = "direct" ]  && [ "$role" = "iran" ]; }   && is_dialer="yes"
    if [ "$is_dialer" = "yes" ]; then
        peer="$(ask "Peer address (the OTHER server's public IP)" "")"
        [ -z "$peer" ] && { echo -e "  ${C_R}Peer is required on this side.${C_RESET}"; pause; return; }
    fi

    local iface="emergency-tun" mtu profile workers pool cipher listen_port health tun_ip=""
    listen_port="$(ask "Tunnel port (server <-> server link)" "1234")"
    mtu="$(ask "MTU" "1380")"
    echo -e "  Performance profile: ${C_C}fast${C_RESET} (max throughput) | ${C_C}balance${C_RESET} | ${C_C}resource${C_RESET} (low RAM)"
    profile="$(ask "Profile" "balance")"
    workers="$(ask "CPU workers (0 = auto-detect)" "0")"
    pool="$(ask "Tunnel links / sessions" "4")"
    health="$(ask "Health/stats port (local only)" "9090")"
    # Only the L3 (TUN) engine uses an interface + tunnel subnet; forwarders do not.
    if [ "$engine" = "l3" ]; then
        iface="$(ask "Tunnel interface" "emergency-tun")"
        if [ "$role" = "iran" ]; then tun_ip="$(ask "Tunnel IP (this host)" "10.10.10.1/24")"
        else tun_ip="$(ask "Tunnel IP (this host)" "10.10.10.2/24")"; fi
    fi

    echo -e "  Encryption: ${C_G}1)${C_RESET} chacha20-poly1305   ${C_G}2)${C_RESET} aes-256-gcm"
    local csel; csel="$(ask "Select" "1")"
    [ "$csel" = "2" ] && cipher="aes-256-gcm" || cipher="chacha20-poly1305"

    # Pre-shared key: must match on both sides.
    local psk
    echo; echo -e "  Pre-shared key (must be identical on both servers)."
    if yesno "Paste an existing PSK?" "n"; then
        psk="$(ask "PSK" "")"
    else
        psk="$("$CORE" genpsk)"
        echo -e "  ${C_G}Generated PSK:${C_RESET} ${C_BOLD}${psk}${C_RESET}"
        echo -e "  ${C_Y}Copy this now — use the SAME key on the other server.${C_RESET}"
    fi
    [ -z "$psk" ] && { echo -e "  ${C_R}PSK required.${C_RESET}"; pause; return; }

    # Forwards apply to the forwarding engines (l4/mux) on the entry (Iran) side.
    # L3 routes all IP traffic and has no port list.
    local forwards_toml="[]" proxy="false"
    if [ "$engine" != "l3" ] && [ "$role" = "iran" ]; then
        echo; echo -e "  ${C_BOLD}VPN configuration / data port(s)${C_RESET}"
        echo -e "  ${C_C}This is your VPN configuration/data port. Users will connect through this port.${C_RESET}"
        echo -e "  ${C_C}Common choices are ports like 443.${C_RESET}"
        echo -e "  Formats: ${C_C}443${C_RESET}  ${C_C}443,8443${C_RESET}  ${C_C}200-300${C_RESET}  ${C_C}8000=9000${C_RESET}  (append ${C_C}@pp${C_RESET} for PROXY protocol)"
        echo -e "  ${C_Y}Note:${C_RESET} must differ from the tunnel port (${listen_port})."
        local flist; flist="$(ask "VPN data port(s)" "443")"
        forwards_toml="$(csv_to_toml_array "$flist")"
        yesno "Enable PROXY protocol v2 by default?" "n" && proxy="true"
    elif [ "$engine" = "l3" ]; then
        echo -e "  ${C_C}L3 engine: all IP traffic to ${tun_ip%/*} peer is tunnelled (no port list).${C_RESET}"
    fi

    write_config "$name" "$role" "$engine" "$transport" "$mode" "$peer" "$listen_port" \
        "$tun_ip" "$iface" "$mtu" "$workers" "$pool" "$cipher" "$psk" \
        "$health" "$profile" "$proxy" "$forwards_toml"

    echo; echo -e "  ${C_C}Validating configuration...${C_RESET}"
    if ! "$CORE" validate --config "${CONF_DIR}/${name}.toml"; then
        echo -e "  ${C_R}Validation failed. Config saved but not started.${C_RESET}"; pause; return
    fi

    systemctl enable --now "${SVC_PREFIX}${name}" >/dev/null 2>&1
    sleep 1
    if systemctl is-active --quiet "${SVC_PREFIX}${name}"; then
        echo -e "  ${C_G}✓ Tunnel '${name}' is active.${C_RESET}"
    else
        echo -e "  ${C_R}✗ Tunnel failed to start. Check logs (menu 6).${C_RESET}"
        systemctl --no-pager status "${SVC_PREFIX}${name}" | sed -n '1,6p'
    fi
    pause
}

csv_to_toml_array() { # "a,b,c" -> ["a", "b", "c"]
    local in="$1" out="" tok
    IFS=',' read -r -a parts <<< "$in"
    for tok in "${parts[@]}"; do
        tok="$(echo "$tok" | tr -d '[:space:]')"; [ -z "$tok" ] && continue
        out="${out:+$out, }\"${tok}\""
    done
    echo "[${out}]"
}

write_config() {
    local name="$1" role="$2" engine="$3" transport="$4" mode="$5" peer="$6" listen="$7" \
          tun_ip="$8" iface="$9" mtu="${10}" workers="${11}" pool="${12}" cipher="${13}" \
          psk="${14}" health="${15}" profile="${16}" proxy="${17}" forwards="${18}"
    install -d -m 0750 "$CONF_DIR"
    umask 077
    {
        echo "# Emergency Tunnel configuration"
        echo "name = \"$name\""
        echo "role = \"$role\""
        echo "engine = \"$engine\""
        echo "transport = \"$transport\""
        echo "mode = \"$mode\""
        [ -n "$peer" ] && echo "peer = \"$peer\""
        echo "listen_port = $listen"
        [ -n "$tun_ip" ] && echo "tun_ip = \"$tun_ip\""
        echo "tun_iface = \"$iface\""
        echo "mtu = $mtu"
        echo "workers = $workers"
        echo "pool = $pool"
        echo "cipher = \"$cipher\""
        echo "psk = \"$psk\""
        echo "health_port = $health"
        echo "profile = \"$profile\""
        echo "log_level = \"info\""
        if [ "$engine" = "l3" ]; then
            echo "heartbeat_interval = 10"
            echo "heartbeat_timeout = 25"
        else
            echo "proxy_protocol = $proxy"
            echo "forwards = $forwards"
            if [ "$engine" = "mux" ]; then
                # mux uses heartbeat for per-session keepalive / RTT.
                echo "heartbeat_interval = 10"
                echo "heartbeat_timeout = 25"
            fi
        fi
    } > "${CONF_DIR}/${name}.toml"
    chmod 0600 "${CONF_DIR}/${name}.toml"
}

# --- Manage single tunnel ----------------------------------------------------
pick_tunnel() {
    local ts=(); mapfile -t ts < <(list_tunnels)
    if [ "${#ts[@]}" -eq 0 ]; then echo -e "  ${C_Y}No tunnels configured.${C_RESET}" >&2; return 1; fi
    echo -e "  Select a tunnel:" >&2
    local i; for i in "${!ts[@]}"; do echo -e "    ${C_G}$((i+1)))${C_RESET} ${ts[$i]}" >&2; done
    local ch; read -r -p "$(echo -e "  Choice: ")" ch
    local idx=$((ch-1))
    [ "$idx" -ge 0 ] 2>/dev/null && [ -n "${ts[$idx]:-}" ] || { echo -e "  ${C_R}Invalid.${C_RESET}" >&2; return 1; }
    echo "${ts[$idx]}"
}

svc_action() { # verb
    local verb="$1" name; banner
    name="$(pick_tunnel)" || { pause; return; }
    systemctl "$verb" "${SVC_PREFIX}${name}"
    echo -e "  ${C_G}${verb} -> ${name}${C_RESET}"
    pause
}

show_status() {
    banner; local name; name="$(pick_tunnel)" || { pause; return; }
    systemctl --no-pager status "${SVC_PREFIX}${name}" | sed -n '1,12p'
    if have curl; then
        local hp; hp="$(grep -E '^health_port' "${CONF_DIR}/${name}.toml" | grep -o '[0-9]*')"
        [ -n "$hp" ] && echo -e "\n  ${C_BOLD}Live stats:${C_RESET}" && curl -fsS --max-time 2 "http://127.0.0.1:${hp}/stats" 2>/dev/null | sed 's/^/    /'
    fi
    pause
}

view_logs() {
    banner; local name; name="$(pick_tunnel)" || { pause; return; }
    echo -e "  ${C_C}Live logs for ${name} (Ctrl-C to return)${C_RESET}\n"
    ( trap 'exit 0' INT
      journalctl -u "${SVC_PREFIX}${name}" -n 100 -f 2>/dev/null \
        || tail -n 100 -f "${LOG_DIR}/${name}.log" )
    pause
}

edit_config() {
    banner; local name; name="$(pick_tunnel)" || { pause; return; }
    "${EDITOR:-nano}" "${CONF_DIR}/${name}.toml"
    if "$CORE" validate --config "${CONF_DIR}/${name}.toml"; then
        yesno "Restart tunnel to apply changes?" "y" && systemctl restart "${SVC_PREFIX}${name}"
    else
        echo -e "  ${C_R}Config invalid — not restarted.${C_RESET}"
    fi
    pause
}

delete_tunnel() {
    banner; local name; name="$(pick_tunnel)" || { pause; return; }
    yesno "Really delete '${name}'?" "n" || { pause; return; }
    systemctl disable --now "${SVC_PREFIX}${name}" >/dev/null 2>&1
    rm -f "${CONF_DIR}/${name}.toml" "${LOG_DIR}/${name}.log" "${LOG_DIR}/${name}.log.1"
    systemctl reset-failed "${SVC_PREFIX}${name}" 2>/dev/null || true
    echo -e "  ${C_R}Deleted ${name}.${C_RESET}"
    pause
}

update_core() {
    banner
    echo -e "  ${C_BOLD}Update Core${C_RESET}\n"
    local url="https://raw.githubusercontent.com/AMirHossein-donyavii/tunnel/main/scripts/install.sh"
    [ -f /usr/local/lib/emergency-tunnel/UPDATE_URL ] && url="$(cat /usr/local/lib/emergency-tunnel/UPDATE_URL)"
    local cur; cur="$(core_version)"
    echo -e "  Installed core: ${C_G}v${cur}${C_RESET}"
    echo -e "  Update source:  ${C_C}${url}${C_RESET}"
    echo -e "  (the installer verifies checksums and restarts active tunnels)"
    yesno "Proceed with update?" "n" || { pause; return; }
    if have curl; then
        curl -fsSL "${url}" | bash || echo -e "  ${C_R}Update failed.${C_RESET}"
    else
        echo -e "  ${C_R}curl not available.${C_RESET}"
    fi
    pause
}

system_info() {
    banner
    echo -e "  ${C_BOLD}System Information${C_RESET}\n"
    "$CORE" sysinfo 2>/dev/null | sed 's/^/  /'
    echo
    echo -e "  ${C_BOLD}Kernel:${C_RESET}  $(uname -sr)"
    echo -e "  ${C_BOLD}Uptime:${C_RESET}  $(uptime -p 2>/dev/null || uptime)"
    echo -e "  ${C_BOLD}Memory:${C_RESET}  $(free -h 2>/dev/null | awk '/Mem:/{print $3" / "$2}')"
    echo -e "  ${C_BOLD}Load:${C_RESET}    $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"
    echo
    echo -e "  ${C_BOLD}Transports:${C_RESET}"
    "$CORE" transports | sed 's/^/    /'
    pause
}

run_uninstall() {
    banner
    echo -e "  ${C_R}${C_BOLD}Uninstall Emergency Tunnel${C_RESET}\n"
    yesno "This removes the core and all tunnels. Continue?" "n" || { pause; return; }
    for cand in "/usr/local/lib/emergency-tunnel/uninstall.sh" "./uninstall.sh" "./scripts/uninstall.sh"; do
        [ -f "$cand" ] && { bash "$cand"; exit 0; }
    done
    # Inline fallback.
    local t; while IFS= read -r t; do systemctl disable --now "${SVC_PREFIX}${t}" 2>/dev/null; done < <(list_tunnels)
    rm -f /etc/systemd/system/emergency-tunnel@.service /usr/local/bin/et-core /usr/local/bin/et
    systemctl daemon-reload
    yesno "Delete configs and logs too?" "n" && rm -rf "$CONF_DIR" "$LOG_DIR"
    echo -e "  ${C_G}Uninstalled.${C_RESET}"; exit 0
}

main_menu() {
    while true; do
        banner
        echo -e "  ${C_G} 1)${C_RESET} Create tunnel        ${C_G} 6)${C_RESET} View logs"
        echo -e "  ${C_G} 2)${C_RESET} Delete tunnel        ${C_G} 7)${C_RESET} Edit configuration"
        echo -e "  ${C_G} 3)${C_RESET} Restart tunnel       ${C_G} 8)${C_RESET} Update core"
        echo -e "  ${C_G} 4)${C_RESET} Stop tunnel          ${C_G} 9)${C_RESET} System information"
        echo -e "  ${C_G} 5)${C_RESET} Show tunnel status   ${C_G}10)${C_RESET} Uninstall"
        echo -e "  ${C_R} 0)${C_RESET} Exit"
        echo -e "${C_B}${LINE}${C_RESET}"
        local ch; read -r -p "  Select an option: " ch
        case "$ch" in
            1) create_tunnel ;;
            2) delete_tunnel ;;
            3) svc_action restart ;;
            4) svc_action stop ;;
            5) show_status ;;
            6) view_logs ;;
            7) edit_config ;;
            8) update_core ;;
            9) system_info ;;
            10) run_uninstall ;;
            0) clear; exit 0 ;;
            *) echo -e "  ${C_R}Invalid option.${C_RESET}"; sleep 1 ;;
        esac
    done
}

need_root
[ -x "$CORE" ] || echo -e "${C_Y}Warning: core not found at ${CORE}. Some actions will fail.${C_RESET}"
main_menu
